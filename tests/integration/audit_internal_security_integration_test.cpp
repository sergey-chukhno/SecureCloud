#include "repository/audit_event_repository_interface.hpp"
#include "security/internal_security_event_recorder.hpp"
#include "service/audit_service_impl.hpp"

#include <atomic>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace securecloud::audit::testing {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

class InMemoryTestRepository : public repository::IAuditEventRepository {
  public:
    bool insert_batch(const std::vector<domain::AuditEvent>& events) override {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.insert(events_.end(), events.begin(), events.end());
        return true;
    }

    repository::RepositoryBatchWriteResult
    insert_batch_classified(const std::vector<domain::AuditEvent>& events) override {
        insert_batch(events);
        return repository::RepositoryBatchWriteResult{
            .status = repository::RepositoryWriteStatus::Committed, .error_code = "", .sanitized_reason = ""};
    }

    std::vector<domain::AuditEvent> query_by_time_range(std::chrono::system_clock::time_point,
                                                        std::chrono::system_clock::time_point, uint32_t) override {
        std::lock_guard<std::mutex> lock(mutex_);
        return events_;
    }

    std::vector<domain::AuditEvent> query_by_producer(const std::string& producer_service,
                                                      std::chrono::system_clock::time_point,
                                                      std::chrono::system_clock::time_point, uint32_t) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<domain::AuditEvent> result;
        for (const auto& e : events_) {
            if (to_string(e.producer_service) == producer_service) {
                result.push_back(e);
            }
        }
        return result;
    }

    std::vector<domain::AuditEvent> query_by_correlation_id(const std::string&, uint32_t) override { return {}; }

    std::optional<domain::AuditEvent> find_by_event_id(const domain::EventId&) override { return std::nullopt; }

    size_t stored_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return events_.size();
    }

    std::vector<domain::AuditEvent> get_all_events() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return events_;
    }

  private:
    mutable std::mutex mutex_;
    std::vector<domain::AuditEvent> events_;
};

class AuditInternalSecurityIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        security::GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(true);
        repo_ = std::make_shared<InMemoryTestRepository>();
        ingestion_service_ = std::make_shared<service::AuditIngestionService>(repo_);
        recorder_ =
            std::make_shared<security::InternalSecurityEventRecorder>(ingestion_service_, "audit-integration-node");
        service_ = std::make_unique<service::AuditServiceImpl>(ingestion_service_, recorder_);
    }

    void TearDown() override {
        security::GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(false);
    }

    v1::AuditEventProto create_proto_event() {
        v1::AuditEventProto event;
        event.set_event_id("018f6e4a-7b3c-7000-8000-000000000001");
        event.set_occurred_at_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        event.set_event_type("user.authentication.success");
        event.set_severity(v1::SEVERITY_INFO);
        event.set_producer_service(v1::PRODUCER_SERVICE_AUTH);
        event.set_producer_instance("auth-node-01");
        event.set_actor_type(v1::ACTOR_TYPE_USER);
        event.set_actor_id("usr_123456");
        event.set_target_type(v1::TARGET_TYPE_SERVICE);
        event.set_target_id("srv_auth");
        return event;
    }

    std::shared_ptr<InMemoryTestRepository> repo_;
    std::shared_ptr<service::AuditIngestionService> ingestion_service_;
    std::shared_ptr<security::InternalSecurityEventRecorder> recorder_;
    std::unique_ptr<service::AuditServiceImpl> service_;
};

// Test 6: End-to-End mTLS Identity Mismatch Recording
TEST_F(AuditInternalSecurityIntegrationTest, EndToEndMtlsIdentityMismatchRecording) {
    security::GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(false);

    grpc::ServerContext context;
    v1::SubmitAuditEventRequest request;
    *request.mutable_event() = create_proto_event();
    v1::SubmitAuditEventResponse response;

    auto status = service_->SubmitAuditEvent(&context, &request, &response);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);

    EXPECT_EQ(recorder_->events_recorded_count(), 1u);
    EXPECT_EQ(repo_->stored_count(), 1u);

    auto stored = repo_->get_all_events();
    EXPECT_EQ(stored.front().event_type, "audit.security.auth.unauthenticated_connection");
}

// Test 7: End-to-End Sensitive Data Ingestion Rejection Recording
TEST_F(AuditInternalSecurityIntegrationTest, EndToEndSensitiveDataIngestionRejectionRecording) {
    grpc::ServerContext context;
    v1::SubmitAuditEventRequest request;
    auto sensitive_evt = create_proto_event();
    (*sensitive_evt.mutable_metadata())["user_password"] = "PlaintextPassword123!";
    *request.mutable_event() = sensitive_evt;
    v1::SubmitAuditEventResponse response;

    auto status = service_->SubmitAuditEvent(&context, &request, &response);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);

    EXPECT_EQ(recorder_->events_recorded_count(), 1u);
    EXPECT_EQ(repo_->stored_count(), 1u);

    auto stored = repo_->get_all_events();
    EXPECT_EQ(stored.front().event_type, "audit.security.payload.sensitive_data_detected");
}

// Test 8: Concurrent Multi-Threaded Internal Event Emission (8 threads, zero data races)
TEST_F(AuditInternalSecurityIntegrationTest, ConcurrentMultiThreadedInternalEventEmission) {
    constexpr int kNumThreads = 8;
    constexpr int kEventsPerThread = 250;

    std::vector<std::thread> workers;
    workers.reserve(kNumThreads);

    for (int t = 0; t < kNumThreads; ++t) {
        workers.emplace_back([this, t]() {
            security::SecurityEventContext ctx;
            ctx.rpc_method = "ConcurrentWorkerThread";
            ctx.peer_socket_address = "127.0.0.1:" + std::to_string(50000 + t);

            for (int i = 0; i < kEventsPerThread; ++i) {
                recorder_->record_event(security::InternalSecurityEventType::IngestionQueueSaturated, ctx);
            }
        });
    }

    for (auto& worker : workers) {
        worker.join();
    }

    uint64_t total_processed = recorder_->events_recorded_count() + recorder_->events_dropped_count();
    EXPECT_EQ(total_processed, static_cast<uint64_t>(kNumThreads * kEventsPerThread));
    EXPECT_EQ(repo_->stored_count(), static_cast<size_t>(recorder_->events_recorded_count()));
}

} // namespace securecloud::audit::testing
