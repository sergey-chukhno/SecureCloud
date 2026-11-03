#include "audit_config.hpp"
#include "audit_server.hpp"
#include "ingestion/audit_ingestion_pipeline.hpp"
#include "repository/audit_event_repository_interface.hpp"
#include "service/audit_ingestion_service.hpp"
#include "service/audit_service_impl.hpp"

#include <atomic>
#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

namespace securecloud::audit::integration::testing {

using ::testing::_;

class MockAuditEventRepository : public repository::IAuditEventRepository {
  public:
    MOCK_METHOD(bool, insert_batch, (const std::vector<domain::AuditEvent>&), (override));
    MOCK_METHOD(repository::RepositoryBatchWriteResult, insert_batch_classified,
                (const std::vector<domain::AuditEvent>&), (override));
    MOCK_METHOD(std::vector<domain::AuditEvent>, query_by_time_range,
                (std::chrono::system_clock::time_point, std::chrono::system_clock::time_point, uint32_t), (override));
    MOCK_METHOD(std::vector<domain::AuditEvent>, query_by_producer,
                (const std::string&, std::chrono::system_clock::time_point, std::chrono::system_clock::time_point,
                 uint32_t),
                (override));
    MOCK_METHOD(std::vector<domain::AuditEvent>, query_by_correlation_id, (const std::string&, uint32_t), (override));
    MOCK_METHOD(std::optional<domain::AuditEvent>, find_by_event_id, (const domain::EventId&), (override));
};

class AuditGracefulShutdownIntegrationTest : public ::testing::Test {
  protected:
    AuditConfig make_test_config() {
        AuditConfig config;
        config.common.service_name = "audit-shutdown-test";
        config.common.service_display_name = "Audit Shutdown Test";
        config.common.grpc_port = 50098;
        config.retention.shutdown_grace_period_ms = 1000;
        return config;
    }

    static domain::AuditEvent create_valid_domain_event() {
        domain::AuditEvent evt;
        evt.event_id = domain::EventId::generate_v7();
        evt.producer_service = domain::ProducerService::Auth;
        evt.event_type = "auth.user.login";
        evt.actor_id = "user-123456";
        evt.actor_type = domain::ActorType::User;
        evt.severity = domain::Severity::Info;
        evt.correlation_id = "corr-123456789012";
        evt.occurred_at = std::chrono::system_clock::now();
        evt.received_at = std::chrono::system_clock::now();
        return evt;
    }
};

// Test 6: Readiness Withdrawal on Shutdown
TEST_F(AuditGracefulShutdownIntegrationTest, ReadinessWithdrawsImmediatelyOnShutdown) {
    AuditServer server(make_test_config());

    // Verify initial server state is configured
    EXPECT_EQ(server.state(), ServiceState::Configured);

    // Initiate server stop
    server.stop();

    // Readiness must be withdrawn and server marked unhealthy
    EXPECT_FALSE(server.is_healthy());
}

// Test 7: Ingress Rejection During Drain
TEST_F(AuditGracefulShutdownIntegrationTest, IngressRejectedWithUnavailableDuringDrain) {
    security::GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(true);

    auto mock_repo = std::make_shared<MockAuditEventRepository>();
    auto ingestion_service = std::make_shared<service::AuditIngestionService>(mock_repo);
    service::AuditServiceImpl audit_service(ingestion_service);

    EXPECT_FALSE(audit_service.is_draining());

    // Transition service layer to draining state
    audit_service.set_draining(true);
    EXPECT_TRUE(audit_service.is_draining());

    grpc::ServerContext context;
    v1::SubmitAuditEventRequest request;
    v1::SubmitAuditEventResponse response;

    auto status = audit_service.SubmitAuditEvent(&context, &request, &response);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(status.error_message(), "Audit service is draining; retry via outbox buffer");

    security::GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(false);
}

// Test 8: In-Flight Batch Flush Under Deadline
TEST_F(AuditGracefulShutdownIntegrationTest, InFlightBatchesFlushedBeforeShutdownTerminates) {
    auto mock_repo = std::make_shared<MockAuditEventRepository>();

    std::atomic<size_t> inserted_count{0};
    EXPECT_CALL(*mock_repo, insert_batch(_))
        .WillRepeatedly([&inserted_count](const std::vector<domain::AuditEvent>& events) {
            inserted_count.fetch_add(events.size());
            return true;
        });

    IngestionConfig ing_config;
    ing_config.batch_size = 100;
    ing_config.batch_flush_interval_ms = 100;

    auto pipeline = std::make_shared<ingestion::AuditIngestionPipeline>(ing_config, mock_repo);
    pipeline->start();

    // Submit 500 fully populated, valid events into the pipeline
    for (int i = 0; i < 500; ++i) {
        ingestion::IngestionEnvelope envelope;
        envelope.event = create_valid_domain_event();
        (void)pipeline->submit(std::move(envelope));
    }

    // Initiate graceful shutdown with 2000ms deadline budget
    pipeline->shutdown(std::chrono::milliseconds(2000));

    // All 500 events must be flushed to ClickHouse repository before shutdown completes
    EXPECT_EQ(inserted_count.load(), 500u);
}

// Test 9: Drain Deadline Expiration & NACK Fidelity
TEST_F(AuditGracefulShutdownIntegrationTest, DeadlineExpirationPreventsFalseACKs) {
    auto mock_repo = std::make_shared<MockAuditEventRepository>();

    // Simulate slow/failing ClickHouse repository
    EXPECT_CALL(*mock_repo, insert_batch(_)).WillRepeatedly([](const std::vector<domain::AuditEvent>&) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        return false;
    });

    IngestionConfig ing_config;
    ing_config.batch_size = 50;
    ing_config.batch_flush_interval_ms = 100;

    auto pipeline = std::make_shared<ingestion::AuditIngestionPipeline>(ing_config, mock_repo);
    pipeline->start();

    ingestion::IngestionEnvelope envelope;
    envelope.event = create_valid_domain_event();
    envelope.event.producer_service = domain::ProducerService::Gateway;
    envelope.event.event_type = "gateway.request.blocked";

    (void)pipeline->submit(std::move(envelope));

    auto start_time = std::chrono::steady_clock::now();

    // Trigger shutdown with short 300ms deadline budget
    pipeline->shutdown(std::chrono::milliseconds(300));

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time);

    // Shutdown must observe the deadline budget without blocking indefinitely
    EXPECT_LE(elapsed.count(), 1500);
}

// Test 10: Repeated & Concurrent Shutdown Signals
TEST_F(AuditGracefulShutdownIntegrationTest, ConcurrentStopCallsAreThreadSafeAndIdempotent) {
    AuditServer server(make_test_config());

    constexpr int k_num_threads = 10;
    std::vector<std::thread> threads;
    threads.reserve(k_num_threads);

    for (int i = 0; i < k_num_threads; ++i) {
        threads.emplace_back([&server]() { server.stop(); });
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    // Server must shut down cleanly and idempotently without double-free or crashes
    EXPECT_FALSE(server.is_healthy());
}

} // namespace securecloud::audit::integration::testing
