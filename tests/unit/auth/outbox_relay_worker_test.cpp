#include "auth/domain/auth_outbox_entity.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/auth_outbox_repository.hpp"
#include "auth/service/outbox_relay_worker.hpp"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;

using domain::AuthOutboxEntity;
using domain::OutboxSeverity;
using domain::OutboxStatus;
using domain::Uuid;

// ============================================================================
// Mocks
// ============================================================================

class MockAuthOutboxRepository : public repository::IAuthOutboxRepository {
  public:
    MOCK_METHOD(void, stage_event, (const AuthOutboxEntity& event, pqxx::transaction_base& tx), (override));
    MOCK_METHOD(void, stage_event, (const AuthOutboxEntity& event), (override));
    MOCK_METHOD(std::vector<AuthOutboxEntity>, fetch_and_lease_pending_batch,
                (std::size_t limit, std::chrono::seconds lease_duration), (override));
    MOCK_METHOD(bool, mark_published, (const Uuid& event_id), (override));

    bool mark_failed(const Uuid& event_id, std::string_view error) override {
        return mark_failed_str(event_id, std::string(error));
    }
    MOCK_METHOD(bool, mark_failed_str, (const Uuid& event_id, const std::string& error));

    bool mark_quarantined(const Uuid& event_id, std::string_view reason) override {
        return mark_quarantined_str(event_id, std::string(reason));
    }
    MOCK_METHOD(bool, mark_quarantined_str, (const Uuid& event_id, const std::string& reason));

    MOCK_METHOD(std::size_t, purge_published_older_than,
                (std::chrono::system_clock::time_point cutoff, std::size_t batch_size), (override));
    MOCK_METHOD(std::size_t, count_pending, (), (override));
};

class MockAuditIngestionStub : public securecloud::audit::v1::AuditIngestionService::StubInterface {
  public:
    MOCK_METHOD(grpc::Status, SubmitAuditEvent,
                (grpc::ClientContext * context, const securecloud::audit::v1::SubmitAuditEventRequest& request,
                 securecloud::audit::v1::SubmitAuditEventResponse* response),
                (override));

    MOCK_METHOD(grpc::Status, BatchSubmitAuditEvents,
                (grpc::ClientContext * context, const securecloud::audit::v1::BatchSubmitAuditEventsRequest& request,
                 securecloud::audit::v1::BatchSubmitAuditEventsResponse* response),
                (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<securecloud::audit::v1::SubmitAuditEventResponse>*,
                AsyncSubmitAuditEventRaw,
                (grpc::ClientContext * context, const securecloud::audit::v1::SubmitAuditEventRequest& request,
                 grpc::CompletionQueue* cq),
                (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<securecloud::audit::v1::SubmitAuditEventResponse>*,
                PrepareAsyncSubmitAuditEventRaw,
                (grpc::ClientContext * context, const securecloud::audit::v1::SubmitAuditEventRequest& request,
                 grpc::CompletionQueue* cq),
                (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<securecloud::audit::v1::BatchSubmitAuditEventsResponse>*,
                AsyncBatchSubmitAuditEventsRaw,
                (grpc::ClientContext * context, const securecloud::audit::v1::BatchSubmitAuditEventsRequest& request,
                 grpc::CompletionQueue* cq),
                (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<securecloud::audit::v1::BatchSubmitAuditEventsResponse>*,
                PrepareAsyncBatchSubmitAuditEventsRaw,
                (grpc::ClientContext * context, const securecloud::audit::v1::BatchSubmitAuditEventsRequest& request,
                 grpc::CompletionQueue* cq),
                (override));
};

AuthOutboxEntity make_valid_outbox_entity(std::string_view event_type = "auth.login.succeeded",
                                          int32_t retry_count = 1) {
    const Uuid eid = Uuid::generate_v7();
    const Uuid uid = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    nlohmann::json payload = {
        {"event_id", eid.to_string()},  {"occurred_at_ms", now_ms},     {"event_type", std::string(event_type)},
        {"severity", "INFO"},           {"producer_service", "AUTH"},   {"producer_instance", "auth-test-1"},
        {"actor_type", "USER"},         {"actor_id", uid.to_string()},  {"target_type", "USER"},
        {"target_id", uid.to_string()}, {"correlation_id", "corr-123"}, {"metadata", {{"client_ip", "127.0.0.1"}}},
    };

    AuthOutboxEntity entity;
    entity.event_id = eid;
    entity.aggregate_type = "USER";
    entity.aggregate_id = uid;
    entity.event_type = std::string(event_type);
    entity.severity = OutboxSeverity::Info;
    entity.payload_json = payload.dump();
    entity.status = OutboxStatus::Pending;
    entity.retry_count = retry_count;
    entity.created_at = now;
    return entity;
}

// ============================================================================
// Fixture
// ============================================================================

class OutboxRelayWorkerTest : public ::testing::Test {
  protected:
    std::shared_ptr<NiceMock<MockAuthOutboxRepository>> repo_{std::make_shared<NiceMock<MockAuthOutboxRepository>>()};
    std::shared_ptr<NiceMock<MockAuditIngestionStub>> stub_{std::make_shared<NiceMock<MockAuditIngestionStub>>()};
};

// ============================================================================
// Constructor & Empty Batch Tests
// ============================================================================

TEST_F(OutboxRelayWorkerTest, Constructor_RejectsNullDependencies) {
    EXPECT_THROW(OutboxRelayWorker(nullptr, stub_), std::invalid_argument);
    EXPECT_THROW(OutboxRelayWorker(repo_, nullptr), std::invalid_argument);
}

TEST_F(OutboxRelayWorkerTest, DrainOnce_EmptyBatch_ReturnsZeroWithoutRpcCall) {
    OutboxRelayWorker worker(repo_, stub_);

    EXPECT_CALL(*repo_, fetch_and_lease_pending_batch(_, _)).WillOnce(Return(std::vector<AuthOutboxEntity>{}));
    EXPECT_CALL(*stub_, BatchSubmitAuditEvents(_, _, _)).Times(0);

    EXPECT_EQ(worker.drain_once(), 0u);
    EXPECT_EQ(worker.metrics().batches_processed.load(), 0u);
}

// ============================================================================
// Nominal Delivery & Partial Rejection Tests
// ============================================================================

TEST_F(OutboxRelayWorkerTest, DrainOnce_ValidBatch_ShipsViaGrpcAndMarksPublished) {
    OutboxRelayWorker worker(repo_, stub_);

    auto ev1 = make_valid_outbox_entity("auth.login.succeeded");
    auto ev2 = make_valid_outbox_entity("auth.token.refreshed");

    EXPECT_CALL(*repo_, fetch_and_lease_pending_batch(_, _)).WillOnce(Return(std::vector<AuthOutboxEntity>{ev1, ev2}));

    securecloud::audit::v1::BatchSubmitAuditEventsRequest captured_req;
    securecloud::audit::v1::BatchSubmitAuditEventsResponse ok_resp;

    EXPECT_CALL(*stub_, BatchSubmitAuditEvents(_, _, _))
        .WillOnce(DoAll(SaveArg<1>(&captured_req), SetArgPointee<2>(ok_resp), Return(grpc::Status::OK)));

    EXPECT_CALL(*repo_, mark_published(ev1.event_id)).WillOnce(Return(true));
    EXPECT_CALL(*repo_, mark_published(ev2.event_id)).WillOnce(Return(true));
    EXPECT_CALL(*repo_, mark_quarantined_str(_, _)).Times(0);
    EXPECT_CALL(*repo_, mark_failed_str(_, _)).Times(0);

    const std::size_t drained = worker.drain_once();
    EXPECT_EQ(drained, 2u);
    ASSERT_EQ(captured_req.events_size(), 2);
    EXPECT_EQ(captured_req.events(0).event_id(), ev1.event_id.to_string());
    EXPECT_EQ(captured_req.events(1).event_id(), ev2.event_id.to_string());

    EXPECT_EQ(worker.metrics().batches_processed.load(), 1u);
    EXPECT_EQ(worker.metrics().events_published.load(), 2u);
    EXPECT_EQ(worker.metrics().events_quarantined.load(), 0u);
}

TEST_F(OutboxRelayWorkerTest, DrainOnce_PartialRejection_QuarantinesRejectedAndPublishesAccepted) {
    OutboxRelayWorker worker(repo_, stub_);

    auto valid_ev = make_valid_outbox_entity("auth.login.succeeded");
    auto rejected_ev = make_valid_outbox_entity("auth.invalid.schema");

    EXPECT_CALL(*repo_, fetch_and_lease_pending_batch(_, _))
        .WillOnce(Return(std::vector<AuthOutboxEntity>{valid_ev, rejected_ev}));

    securecloud::audit::v1::BatchSubmitAuditEventsResponse partial_resp;
    partial_resp.add_rejected_event_ids(rejected_ev.event_id.to_string());

    EXPECT_CALL(*stub_, BatchSubmitAuditEvents(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(partial_resp), Return(grpc::Status::OK)));

    EXPECT_CALL(*repo_, mark_published(valid_ev.event_id)).WillOnce(Return(true));
    EXPECT_CALL(*repo_, mark_quarantined_str(rejected_ev.event_id, HasSubstr("Rejected by AuditIngestionService")))
        .WillOnce(Return(true));

    EXPECT_EQ(worker.drain_once(), 2u);
    EXPECT_EQ(worker.metrics().events_published.load(), 1u);
    EXPECT_EQ(worker.metrics().events_quarantined.load(), 1u);
}

// ============================================================================
// Poison Pill & Retry Exhaustion Tests
// ============================================================================

TEST_F(OutboxRelayWorkerTest, DrainOnce_CorruptedJsonPayload_QuarantinesPoisonPillWithoutBlockingBatch) {
    OutboxRelayWorker worker(repo_, stub_);

    auto poison_ev = make_valid_outbox_entity("auth.login.failed");
    poison_ev.payload_json = "{not-valid-json";

    auto good_ev = make_valid_outbox_entity("auth.login.succeeded");

    EXPECT_CALL(*repo_, fetch_and_lease_pending_batch(_, _))
        .WillOnce(Return(std::vector<AuthOutboxEntity>{poison_ev, good_ev}));

    EXPECT_CALL(*repo_, mark_quarantined_str(poison_ev.event_id, HasSubstr("Corrupted outbox payload_json")))
        .WillOnce(Return(true));

    securecloud::audit::v1::BatchSubmitAuditEventsRequest captured_req;
    EXPECT_CALL(*stub_, BatchSubmitAuditEvents(_, _, _))
        .WillOnce(DoAll(SaveArg<1>(&captured_req), Return(grpc::Status::OK)));

    EXPECT_CALL(*repo_, mark_published(good_ev.event_id)).WillOnce(Return(true));

    EXPECT_EQ(worker.drain_once(), 2u);
    ASSERT_EQ(captured_req.events_size(), 1);
    EXPECT_EQ(captured_req.events(0).event_id(), good_ev.event_id.to_string());
    EXPECT_EQ(worker.metrics().events_quarantined.load(), 1u);
    EXPECT_EQ(worker.metrics().events_published.load(), 1u);
}

TEST_F(OutboxRelayWorkerTest, DrainOnce_ExceededMaxRetriesBeforeRpc_QuarantinesImmediately) {
    OutboxRelayConfig cfg;
    cfg.max_retries = 3;
    OutboxRelayWorker worker(repo_, stub_, cfg);

    auto exhausted_ev = make_valid_outbox_entity("auth.login.succeeded", /*retry_count=*/4);

    EXPECT_CALL(*repo_, fetch_and_lease_pending_batch(_, _))
        .WillOnce(Return(std::vector<AuthOutboxEntity>{exhausted_ev}));

    EXPECT_CALL(*repo_, mark_quarantined_str(exhausted_ev.event_id, HasSubstr("Exceeded maximum")))
        .WillOnce(Return(true));
    EXPECT_CALL(*stub_, BatchSubmitAuditEvents(_, _, _)).Times(0);

    EXPECT_EQ(worker.drain_once(), 1u);
    EXPECT_EQ(worker.metrics().events_quarantined.load(), 1u);
    EXPECT_EQ(worker.metrics().batches_processed.load(), 1u);
}

// ============================================================================
// gRPC Error Handling (Transient vs Non-Retryable)
// ============================================================================

TEST_F(OutboxRelayWorkerTest, DrainOnce_TransientGrpcError_MarksFailedBelowMaxRetriesAndQuarantinesAtLimit) {
    OutboxRelayConfig cfg;
    cfg.max_retries = 3;
    OutboxRelayWorker worker(repo_, stub_, cfg);

    auto retryable_ev = make_valid_outbox_entity("auth.login.succeeded", /*retry_count=*/1);
    auto at_limit_ev = make_valid_outbox_entity("auth.session.revoked", /*retry_count=*/3);

    EXPECT_CALL(*repo_, fetch_and_lease_pending_batch(_, _))
        .WillOnce(Return(std::vector<AuthOutboxEntity>{retryable_ev, at_limit_ev}));

    EXPECT_CALL(*stub_, BatchSubmitAuditEvents(_, _, _))
        .WillOnce(Return(grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit service unavailable")));

    EXPECT_CALL(*repo_, mark_failed_str(retryable_ev.event_id, HasSubstr("Audit service unavailable")))
        .WillOnce(Return(true));
    EXPECT_CALL(*repo_, mark_quarantined_str(at_limit_ev.event_id, HasSubstr("Audit service unavailable")))
        .WillOnce(Return(true));

    EXPECT_EQ(worker.drain_once(), 2u);
    EXPECT_EQ(worker.metrics().events_failed.load(), 1u);
    EXPECT_EQ(worker.metrics().events_quarantined.load(), 1u);
}

TEST_F(OutboxRelayWorkerTest, DrainOnce_NonRetryableGrpcError_QuarantinesImmediatelyOnFirstAttempt) {
    OutboxRelayConfig cfg;
    cfg.max_retries = 15;
    OutboxRelayWorker worker(repo_, stub_, cfg);

    auto ev = make_valid_outbox_entity("auth.login.succeeded", /*retry_count=*/1);

    EXPECT_CALL(*repo_, fetch_and_lease_pending_batch(_, _)).WillOnce(Return(std::vector<AuthOutboxEntity>{ev}));

    EXPECT_CALL(*stub_, BatchSubmitAuditEvents(_, _, _))
        .WillOnce(Return(grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid proto field")));

    EXPECT_CALL(*repo_, mark_quarantined_str(ev.event_id, HasSubstr("Invalid proto field"))).WillOnce(Return(true));
    EXPECT_CALL(*repo_, mark_failed_str(_, _)).Times(0);

    EXPECT_EQ(worker.drain_once(), 1u);
    EXPECT_EQ(worker.metrics().events_quarantined.load(), 1u);
    EXPECT_EQ(worker.metrics().events_failed.load(), 0u);
}

// ============================================================================
// Background Thread Lifecycle Tests
// ============================================================================

TEST_F(OutboxRelayWorkerTest, StartStopAndNotify_LifecycleIsIdempotentAndThreadSafe) {
    OutboxRelayConfig cfg;
    cfg.poll_interval = std::chrono::milliseconds(500);
    OutboxRelayWorker worker(repo_, stub_, cfg);

    EXPECT_CALL(*repo_, fetch_and_lease_pending_batch(_, _)).WillRepeatedly(Return(std::vector<AuthOutboxEntity>{}));

    worker.start();
    worker.start(); // Idempotent second start
    worker.notify_new_events();
    worker.stop();
    worker.stop(); // Idempotent second stop
}

} // namespace
} // namespace securecloud::auth::service::test
