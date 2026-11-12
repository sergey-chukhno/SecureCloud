#include "auth/audit/auth_outbox_relay.hpp"
#include "auth/auth_config.hpp"
#include "auth/domain/audit_event.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/outbox_event_mapper.hpp"
#include "securecloud/configuration/configuration_source.hpp"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::auth::audit::test {
namespace {

using ::testing::_;
using ::testing::AllOf;
using ::testing::Ge;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::Le;
using ::testing::NiceMock;
using ::testing::Return;

class MockAuthOutboxRepository : public repository::IAuthOutboxRepository {
  public:
    MOCK_METHOD(void, stage_event, (const domain::AuthOutboxEntity& event, pqxx::transaction_base& tx), (override));
    MOCK_METHOD(void, stage_event, (const domain::AuthOutboxEntity& event), (override));
    MOCK_METHOD(std::vector<domain::AuthOutboxEntity>, fetch_and_lease_pending_batch,
                (std::size_t limit, std::chrono::seconds lease_duration), (override));
    MOCK_METHOD(bool, mark_published, (const domain::Uuid& event_id), (override));
    MOCK_METHOD(bool, mark_failed, (const domain::Uuid& event_id, std::string_view error), (override));
    MOCK_METHOD(bool, mark_quarantined, (const domain::Uuid& event_id, std::string_view reason), (override));
    MOCK_METHOD(std::size_t, purge_published_older_than,
                (std::chrono::system_clock::time_point cutoff, std::size_t batch_size), (override));
    MOCK_METHOD(std::size_t, count_pending, (), (override));
};

class MockAuthAuditClient : public IAuthAuditClient {
  public:
    MOCK_METHOD(AuditBatchSubmitResult, submit_batch,
                (const std::vector<::securecloud::audit::v1::AuditEventProto>& events), (override));
};

class MapConfigSource : public common::configuration::ConfigurationSource {
  public:
    explicit MapConfigSource(std::map<std::string, std::string> values) : values_(std::move(values)) {}

    std::optional<std::string> get(std::string_view key) const override {
        const auto it = values_.find(std::string(key));
        if (it == values_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

  private:
    std::map<std::string, std::string> values_;
};

domain::AuthOutboxEntity make_valid_outbox_entity() {
    const auto uid = domain::Uuid::generate_v7();
    const auto did = domain::Uuid::generate_v7();
    const auto sid = domain::Uuid::generate_v7();
    const auto ev = domain::AuditEvent::login_succeeded(uid, "alice@securecloud.io", did, sid, "198.51.100.12");
    return service::OutboxEventMapper::to_outbox_entity(ev);
}

TEST(AuthOutboxRelayTest, Constructor_RejectsNullDependenciesAndClampsBatchSize) {
    auto repo = std::make_shared<NiceMock<MockAuthOutboxRepository>>();
    auto client = std::make_shared<NiceMock<MockAuthAuditClient>>();

    EXPECT_THROW((AuthOutboxRelay{nullptr, client}), std::invalid_argument);
    EXPECT_THROW((AuthOutboxRelay{repo, nullptr}), std::invalid_argument);

    AuthOutboxRelayConfig oversized_cfg;
    oversized_cfg.batch_size = 250; // Exceeds AUDIT-004 max 100

    EXPECT_CALL(*repo, fetch_and_lease_pending_batch(100u, oversized_cfg.lease_duration))
        .WillOnce(Return(std::vector<domain::AuthOutboxEntity>{}));

    AuthOutboxRelay relay(repo, client, oversized_cfg);
    EXPECT_EQ(relay.poll_and_dispatch(), 0u);
}

TEST(AuthOutboxRelayTest, PollAndDispatch_ValidBatch_MapsSanitizesAndMarksPublished) {
    auto repo = std::make_shared<NiceMock<MockAuthOutboxRepository>>();
    auto client = std::make_shared<NiceMock<MockAuthAuditClient>>();

    const auto e1 = make_valid_outbox_entity();
    const auto e2 = make_valid_outbox_entity();

    EXPECT_CALL(*repo, fetch_and_lease_pending_batch(50u, std::chrono::seconds(30)))
        .WillOnce(Return(std::vector<domain::AuthOutboxEntity>{e1, e2}));

    EXPECT_CALL(*client, submit_batch(_))
        .WillOnce(Invoke([&](const std::vector<::securecloud::audit::v1::AuditEventProto>& batch) {
            EXPECT_EQ(batch.size(), 2u);
            EXPECT_EQ(batch[0].event_id(), e1.event_id.to_string());
            EXPECT_EQ(batch[0].producer_service(), ::securecloud::audit::v1::PRODUCER_SERVICE_AUTH);
            EXPECT_EQ(batch[1].event_id(), e2.event_id.to_string());

            AuditBatchSubmitResult res;
            res.rpc_success = true;
            res.status = grpc::Status::OK;
            res.accepted_count = 2;
            res.rejected_count = 0;
            return res;
        }));

    EXPECT_CALL(*repo, mark_published(e1.event_id)).WillOnce(Return(true));
    EXPECT_CALL(*repo, mark_published(e2.event_id)).WillOnce(Return(true));

    AuthOutboxRelay relay(repo, client);
    EXPECT_EQ(relay.poll_and_dispatch(), 2u);
}

TEST(AuthOutboxRelayTest, PollAndDispatch_PermanentRejectionsAndMalformedPayload_QuarantinesWithoutBlockingValid) {
    auto repo = std::make_shared<NiceMock<MockAuthOutboxRepository>>();
    auto client = std::make_shared<NiceMock<MockAuthAuditClient>>();

    const auto valid_ev = make_valid_outbox_entity();
    const auto rejected_ev = make_valid_outbox_entity();

    domain::AuthOutboxEntity poison_ev;
    poison_ev.event_id = domain::Uuid::generate_v7();
    poison_ev.payload_json = "{corrupted_json";

    EXPECT_CALL(*repo, fetch_and_lease_pending_batch(50u, std::chrono::seconds(30)))
        .WillOnce(Return(std::vector<domain::AuthOutboxEntity>{poison_ev, valid_ev, rejected_ev}));

    // Poison pill is quarantined locally before gRPC call
    EXPECT_CALL(*repo, mark_quarantined(poison_ev.event_id, _)).WillOnce(Return(true));

    EXPECT_CALL(*client, submit_batch(_))
        .WillOnce(Invoke([&](const std::vector<::securecloud::audit::v1::AuditEventProto>& batch) {
            EXPECT_EQ(batch.size(), 2u);
            AuditBatchSubmitResult res;
            res.rpc_success = true;
            res.status = grpc::Status::OK;
            res.accepted_count = 1;
            res.rejected_count = 1;
            res.rejected_event_ids = {rejected_ev.event_id.to_string()};
            return res;
        }));

    EXPECT_CALL(*repo, mark_published(valid_ev.event_id)).WillOnce(Return(true));
    EXPECT_CALL(*repo, mark_quarantined(rejected_ev.event_id, HasSubstr("AuditIngestionService")))
        .WillOnce(Return(true));

    AuthOutboxRelay relay(repo, client);
    EXPECT_EQ(relay.poll_and_dispatch(), 3u);
}

TEST(AuthOutboxRelayTest, PollAndDispatch_TransientGrpcFailure_MarksFailedAndRetainsPendingForIdempotentRetry) {
    auto repo = std::make_shared<NiceMock<MockAuthOutboxRepository>>();
    auto client = std::make_shared<NiceMock<MockAuthAuditClient>>();

    const auto e1 = make_valid_outbox_entity();
    const auto e2 = make_valid_outbox_entity();

    EXPECT_CALL(*repo, fetch_and_lease_pending_batch(_, _))
        .WillOnce(Return(std::vector<domain::AuthOutboxEntity>{e1, e2}));

    AuditBatchSubmitResult unavailable_res;
    unavailable_res.rpc_success = false;
    unavailable_res.status = grpc::Status(grpc::StatusCode::UNAVAILABLE, "Connection reset by peer");

    EXPECT_CALL(*client, submit_batch(_)).WillOnce(Return(unavailable_res));

    EXPECT_CALL(*repo, mark_published(_)).Times(0);
    EXPECT_CALL(*repo, mark_quarantined(_, _)).Times(0);
    EXPECT_CALL(*repo, mark_failed(e1.event_id, HasSubstr("Connection reset by peer"))).WillOnce(Return(true));
    EXPECT_CALL(*repo, mark_failed(e2.event_id, HasSubstr("Connection reset by peer"))).WillOnce(Return(true));

    AuthOutboxRelay relay(repo, client);
    EXPECT_EQ(relay.poll_and_dispatch(), 2u);
}

TEST(AuthOutboxRelayTest, ComputeBackoffDelay_AppliesExponentialGrowthCeilingAndJitter) {
    auto repo = std::make_shared<NiceMock<MockAuthOutboxRepository>>();
    auto client = std::make_shared<NiceMock<MockAuthAuditClient>>();

    AuthOutboxRelayConfig cfg;
    cfg.initial_backoff = std::chrono::milliseconds(200);
    cfg.max_backoff = std::chrono::milliseconds(1000);
    cfg.backoff_multiplier = 2.0;
    cfg.jitter_ratio = 0.25;

    AuthOutboxRelay relay(repo, client, cfg);

    EXPECT_EQ(relay.compute_backoff_delay(0).count(), 0);

    // Attempt 1: 200ms ± 25% -> [150, 250]
    for (int i = 0; i < 20; ++i) {
        const auto d1 = relay.compute_backoff_delay(1).count();
        EXPECT_GE(d1, 150);
        EXPECT_LE(d1, 250);
    }

    // Attempt 2: 400ms ± 25% -> [300, 500]
    for (int i = 0; i < 20; ++i) {
        const auto d2 = relay.compute_backoff_delay(2).count();
        EXPECT_GE(d2, 300);
        EXPECT_LE(d2, 500);
    }

    // Attempt 10: capped at max_backoff 1000ms
    for (int i = 0; i < 20; ++i) {
        const auto d10 = relay.compute_backoff_delay(10).count();
        EXPECT_GE(d10, 750);
        EXPECT_LE(d10, 1000);
    }
}

TEST(AuthOutboxRelayTest, PurgeOldPublishedRecords_UsesConfiguredRetentionAndBatchSize) {
    auto repo = std::make_shared<NiceMock<MockAuthOutboxRepository>>();
    auto client = std::make_shared<NiceMock<MockAuthAuditClient>>();

    AuthOutboxRelayConfig cfg;
    cfg.published_retention = std::chrono::hours(24 * 7);
    cfg.purge_batch_size = 500;

    const auto expected_cutoff = std::chrono::system_clock::now() - cfg.published_retention;
    EXPECT_CALL(*repo, purge_published_older_than(
                           AllOf(Ge(expected_cutoff - std::chrono::seconds(5)),
                                 Le(expected_cutoff + std::chrono::seconds(5))),
                           500u))
        .WillOnce(Return(42u));

    AuthOutboxRelay relay(repo, client, cfg);
    EXPECT_EQ(relay.purge_old_published_records(), 42u);
}

TEST(AuthOutboxRelayTest, StartAndStop_DrainsPendingEventsOnGracefulShutdown) {
    auto repo = std::make_shared<NiceMock<MockAuthOutboxRepository>>();
    auto client = std::make_shared<NiceMock<MockAuthAuditClient>>();

    const auto drain_ev = make_valid_outbox_entity();

    // Return empty during background loop, then return 1 pending event during shutdown drain
    EXPECT_CALL(*repo, fetch_and_lease_pending_batch(_, _))
        .WillOnce(Return(std::vector<domain::AuthOutboxEntity>{}))
        .WillOnce(Return(std::vector<domain::AuthOutboxEntity>{drain_ev}))
        .WillRepeatedly(Return(std::vector<domain::AuthOutboxEntity>{}));

    AuditBatchSubmitResult ok_res;
    ok_res.rpc_success = true;
    ok_res.status = grpc::Status::OK;
    ok_res.accepted_count = 1;

    EXPECT_CALL(*client, submit_batch(_)).WillOnce(Return(ok_res));
    EXPECT_CALL(*repo, mark_published(drain_ev.event_id)).WillOnce(Return(true));

    AuthOutboxRelayConfig cfg;
    cfg.poll_interval = std::chrono::milliseconds(50);
    cfg.shutdown_drain_timeout = std::chrono::milliseconds(500);

    AuthOutboxRelay relay(repo, client, cfg);
    EXPECT_FALSE(relay.is_running());

    relay.start();
    EXPECT_TRUE(relay.is_running());
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    relay.stop();
    EXPECT_FALSE(relay.is_running());
}

TEST(AuthConfigOutboxTest, Load_ParsesAuditAndOutboxRelayEnvironmentVariables) {
    MapConfigSource source({
        {"SECURECLOUD_AUTH_DB_PASSWORD", "super-secret-db-pass"},
        {"SECURECLOUD_AUTH_AUDIT_ENDPOINT", "audit.securecloud.internal:50055"},
        {"SECURECLOUD_AUTH_AUDIT_TIMEOUT_MS", "3500"},
        {"SECURECLOUD_AUTH_AUDIT_PEER_SAN", "audit.securecloud.internal"},
        {"SECURECLOUD_AUTH_OUTBOX_POLL_INTERVAL_MS", "250"},
        {"SECURECLOUD_AUTH_OUTBOX_BATCH_SIZE", "75"},
        {"SECURECLOUD_AUTH_OUTBOX_LEASE_SECONDS", "45"},
        {"SECURECLOUD_AUTH_OUTBOX_INITIAL_BACKOFF_MS", "100"},
        {"SECURECLOUD_AUTH_OUTBOX_MAX_BACKOFF_MS", "15000"},
        {"SECURECLOUD_AUTH_OUTBOX_RETENTION_HOURS", "72"},
        {"SECURECLOUD_AUTH_OUTBOX_PURGE_BATCH_SIZE", "250"},
    });

    common::configuration::ValidationResult errors;
    const auto cfg = AuthConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid()) << errors.to_string();
    EXPECT_TRUE(cfg.outbox_relay_enabled);
    EXPECT_EQ(cfg.audit_endpoint, "audit.securecloud.internal:50055");
    EXPECT_EQ(cfg.audit_timeout, std::chrono::milliseconds(3500));
    EXPECT_EQ(cfg.audit_expected_peer_san, "audit.securecloud.internal");
    EXPECT_EQ(cfg.outbox_relay.poll_interval, std::chrono::milliseconds(250));
    EXPECT_EQ(cfg.outbox_relay.batch_size, 75u);
    EXPECT_EQ(cfg.outbox_relay.lease_duration, std::chrono::seconds(45));
    EXPECT_EQ(cfg.outbox_relay.initial_backoff, std::chrono::milliseconds(100));
    EXPECT_EQ(cfg.outbox_relay.max_backoff, std::chrono::milliseconds(15000));
    EXPECT_EQ(cfg.outbox_relay.published_retention, std::chrono::hours(72));
    EXPECT_EQ(cfg.outbox_relay.purge_batch_size, 250u);
}

} // namespace
} // namespace securecloud::auth::audit::test
