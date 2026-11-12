#include "auth/audit/auth_audit_client.hpp"
#include "auth/audit/auth_outbox_diagnostics.hpp"
#include "auth/audit/auth_outbox_metrics.hpp"
#include "auth/audit/auth_outbox_relay.hpp"
#include "auth/auth_config.hpp"
#include "auth/crypto/argon2id_hasher.hpp"
#include "auth/db/db_exec.hpp"
#include "auth/db/migration_runner.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/audit_event.hpp"
#include "auth/domain/auth_outbox_entity.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/auth_outbox_repository.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/repository/user_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/credential_verifier.hpp"
#include "auth/service/outbox_event_mapper.hpp"
#include "auth/service/session_manager.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace securecloud::auth::integration::test {
namespace {

using domain::AccountStatus;
using domain::AuditEvent;
using domain::AuthenticationLevel;
using domain::DeviceEntity;
using domain::DeviceStatus;
using domain::SessionEntity;
using domain::SessionStatus;
using domain::UserEntity;
using domain::Uuid;

AuthConfig make_test_auth_config() {
    AuthConfig config;
    config.db_host = "127.0.0.1";
    config.db_port = 5433; // Strictly containerized PostgreSQL 17 on port 5433
    config.db_name = "securecloud_auth";
    config.db_user = "auth_user";
    config.db_password = common::configuration::SecretString("auth_dev_db_secret");
    return config;
}

/// Thread-safe in-memory AuditIngestionService test double supporting outage & rejection injection.
class FakeAuditIngestionClient final : public audit::IAuthAuditClient {
  public:
    audit::AuditBatchSubmitResult
    submit_batch(const std::vector<::securecloud::audit::v1::AuditEventProto>& events) override {
        audit::AuditBatchSubmitResult res;
        if (!available.load(std::memory_order_acquire)) {
            res.rpc_success = false;
            res.status = grpc::Status(grpc::StatusCode::UNAVAILABLE, "Simulated AuditIngestionService outage");
            return res;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        res.rpc_success = true;
        res.status = grpc::Status::OK;

        for (const auto& ev : events) {
            if (rejected_ids.contains(ev.event_id())) {
                res.rejected_event_ids.push_back(ev.event_id());
                ++res.rejected_count;
            } else {
                delivered_ids.push_back(ev.event_id());
                ++res.accepted_count;
            }
        }
        return res;
    }

    std::atomic<bool> available{true};
    std::unordered_set<std::string> rejected_ids;
    std::vector<std::string> delivered_ids;

  private:
    std::mutex mutex_;
};

// ============================================================================
// Pre-flight Port 5432 Guard
// ============================================================================

TEST(AuthOutboxPreflightTest, StrictPort5432Protection) {
    AuthConfig forbidden_cfg = make_test_auth_config();
    forbidden_cfg.db_port = 5432;

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), db::PortForbiddenException);
}

// ============================================================================
// Live PostgreSQL Transactional Outbox Verification Fixture
// ============================================================================

class AuthOutboxTransactionIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        config_ = make_test_auth_config();

        ASSERT_NE(config_.db_port, 5432) << "CRITICAL: Tests must NEVER connect to host PostgreSQL on port 5432!";
        ASSERT_EQ(config_.db_port, 5433) << "Tests must strictly connect to containerized PostgreSQL 17 on port 5433!";

        db::ConnectionPoolConfig pool_cfg;
        pool_cfg.min_connections = 0;
        pool_cfg.max_connections = 16;
        pool_cfg.acquire_timeout = std::chrono::milliseconds{5000};
        pool_cfg.connect_timeout = std::chrono::seconds{2};
        pool_cfg.statement_timeout = std::chrono::milliseconds{2000};

        pool_ = std::make_unique<db::PostgresConnectionPool>(config_, pool_cfg);

        if (!pool_->ping()) {
            GTEST_SKIP() << "PostgreSQL 17 container on 127.0.0.1:5433 is not reachable. Skipping live database "
                            "outbox integration tests.";
        }

        db::MigrationRunner runner(*pool_);
        const auto mig_res = runner.run_migrations();
        ASSERT_GE(mig_res.current_version, 5);

        // Isolate each test run with an empty outbox table
        {
            auto conn = pool_->acquire();
            pqxx::work tx(*conn);
            db::exec_sql(tx, "DELETE FROM auth_outbox;", pqxx::params{});
            tx.commit();
        }

        metrics_.reset();
        diagnostics_.set_output_stream(&log_buffer_);

        outbox_repo_ = std::make_shared<repository::PostgresAuthOutboxRepository>(*pool_);
        user_repo_ = std::make_shared<repository::PostgresUserRepository>(*pool_);
        device_repo_ = std::make_shared<repository::PostgresDeviceRepository>(*pool_);
        session_repo_ = std::make_shared<repository::PostgresSessionRepository>(*pool_);
        hasher_ = std::make_shared<crypto::OpenSslArgon2idHasher>();
    }

    void TearDown() override { diagnostics_.set_output_stream(nullptr); }

    struct OutboxRowSnapshot {
        std::string status;
        int32_t retry_count{0};
        bool has_processed_at{false};
        bool has_leased_until{false};
        std::optional<std::string> last_error;
    };

    std::optional<OutboxRowSnapshot> fetch_outbox_row(const Uuid& event_id) {
        auto conn = pool_->acquire();
        pqxx::work tx(*conn);
        auto res =
            db::exec_sql(tx,
                         "SELECT status, retry_count, processed_at IS NOT NULL, leased_until IS NOT NULL, last_error "
                         "FROM auth_outbox WHERE event_id = $1;",
                         pqxx::params{event_id.to_string()});
        tx.commit();
        if (res.empty()) {
            return std::nullopt;
        }
        OutboxRowSnapshot snap;
        snap.status = res[0][0].as<std::string>();
        snap.retry_count = res[0][1].as<int32_t>();
        snap.has_processed_at = res[0][2].as<bool>();
        snap.has_leased_until = res[0][3].as<bool>();
        if (!res[0][4].is_null()) {
            snap.last_error = res[0][4].as<std::string>();
        }
        return snap;
    }

    std::pair<UserEntity, DeviceEntity> create_active_user_and_device(std::string_view raw_password = "Password123!") {
        const auto now = std::chrono::system_clock::now();
        const auto user_id = Uuid::generate_v7();
        const auto device_id = Uuid::generate_v7();

        UserEntity user{
            .user_id = user_id,
            .credential_identifier = "outbox_user_" + user_id.to_string() + "@securecloud.io",
            .password_verifier = hasher_->hash_password(common::configuration::SecretString(std::string(raw_password))),
            .password_algorithm = "argon2id",
            .password_updated_at = now,
            .account_status = AccountStatus::Active,
            .created_at = now,
            .updated_at = now,
            .version = 1,
        };
        user_repo_->create_user(user);

        DeviceEntity device{
            .device_id = device_id,
            .user_id = user_id,
            .device_status = DeviceStatus::Active,
            .registered_at = now,
            .revoked_at = std::nullopt,
            .revocation_reason = std::nullopt,
            .last_authenticated_at = now,
            .created_at = now,
            .updated_at = now,
        };
        device_repo_->register_device(device);

        return {user, device};
    }

    AuthConfig config_;
    std::unique_ptr<db::PostgresConnectionPool> pool_;
    audit::AuthOutboxMetrics metrics_;
    audit::AuthOutboxDiagnostics diagnostics_;
    std::ostringstream log_buffer_;
    std::shared_ptr<repository::PostgresAuthOutboxRepository> outbox_repo_;
    std::shared_ptr<repository::PostgresUserRepository> user_repo_;
    std::shared_ptr<repository::PostgresDeviceRepository> device_repo_;
    std::shared_ptr<repository::PostgresSessionRepository> session_repo_;
    std::shared_ptr<crypto::OpenSslArgon2idHasher> hasher_;
};

// ============================================================================
// Test 5: Atomic Commit (Session Creation + Outbox Event Commit Together)
// ============================================================================

TEST_F(AuthOutboxTransactionIntegrationTest, AtomicCommit_SessionAndOutboxRecordBothCommitted) {
    const auto [user, device] = create_active_user_and_device();
    service::OutboxAuditEventPublisher publisher(outbox_repo_, "auth-it-1", nullptr, &metrics_);

    const auto now = std::chrono::system_clock::now();
    const auto session_id = Uuid::generate_v7();
    const auto audit_ev = AuditEvent::login_succeeded(user.user_id, user.credential_identifier, device.device_id,
                                                      session_id, "10.0.0.12");

    {
        auto conn = pool_->acquire();
        pqxx::work tx(*conn);

        db::exec_sql(tx,
                     "INSERT INTO sessions ("
                     "  session_id, user_id, device_id, session_status, authentication_level,"
                     "  created_at, expires_at, revoked_at, last_used_at"
                     ") VALUES ($1, $2, $3, 'ACTIVE', 'PRIMARY_ONLY', $4, $5, NULL, $4);",
                     pqxx::params{session_id.to_string(), user.user_id.to_string(), device.device_id.to_string(),
                                  domain::to_iso8601(now), domain::to_iso8601(now + std::chrono::hours(24))});

        publisher.publish_in_tx(audit_ev, tx);
        tx.commit();
    }

    const auto persisted_session = session_repo_->find_by_id(session_id);
    ASSERT_TRUE(persisted_session.has_value());
    EXPECT_EQ(persisted_session->session_status, SessionStatus::Active);

    const auto persisted_outbox = fetch_outbox_row(audit_ev.event_id);
    ASSERT_TRUE(persisted_outbox.has_value());
    EXPECT_EQ(persisted_outbox->status, "PENDING");
    EXPECT_EQ(persisted_outbox->retry_count, 0);
    EXPECT_EQ(metrics_.events_staged_total(audit::StagingCategory::Transactional), 1u);
}

// ============================================================================
// Test 6: Atomic Rollback (Aborted Transaction Leaves Zero Phantom Events)
// ============================================================================

TEST_F(AuthOutboxTransactionIntegrationTest, AtomicRollback_AbortedTransactionLeavesZeroPhantomEvents) {
    const auto [user, device] = create_active_user_and_device();
    service::OutboxAuditEventPublisher publisher(outbox_repo_, "auth-it-1", nullptr, &metrics_);

    const auto now = std::chrono::system_clock::now();
    const auto session_id = Uuid::generate_v7();
    const auto audit_ev = AuditEvent::login_succeeded(user.user_id, user.credential_identifier, device.device_id,
                                                      session_id, "10.0.0.13");

    {
        auto conn = pool_->acquire();
        pqxx::work tx(*conn);

        db::exec_sql(tx,
                     "INSERT INTO sessions ("
                     "  session_id, user_id, device_id, session_status, authentication_level,"
                     "  created_at, expires_at, revoked_at, last_used_at"
                     ") VALUES ($1, $2, $3, 'ACTIVE', 'PRIMARY_ONLY', $4, $5, NULL, $4);",
                     pqxx::params{session_id.to_string(), user.user_id.to_string(), device.device_id.to_string(),
                                  domain::to_iso8601(now), domain::to_iso8601(now + std::chrono::hours(24))});

        publisher.publish_in_tx(audit_ev, tx);

        // Simulate business failure / constraint violation forcing transaction abort
        tx.abort();
    }

    EXPECT_FALSE(session_repo_->find_by_id(session_id).has_value());
    EXPECT_FALSE(fetch_outbox_row(audit_ev.event_id).has_value());
    EXPECT_EQ(outbox_repo_->count_pending(), 0u);
}

// ============================================================================
// Test 7: Autonomous Staging (Failed Login Stages Outbox Event Independently)
// ============================================================================

TEST_F(AuthOutboxTransactionIntegrationTest, AutonomousStaging_FailedLoginCommitsOutboxEventIndependently) {
    const auto [user, device] = create_active_user_and_device("CorrectHorseBatteryStaple!");

    auto publisher =
        std::make_shared<service::OutboxAuditEventPublisher>(outbox_repo_, "auth-it-1", nullptr, &metrics_);
    auto verifier = std::make_shared<service::CredentialVerifier>(user_repo_, hasher_);
    auto session_mgr =
        std::make_shared<service::SessionManager>(session_repo_, device_repo_, std::chrono::hours(24), publisher);
    service::AuthServiceImpl auth_service(verifier, session_mgr, publisher);

    grpc::ServerContext ctx;
    v1::AuthenticateRequest req;
    req.set_credential_identifier(user.credential_identifier);
    req.set_password("WrongPasswordAttempt!");
    req.set_device_id(device.device_id.to_string());
    v1::AuthenticateResponse resp;

    const auto status = auth_service.Authenticate(&ctx, &req, &resp);
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);

    // Verify no session was created, yet the autonomous auth.login.failed audit event is durably staged
    EXPECT_TRUE(session_repo_->list_active_by_user_id(user.user_id).empty());
    EXPECT_EQ(outbox_repo_->count_pending(), 1u);
    EXPECT_EQ(metrics_.events_staged_total(audit::StagingCategory::Autonomous), 1u);

    auto leased = outbox_repo_->fetch_and_lease_pending_batch(10, std::chrono::seconds(30));
    ASSERT_EQ(leased.size(), 1u);
    EXPECT_EQ(leased[0].event_type, "auth.login.failed");
}

// ============================================================================
// Test 8: Crash & Restart Recovery (100 Staged Events Delivered After Restart)
// ============================================================================

TEST_F(AuthOutboxTransactionIntegrationTest, CrashAndRestartRecovery_DeliversAll100PendingEvents) {
    constexpr size_t kEventCount = 100;
    const auto uid = Uuid::generate_v7();
    const auto did = Uuid::generate_v7();
    const auto sid = Uuid::generate_v7();

    std::vector<Uuid> staged_ids;
    staged_ids.reserve(kEventCount);

    for (size_t i = 0; i < kEventCount; ++i) {
        const auto ev = AuditEvent::login_succeeded(uid, "crash_test@securecloud.io", did, sid, "192.0.2.10");
        const auto entity = service::OutboxEventMapper::to_outbox_entity(ev);
        outbox_repo_->stage_event(entity);
        staged_ids.push_back(entity.event_id);
    }

    ASSERT_EQ(outbox_repo_->count_pending(), kEventCount);

    // Instantiate fresh relay worker simulating process startup after crash
    auto fake_client = std::make_shared<FakeAuditIngestionClient>();
    audit::AuthOutboxRelayConfig cfg;
    cfg.batch_size = 40;
    cfg.poll_interval = std::chrono::milliseconds(10);

    audit::AuthOutboxRelay relay(outbox_repo_, fake_client, cfg, "auth-restarted", &metrics_, &diagnostics_);
    while (outbox_repo_->count_pending() > 0) {
        ASSERT_GT(relay.poll_and_dispatch(), 0u);
    }

    EXPECT_EQ(fake_client->delivered_ids.size(), kEventCount);
    EXPECT_EQ(outbox_repo_->count_pending(), 0u);
    EXPECT_EQ(metrics_.events_delivered_total(), kEventCount);

    for (const auto& id : staged_ids) {
        const auto snap = fetch_outbox_row(id);
        ASSERT_TRUE(snap.has_value());
        EXPECT_EQ(snap->status, "PUBLISHED");
        EXPECT_TRUE(snap->has_processed_at);
        EXPECT_FALSE(snap->has_leased_until);
    }
}

// ============================================================================
// Test 9: Multi-Worker Concurrency (SKIP LOCKED Across 4 Threads, 1,000 Events)
// ============================================================================

TEST_F(AuthOutboxTransactionIntegrationTest, MultiWorkerConcurrency_FourWorkersProcess1000EventsWithZeroDuplicates) {
    constexpr size_t kTotalEvents = 1000;
    constexpr size_t kNumWorkers = 4;

    const auto uid = Uuid::generate_v7();
    const auto did = Uuid::generate_v7();
    const auto sid = Uuid::generate_v7();

    // Bulk-insert 1,000 pending events in a single transaction for fast test setup
    {
        auto conn = pool_->acquire();
        pqxx::work tx(*conn);
        for (size_t i = 0; i < kTotalEvents; ++i) {
            const auto ev = AuditEvent::token_refreshed(sid, uid, did, "198.51.100.200");
            const auto entity = service::OutboxEventMapper::to_outbox_entity(ev);
            outbox_repo_->stage_event(entity, tx);
        }
        tx.commit();
    }

    ASSERT_EQ(outbox_repo_->count_pending(), kTotalEvents);

    auto fake_client = std::make_shared<FakeAuditIngestionClient>();
    audit::AuthOutboxRelayConfig cfg;
    cfg.batch_size = 25;
    cfg.poll_interval = std::chrono::milliseconds(5);
    cfg.lease_duration = std::chrono::seconds(30);
    cfg.shutdown_drain_timeout = std::chrono::milliseconds(0);

    std::vector<std::unique_ptr<audit::AuthOutboxRelay>> workers;
    workers.reserve(kNumWorkers);
    for (size_t w = 0; w < kNumWorkers; ++w) {
        workers.push_back(std::make_unique<audit::AuthOutboxRelay>(
            outbox_repo_, fake_client, cfg, "auth-worker-" + std::to_string(w), &metrics_, &diagnostics_));
    }

    for (auto& worker : workers) {
        worker->start();
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (outbox_repo_->count_pending() > 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    for (auto& worker : workers) {
        worker->stop();
    }

    EXPECT_EQ(outbox_repo_->count_pending(), 0u);
    EXPECT_EQ(fake_client->delivered_ids.size(), kTotalEvents);

    std::unordered_set<std::string> unique_ids(fake_client->delivered_ids.begin(), fake_client->delivered_ids.end());
    EXPECT_EQ(unique_ids.size(), kTotalEvents) << "SKIP LOCKED must guarantee zero duplicate deliveries";
}

// ============================================================================
// Test 10: Audit Unavailability & Backlog Drain
// ============================================================================

TEST_F(AuthOutboxTransactionIntegrationTest, AuditUnavailability_RetainsBacklogAndDrainsUponRecovery) {
    constexpr size_t kBacklogSize = 50;
    const auto uid = Uuid::generate_v7();
    const auto did = Uuid::generate_v7();

    std::vector<Uuid> ids;
    ids.reserve(kBacklogSize);
    for (size_t i = 0; i < kBacklogSize; ++i) {
        const auto ev = AuditEvent::device_authorized(uid, did, "203.0.113.88");
        const auto entity = service::OutboxEventMapper::to_outbox_entity(ev);
        outbox_repo_->stage_event(entity);
        ids.push_back(entity.event_id);
    }

    auto fake_client = std::make_shared<FakeAuditIngestionClient>();
    fake_client->available.store(false, std::memory_order_release);

    audit::AuthOutboxRelayConfig cfg;
    cfg.batch_size = 50;
    audit::AuthOutboxRelay relay(outbox_repo_, fake_client, cfg, "auth-it-1", &metrics_, &diagnostics_);

    // Attempt dispatch while Audit Service is unreachable
    EXPECT_EQ(relay.poll_and_dispatch(), kBacklogSize);
    EXPECT_EQ(fake_client->delivered_ids.size(), 0u);
    EXPECT_EQ(outbox_repo_->count_pending(), kBacklogSize);

    for (const auto& id : ids) {
        const auto snap = fetch_outbox_row(id);
        ASSERT_TRUE(snap.has_value());
        EXPECT_EQ(snap->status, "PENDING");
        EXPECT_EQ(snap->retry_count, 1);
        EXPECT_FALSE(snap->has_leased_until);
        ASSERT_TRUE(snap->last_error.has_value());
    }

    // Bring Audit Service back online and drain the backlog
    fake_client->available.store(true, std::memory_order_release);
    EXPECT_EQ(relay.poll_and_dispatch(), kBacklogSize);

    EXPECT_EQ(fake_client->delivered_ids.size(), kBacklogSize);
    EXPECT_EQ(outbox_repo_->count_pending(), 0u);
    for (const auto& id : ids) {
        const auto snap = fetch_outbox_row(id);
        ASSERT_TRUE(snap.has_value());
        EXPECT_EQ(snap->status, "PUBLISHED");
        EXPECT_FALSE(snap->last_error.has_value());
    }
}

// ============================================================================
// Test 11: Permanent Rejection Quarantine (Poison Pills Quarantined, Queue Flows)
// ============================================================================

TEST_F(AuthOutboxTransactionIntegrationTest, PermanentRejectionQuarantine_QuarantinesBadEventsAndContinues) {
    const auto uid = Uuid::generate_v7();
    const auto did = Uuid::generate_v7();
    const auto sid = Uuid::generate_v7();

    // 1. Poison event with malformed JSON payload
    domain::AuthOutboxEntity poison_entity;
    poison_entity.event_id = Uuid::generate_v7();
    poison_entity.aggregate_type = "AUTH";
    poison_entity.event_type = "auth.malformed";
    poison_entity.severity = domain::OutboxSeverity::Warning;
    poison_entity.payload_json = R"({"corrupted_unclosed": )";
    poison_entity.status = domain::OutboxStatus::Pending;
    poison_entity.created_at = std::chrono::system_clock::now() - std::chrono::seconds(3);

    // Insert raw invalid JSON text via SQL (cast bypassed if payload_json is text, or invalid schema JSONB)
    {
        auto conn = pool_->acquire();
        pqxx::work tx(*conn);
        // Valid JSONB syntax, but missing required AUDIT-002 fields so AuthAuditMapper rejects it
        db::exec_sql(
            tx,
            "INSERT INTO auth_outbox (event_id, aggregate_type, event_type, severity, payload_json, status, "
            "created_at) "
            "VALUES ($1, 'AUTH', 'auth.invalid_schema', 'WARNING', '{\"unexpected_schema\": 123}'::jsonb, 'PENDING', "
            "NOW() - INTERVAL '3 seconds');",
            pqxx::params{poison_entity.event_id.to_string()});
        tx.commit();
    }

    // 2. Event rejected remotely by AuditIngestionService
    auto remote_rejected_ev = AuditEvent::mfa_disabled(uid, "198.51.100.10");
    auto remote_rejected_entity = service::OutboxEventMapper::to_outbox_entity(remote_rejected_ev);
    remote_rejected_entity.created_at = std::chrono::system_clock::now() - std::chrono::seconds(2);
    outbox_repo_->stage_event(remote_rejected_entity);

    // 3. Valid event that must succeed
    auto valid_ev = AuditEvent::login_succeeded(uid, "survivor@securecloud.io", did, sid, "198.51.100.11");
    auto valid_entity = service::OutboxEventMapper::to_outbox_entity(valid_ev);
    valid_entity.created_at = std::chrono::system_clock::now() - std::chrono::seconds(1);
    outbox_repo_->stage_event(valid_entity);

    auto fake_client = std::make_shared<FakeAuditIngestionClient>();
    fake_client->rejected_ids.insert(remote_rejected_entity.event_id.to_string());

    audit::AuthOutboxRelay relay(outbox_repo_, fake_client, {}, "auth-it-1", &metrics_, &diagnostics_);
    EXPECT_EQ(relay.poll_and_dispatch(), 3u);

    const auto poison_snap = fetch_outbox_row(poison_entity.event_id);
    ASSERT_TRUE(poison_snap.has_value());
    EXPECT_EQ(poison_snap->status, "QUARANTINED");
    ASSERT_TRUE(poison_snap->last_error.has_value());

    const auto remote_rej_snap = fetch_outbox_row(remote_rejected_entity.event_id);
    ASSERT_TRUE(remote_rej_snap.has_value());
    EXPECT_EQ(remote_rej_snap->status, "QUARANTINED");
    ASSERT_TRUE(remote_rej_snap->last_error.has_value());

    const auto valid_snap = fetch_outbox_row(valid_entity.event_id);
    ASSERT_TRUE(valid_snap.has_value());
    EXPECT_EQ(valid_snap->status, "PUBLISHED");

    EXPECT_EQ(outbox_repo_->count_pending(), 0u);
    EXPECT_EQ(fake_client->delivered_ids.size(), 1u);
    EXPECT_EQ(fake_client->delivered_ids[0], valid_entity.event_id.to_string());
}

// ============================================================================
// Test 12: Retention Purge (Deletes Only Expired PUBLISHED Records)
// ============================================================================

TEST_F(AuthOutboxTransactionIntegrationTest, RetentionPurge_RemovesOnlyExpiredPublishedRecords) {
    const auto uid = Uuid::generate_v7();
    const auto did = Uuid::generate_v7();
    const auto sid = Uuid::generate_v7();

    const auto e_expired_1 =
        service::OutboxEventMapper::to_outbox_entity(AuditEvent::login_succeeded(uid, "a@sc.io", did, sid, "10.0.0.1"));
    const auto e_expired_2 =
        service::OutboxEventMapper::to_outbox_entity(AuditEvent::login_succeeded(uid, "b@sc.io", did, sid, "10.0.0.2"));
    const auto e_recent_pub =
        service::OutboxEventMapper::to_outbox_entity(AuditEvent::login_succeeded(uid, "c@sc.io", did, sid, "10.0.0.3"));
    const auto e_old_pending =
        service::OutboxEventMapper::to_outbox_entity(AuditEvent::login_succeeded(uid, "d@sc.io", did, sid, "10.0.0.4"));

    {
        auto conn = pool_->acquire();
        pqxx::work tx(*conn);

        // Two PUBLISHED rows processed 8 days ago (eligible for 7-day retention purge)
        for (const auto* ev : {&e_expired_1, &e_expired_2}) {
            db::exec_sql(
                tx,
                "INSERT INTO auth_outbox (event_id, aggregate_type, event_type, severity, payload_json, status, "
                "created_at, processed_at) "
                "VALUES ($1, 'AUTH', $2, 'INFO', $3::jsonb, 'PUBLISHED', NOW() - INTERVAL '9 days', "
                "NOW() - INTERVAL '8 days');",
                pqxx::params{ev->event_id.to_string(), ev->event_type, ev->payload_json});
        }

        // One PUBLISHED row processed 2 days ago (must be retained)
        db::exec_sql(
            tx,
            "INSERT INTO auth_outbox (event_id, aggregate_type, event_type, severity, payload_json, status, "
            "created_at, processed_at) "
            "VALUES ($1, 'AUTH', $2, 'INFO', $3::jsonb, 'PUBLISHED', NOW() - INTERVAL '3 days', "
            "NOW() - INTERVAL '2 days');",
            pqxx::params{e_recent_pub.event_id.to_string(), e_recent_pub.event_type, e_recent_pub.payload_json});

        // One PENDING row created 10 days ago (must NEVER be purged while still PENDING)
        db::exec_sql(
            tx,
            "INSERT INTO auth_outbox (event_id, aggregate_type, event_type, severity, payload_json, status, "
            "created_at, processed_at) "
            "VALUES ($1, 'AUTH', $2, 'INFO', $3::jsonb, 'PENDING', NOW() - INTERVAL '10 days', NULL);",
            pqxx::params{e_old_pending.event_id.to_string(), e_old_pending.event_type, e_old_pending.payload_json});

        tx.commit();
    }

    auto fake_client = std::make_shared<FakeAuditIngestionClient>();
    audit::AuthOutboxRelayConfig cfg;
    cfg.published_retention = std::chrono::hours(24 * 7); // 7 days
    cfg.purge_batch_size = 100;

    audit::AuthOutboxRelay relay(outbox_repo_, fake_client, cfg, "auth-it-1", &metrics_, &diagnostics_);
    const size_t purged = relay.purge_old_published_records();

    EXPECT_EQ(purged, 2u);
    EXPECT_EQ(metrics_.purged_total(), 2u);

    EXPECT_FALSE(fetch_outbox_row(e_expired_1.event_id).has_value());
    EXPECT_FALSE(fetch_outbox_row(e_expired_2.event_id).has_value());

    const auto recent_snap = fetch_outbox_row(e_recent_pub.event_id);
    ASSERT_TRUE(recent_snap.has_value());
    EXPECT_EQ(recent_snap->status, "PUBLISHED");

    const auto pending_snap = fetch_outbox_row(e_old_pending.event_id);
    ASSERT_TRUE(pending_snap.has_value());
    EXPECT_EQ(pending_snap->status, "PENDING");
}

} // namespace
} // namespace securecloud::auth::integration::test

// Deterministic Process Teardown (eliminates MinGW/Windows loader lock hangs)
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
#ifdef _WIN32
    std::fflush(nullptr);
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
#else
    return result;
#endif
}
