#include "auth/auth_config.hpp"
#include "auth/crypto/argon2id_hasher.hpp"
#include "auth/db/migration_runner.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/repository/user_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/credential_verifier.hpp"
#include "auth/service/session_manager.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::auth::integration::test {
namespace {

using domain::AccountStatus;
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
    config.db_port = 5433; // Strictly container port 5433 (PostgreSQL 17)
    config.db_name = "securecloud_auth";
    config.db_user = "auth_user";
    config.db_password = common::configuration::SecretString("auth_dev_db_secret");
    return config;
}

// In-memory test sink for capturing audit events during integration tests
class TestAuditSink final : public service::IAuditEventSink {
  public:
    void emit(const domain::AuditEvent& event, std::string_view /*json_payload*/) override {
        emitted_events.push_back(event);
    }
    std::vector<domain::AuditEvent> emitted_events;
};

// ============================================================================
// 1. Strict Port 5432 Protection & Pre-Flight Isolation
// ============================================================================

TEST(AuthSessionPreflightTest, StrictPort5432Protection) {
    AuthConfig forbidden_cfg = make_test_auth_config();
    forbidden_cfg.db_port = 5432;

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), db::PortForbiddenException);
}

// ============================================================================
// 2. End-to-End Live Session Integration Test Fixture
// ============================================================================

class AuthSessionIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        config_ = make_test_auth_config();

        // Security Guard Invariant: NEVER touch host PostgreSQL 14 on port 5432!
        ASSERT_NE(config_.db_port, 5432) << "CRITICAL ERROR: Tests must NEVER connect to host PostgreSQL on port 5432!";
        ASSERT_EQ(config_.db_port, 5433) << "Tests must strictly connect to containerized PostgreSQL 17 on port 5433!";

        db::ConnectionPoolConfig pool_cfg;
        pool_cfg.min_connections = 0;
        pool_cfg.max_connections = 10;
        pool_cfg.acquire_timeout = std::chrono::milliseconds{5000};
        pool_cfg.connect_timeout = std::chrono::seconds{2};

        pool_ = std::make_unique<db::PostgresConnectionPool>(config_, pool_cfg);

        // Ensure database is online and reachable
        if (!pool_->ping()) {
            GTEST_SKIP() << "PostgreSQL 17 container on 127.0.0.1:5433 is not reachable. Skipping live database "
                            "integration tests.";
        }

        // Ensure migrations are applied prior to running tests
        db::MigrationRunner runner(*pool_);
        runner.run_migrations();

        audit_sink_ = std::make_shared<TestAuditSink>();
        audit_publisher_ = std::make_shared<service::AuditEventPublisher>(audit_sink_);

        user_repo_ = std::make_shared<repository::PostgresUserRepository>(*pool_);
        device_repo_ = std::make_shared<repository::PostgresDeviceRepository>(*pool_);
        session_repo_ = std::make_shared<repository::PostgresSessionRepository>(*pool_);
        hasher_ = std::make_shared<crypto::OpenSslArgon2idHasher>();
    }

    // Factory to construct a fresh AuthServiceImpl instance wired to the same database pool
    std::unique_ptr<service::AuthServiceImpl> create_auth_service() {
        auto verifier = std::make_shared<service::CredentialVerifier>(user_repo_, hasher_);
        auto session_mgr = std::make_shared<service::SessionManager>(session_repo_, device_repo_,
                                                                     std::chrono::hours(24), audit_publisher_);
        return std::make_unique<service::AuthServiceImpl>(verifier, session_mgr, audit_publisher_);
    }

    AuthConfig config_;
    std::unique_ptr<db::PostgresConnectionPool> pool_;
    std::shared_ptr<TestAuditSink> audit_sink_;
    std::shared_ptr<service::AuditEventPublisher> audit_publisher_;
    std::shared_ptr<repository::PostgresUserRepository> user_repo_;
    std::shared_ptr<repository::PostgresDeviceRepository> device_repo_;
    std::shared_ptr<repository::PostgresSessionRepository> session_repo_;
    std::shared_ptr<crypto::OpenSslArgon2idHasher> hasher_;
};

// Test 2: Session Durability Across Service Restart & Lifecycle Revocation
TEST_F(AuthSessionIntegrationTest, SessionDurabilityAcrossServiceRestart) {
    std::string email = "user_" + Uuid::generate_v7().to_string() + "@securecloud.io";
    std::string raw_password = "SecurePassword123!";

    // 1. Create User and Active Device
    UserEntity user;
    user.user_id = Uuid::generate_v7();
    user.credential_identifier = email;
    user.password_verifier = hasher_->hash_password(common::configuration::SecretString(raw_password));
    user.password_algorithm = "argon2id";
    user.password_updated_at = std::chrono::system_clock::now();
    user.account_status = AccountStatus::Active;
    user.created_at = std::chrono::system_clock::now();
    user.updated_at = user.created_at;
    user.version = 1;
    user_repo_->create_user(user);

    DeviceEntity device;
    device.device_id = Uuid::generate_v7();
    device.user_id = user.user_id;
    device.device_status = DeviceStatus::Active;
    device.registered_at = std::chrono::system_clock::now();
    device.last_authenticated_at = device.registered_at;
    device.created_at = device.registered_at;
    device.updated_at = device.registered_at;
    device_repo_->register_device(device);

    // 2. Start Service Instance 1 and Authenticate
    auto service_instance_1 = create_auth_service();

    grpc::ServerContext auth_ctx;
    v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(email);
    auth_req.set_password(raw_password);
    auth_req.set_device_id(device.device_id.to_string());
    v1::AuthenticateResponse auth_resp;

    auto auth_status = service_instance_1->Authenticate(&auth_ctx, &auth_req, &auth_resp);
    ASSERT_TRUE(auth_status.ok()) << "Authentication failed: " << auth_status.error_message();

    std::string session_id_str = auth_resp.session_id();
    ASSERT_FALSE(session_id_str.empty());

    // Validate on Instance 1
    grpc::ServerContext val_ctx_1;
    v1::ValidateSessionRequest val_req_1;
    val_req_1.set_session_id(session_id_str);
    v1::ValidateSessionResponse val_resp_1;

    auto val_status_1 = service_instance_1->ValidateSession(&val_ctx_1, &val_req_1, &val_resp_1);
    ASSERT_TRUE(val_status_1.ok());
    EXPECT_TRUE(val_resp_1.is_valid());
    EXPECT_EQ(val_resp_1.user_id(), user.user_id.to_string());
    EXPECT_EQ(val_resp_1.device_id(), device.device_id.to_string());

    // 3. Simulate Complete Process Restart: Destroy Instance 1
    service_instance_1.reset();

    // 4. Start Service Instance 2 with Fresh State Over Same Database Pool
    auto service_instance_2 = create_auth_service();

    // Validate on Instance 2: State MUST be durable
    grpc::ServerContext val_ctx_2;
    v1::ValidateSessionRequest val_req_2;
    val_req_2.set_session_id(session_id_str);
    v1::ValidateSessionResponse val_resp_2;

    auto val_status_2 = service_instance_2->ValidateSession(&val_ctx_2, &val_req_2, &val_resp_2);
    ASSERT_TRUE(val_status_2.ok());
    EXPECT_TRUE(val_resp_2.is_valid());
    EXPECT_EQ(val_resp_2.user_id(), user.user_id.to_string());
    EXPECT_EQ(val_resp_2.device_id(), device.device_id.to_string());

    // 5. Revoke Session on Instance 2
    grpc::ServerContext rev_ctx;
    v1::RevokeSessionRequest rev_req;
    rev_req.set_session_id(session_id_str);
    rev_req.set_reason("User logout in integration test");
    v1::RevokeSessionResponse rev_resp;

    auto rev_status = service_instance_2->RevokeSession(&rev_ctx, &rev_req, &rev_resp);
    ASSERT_TRUE(rev_status.ok());
    EXPECT_TRUE(rev_resp.revoked());

    // 6. Post-Revocation: ValidateSession on Instance 2 MUST deterministically reject
    grpc::ServerContext post_rev_ctx;
    v1::ValidateSessionRequest post_rev_req;
    post_rev_req.set_session_id(session_id_str);
    v1::ValidateSessionResponse post_rev_resp;

    auto post_rev_status = service_instance_2->ValidateSession(&post_rev_ctx, &post_rev_req, &post_rev_resp);
    ASSERT_TRUE(post_rev_status.ok());
    EXPECT_FALSE(post_rev_resp.is_valid());
}

// Test 3: Concurrent Multi-Threaded Session Revocation and Validation Stress Test
TEST_F(AuthSessionIntegrationTest, ConcurrentSessionRevocationAndValidationRace) {
    std::string email = "race_" + Uuid::generate_v7().to_string() + "@securecloud.io";
    std::string raw_password = "RacePassword123!";

    UserEntity user;
    user.user_id = Uuid::generate_v7();
    user.credential_identifier = email;
    user.password_verifier = hasher_->hash_password(common::configuration::SecretString(raw_password));
    user.password_algorithm = "argon2id";
    user.password_updated_at = std::chrono::system_clock::now();
    user.account_status = AccountStatus::Active;
    user.created_at = std::chrono::system_clock::now();
    user.updated_at = user.created_at;
    user.version = 1;
    user_repo_->create_user(user);

    DeviceEntity device;
    device.device_id = Uuid::generate_v7();
    device.user_id = user.user_id;
    device.device_status = DeviceStatus::Active;
    device.registered_at = std::chrono::system_clock::now();
    device.last_authenticated_at = device.registered_at;
    device.created_at = device.registered_at;
    device.updated_at = device.registered_at;
    device_repo_->register_device(device);

    auto service = create_auth_service();

    grpc::ServerContext auth_ctx;
    v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(email);
    auth_req.set_password(raw_password);
    auth_req.set_device_id(device.device_id.to_string());
    v1::AuthenticateResponse auth_resp;

    auto auth_status = service->Authenticate(&auth_ctx, &auth_req, &auth_resp);
    ASSERT_TRUE(auth_status.ok());
    std::string session_id_str = auth_resp.session_id();

    constexpr int k_num_readers = 4;
    std::atomic<bool> stop_flag{false};
    std::atomic<int> read_count{0};
    std::vector<std::thread> reader_threads;

    for (int i = 0; i < k_num_readers; ++i) {
        reader_threads.emplace_back([&, this]() {
            auto thread_service = create_auth_service();
            while (!stop_flag.load(std::memory_order_relaxed)) {
                grpc::ServerContext val_ctx;
                v1::ValidateSessionRequest val_req;
                val_req.set_session_id(session_id_str);
                v1::ValidateSessionResponse val_resp;
                auto s = thread_service->ValidateSession(&val_ctx, &val_req, &val_resp);
                EXPECT_TRUE(s.ok());
                read_count.fetch_add(1, std::memory_order_relaxed);
                std::this_thread::yield();
            }
        });
    }

    // Let concurrent readers run briefly
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Execute RevokeSession from another thread
    grpc::ServerContext rev_ctx;
    v1::RevokeSessionRequest rev_req;
    rev_req.set_session_id(session_id_str);
    rev_req.set_reason("Concurrent race test");
    v1::RevokeSessionResponse rev_resp;
    auto rev_status = service->RevokeSession(&rev_ctx, &rev_req, &rev_resp);
    EXPECT_TRUE(rev_status.ok());
    EXPECT_TRUE(rev_resp.revoked());

    // Stop reader threads
    stop_flag.store(true, std::memory_order_relaxed);
    for (auto& t : reader_threads) {
        t.join();
    }

    EXPECT_GT(read_count.load(), 0);

    // Final check: MUST deterministically return is_valid = false
    grpc::ServerContext final_ctx;
    v1::ValidateSessionRequest final_req;
    final_req.set_session_id(session_id_str);
    v1::ValidateSessionResponse final_resp;
    auto final_status = service->ValidateSession(&final_ctx, &final_req, &final_resp);
    EXPECT_TRUE(final_status.ok());
    EXPECT_FALSE(final_resp.is_valid());
}

} // namespace
} // namespace securecloud::auth::integration::test
