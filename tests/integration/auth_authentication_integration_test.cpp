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

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>

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

TEST(AuthAuthenticationPreflightTest, StrictPort5432Protection) {
    AuthConfig forbidden_cfg = make_test_auth_config();
    forbidden_cfg.db_port = 5432;

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), db::PortForbiddenException);
}

// ============================================================================
// 2. End-to-End Live Authentication Integration Test Fixture
// ============================================================================

class AuthAuthenticationIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        config_ = make_test_auth_config();

        // Security Guard Invariant: NEVER touch host PostgreSQL 14 on port 5432!
        ASSERT_NE(config_.db_port, 5432) << "CRITICAL ERROR: Tests must NEVER connect to host PostgreSQL on port 5432!";
        ASSERT_EQ(config_.db_port, 5433) << "Tests must strictly connect to containerized PostgreSQL 17 on port 5433!";

        db::ConnectionPoolConfig pool_cfg;
        pool_cfg.min_connections = 0;
        pool_cfg.max_connections = 5;
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
        auto audit_publisher = std::make_shared<service::AuditEventPublisher>(audit_sink_);

        auto user_repo = std::make_shared<repository::PostgresUserRepository>(*pool_);
        auto device_repo = std::make_shared<repository::PostgresDeviceRepository>(*pool_);
        auto session_repo = std::make_shared<repository::PostgresSessionRepository>(*pool_);

        user_repo_ = user_repo;
        device_repo_ = device_repo;
        session_repo_ = session_repo;

        auto hasher = std::make_shared<crypto::OpenSslArgon2idHasher>();
        hasher_ = hasher;

        auto verifier = std::make_shared<service::CredentialVerifier>(user_repo, hasher);
        auto session_mgr = std::make_shared<service::SessionManager>(session_repo, device_repo);

        auth_service_ = std::make_unique<service::AuthServiceImpl>(verifier, session_mgr, audit_publisher);
    }

    AuthConfig config_;
    std::unique_ptr<db::PostgresConnectionPool> pool_;
    std::shared_ptr<TestAuditSink> audit_sink_;
    std::shared_ptr<repository::PostgresUserRepository> user_repo_;
    std::shared_ptr<repository::PostgresDeviceRepository> device_repo_;
    std::shared_ptr<repository::PostgresSessionRepository> session_repo_;
    std::shared_ptr<crypto::OpenSslArgon2idHasher> hasher_;
    std::unique_ptr<service::AuthServiceImpl> auth_service_;
};

// Test 2: Successful End-to-End Primary Authentication Flow
TEST_F(AuthAuthenticationIntegrationTest, Authenticate_SuccessfulEndToEndFlow) {
    std::string email = "user_" + Uuid::generate_v7().to_string().substr(0, 8) + "@securecloud.io";
    std::string raw_password = "SecurePassword123!";

    // 1. Create User in PostgreSQL
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

    // 2. Register Active Device for User in PostgreSQL
    DeviceEntity device;
    device.device_id = Uuid::generate_v7();
    device.user_id = user.user_id;
    device.device_status = DeviceStatus::Active;
    device.registered_at = std::chrono::system_clock::now();
    device.last_authenticated_at = device.registered_at;
    device.created_at = device.registered_at;
    device.updated_at = device.registered_at;
    device_repo_->register_device(device);

    // 3. Invoke Authenticate gRPC method
    grpc::ServerContext context;
    v1::AuthenticateRequest request;
    request.set_credential_identifier(email);
    request.set_password(raw_password);
    request.set_device_id(device.device_id.to_string());
    v1::AuthenticateResponse response;

    auto status = auth_service_->Authenticate(&context, &request, &response);
    ASSERT_TRUE(status.ok()) << "Authenticate RPC failed: " << status.error_message();

    // 4. Assert response payload
    EXPECT_EQ(response.user_id(), user.user_id.to_string());
    EXPECT_EQ(response.authentication_level(), v1::AUTHENTICATION_LEVEL_PRIMARY);
    EXPECT_GT(response.expires_at_epoch_ms(), 0);
    EXPECT_FALSE(response.mfa_required());

    auto session_id_opt = Uuid::from_string(response.session_id());
    ASSERT_TRUE(session_id_opt.has_value());

    // 5. Verify session record persisted in PostgreSQL database
    auto db_session = session_repo_->find_by_id(*session_id_opt);
    ASSERT_TRUE(db_session.has_value());
    EXPECT_EQ(db_session->user_id, user.user_id);
    EXPECT_EQ(db_session->device_id, device.device_id);
    EXPECT_EQ(db_session->session_status, SessionStatus::Active);
    EXPECT_EQ(db_session->authentication_level, AuthenticationLevel::PrimaryOnly);

    // 6. Verify audit event emission
    ASSERT_FALSE(audit_sink_->emitted_events.empty());
    const auto& last_event = audit_sink_->emitted_events.back();
    EXPECT_EQ(last_event.event_type, domain::AuditEventType::LoginSucceeded);
    EXPECT_EQ(last_event.credential_identifier, email);
    ASSERT_TRUE(last_event.user_id.has_value());
    EXPECT_EQ(last_event.user_id.value(), user.user_id);
    ASSERT_TRUE(last_event.session_id.has_value());
    EXPECT_EQ(last_event.session_id.value(), *session_id_opt);
}

// Test 3: Invalid Password Fails Authentication and Persists No Session
TEST_F(AuthAuthenticationIntegrationTest, Authenticate_InvalidPassword_ReturnsUnauthenticatedAndNoSession) {
    std::string email = "user_" + Uuid::generate_v7().to_string().substr(0, 8) + "@securecloud.io";
    std::string raw_password = "CorrectPassword123!";
    std::string wrong_password = "WrongPassword999!";

    // 1. Create User in PostgreSQL
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

    // 2. Register Active Device for User in PostgreSQL
    DeviceEntity device;
    device.device_id = Uuid::generate_v7();
    device.user_id = user.user_id;
    device.device_status = DeviceStatus::Active;
    device.registered_at = std::chrono::system_clock::now();
    device.last_authenticated_at = device.registered_at;
    device.created_at = device.registered_at;
    device.updated_at = device.registered_at;
    device_repo_->register_device(device);

    // 3. Invoke Authenticate gRPC method with WRONG password
    grpc::ServerContext context;
    v1::AuthenticateRequest request;
    request.set_credential_identifier(email);
    request.set_password(wrong_password);
    request.set_device_id(device.device_id.to_string());
    v1::AuthenticateResponse response;

    auto status = auth_service_->Authenticate(&context, &request, &response);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_EQ(status.error_message(), "Invalid credentials");

    // 4. Verify NO active sessions created in database for this user
    auto active_sessions = session_repo_->list_active_by_user_id(user.user_id);
    EXPECT_TRUE(active_sessions.empty());

    // 5. Verify audit event was emitted as LoginFailed
    ASSERT_FALSE(audit_sink_->emitted_events.empty());
    const auto& last_event = audit_sink_->emitted_events.back();
    EXPECT_EQ(last_event.event_type, domain::AuditEventType::LoginFailed);
    EXPECT_EQ(last_event.credential_identifier, email);
    EXPECT_EQ(last_event.failure_reason, "Invalid credentials");
}

} // namespace
} // namespace securecloud::auth::integration::test
