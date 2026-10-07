#include "auth/auth_config.hpp"
#include "auth/crypto/argon2id_hasher.hpp"
#include "auth/crypto/token_crypto.hpp"
#include "auth/db/migration_runner.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/refresh_token_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/repository/user_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/credential_verifier.hpp"
#include "auth/service/session_manager.hpp"
#include "auth/service/token_manager.hpp"
#include "gateway/http/auth/local_token_verifier.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <chrono>
#include <gmock/gmock.h>
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
using securecloud::gateway::http::LocalTokenVerifier;

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

TEST(AuthTokenPreflightTest, StrictPort5432Protection) {
    AuthConfig forbidden_cfg = make_test_auth_config();
    forbidden_cfg.db_port = 5432;

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), db::PortForbiddenException);
}

// ============================================================================
// 2. End-to-End Live Token Lifecycle Integration Test Fixture
// ============================================================================

class AuthTokenIntegrationTest : public ::testing::Test {
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
        refresh_token_repo_ = std::make_shared<repository::PostgresRefreshTokenRepository>(*pool_);
        hasher_ = std::make_shared<crypto::OpenSslArgon2idHasher>();
        token_signer_ = std::make_shared<crypto::Ed25519TokenSigner>("sc-auth-v1");

        // Perimeter Gateway verifier configured strictly with the public verification key
        gateway_verifier_ = LocalTokenVerifier::from_public_key_pem(token_signer_->get_public_key_pem());
    }

    // Factory to construct a fresh AuthServiceImpl instance wired to the same database pool
    std::unique_ptr<service::AuthServiceImpl> create_auth_service() {
        auto verifier = std::make_shared<service::CredentialVerifier>(user_repo_, hasher_);
        auto session_mgr = std::make_shared<service::SessionManager>(session_repo_, device_repo_,
                                                                     std::chrono::hours(24), audit_publisher_);
        auto token_mgr = std::make_shared<service::TokenManager>(token_signer_, refresh_token_repo_, session_repo_,
                                                                 device_repo_, audit_publisher_);
        return std::make_unique<service::AuthServiceImpl>(verifier, session_mgr, audit_publisher_, token_mgr);
    }

    AuthConfig config_;
    std::unique_ptr<db::PostgresConnectionPool> pool_;
    std::shared_ptr<TestAuditSink> audit_sink_;
    std::shared_ptr<service::AuditEventPublisher> audit_publisher_;
    std::shared_ptr<repository::PostgresUserRepository> user_repo_;
    std::shared_ptr<repository::PostgresDeviceRepository> device_repo_;
    std::shared_ptr<repository::PostgresSessionRepository> session_repo_;
    std::shared_ptr<repository::PostgresRefreshTokenRepository> refresh_token_repo_;
    std::shared_ptr<crypto::OpenSslArgon2idHasher> hasher_;
    std::shared_ptr<crypto::Ed25519TokenSigner> token_signer_;
    std::unique_ptr<LocalTokenVerifier> gateway_verifier_;
};

// ============================================================================
// 3. Test Cases: Complete Token Lifecycles & Security Controls
// ============================================================================

TEST_F(AuthTokenIntegrationTest, EndToEndTokenLifecycle_AuthenticateValidateRefresh) {
    std::string email = "token_user_" + Uuid::generate_v7().to_string() + "@securecloud.io";
    std::string raw_password = "SecurePassword123!";

    // 1. Seed User and Active Device
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

    auto auth_service = create_auth_service();

    // 2. Call Authenticate RPC
    grpc::ServerContext auth_ctx;
    v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(email);
    auth_req.set_password(raw_password);
    auth_req.set_device_id(device.device_id.to_string());
    v1::AuthenticateResponse auth_resp;

    auto auth_status = auth_service->Authenticate(&auth_ctx, &auth_req, &auth_resp);
    ASSERT_TRUE(auth_status.ok()) << "Authenticate failed: " << auth_status.error_message();

    EXPECT_FALSE(auth_resp.session_id().empty());
    EXPECT_FALSE(auth_resp.access_token().empty());
    EXPECT_FALSE(auth_resp.refresh_token().empty());
    EXPECT_EQ(auth_resp.user_id(), user.user_id.to_string());

    // 3. Gateway Perimeter Validation (Zero RPC / Zero DB)
    auto gateway_validation = gateway_verifier_->validate(auth_resp.access_token(), auth_resp.session_id());
    ASSERT_TRUE(gateway_validation.has_value());
    const auto& context = gateway_validation.value();
    EXPECT_EQ(context.user_id(), user.user_id.to_string());
    EXPECT_EQ(context.device_id(), device.device_id.to_string());
    EXPECT_EQ(context.session_id(), auth_resp.session_id());
    EXPECT_TRUE(context.has_scope("access"));

    // 4. Call RefreshSession RPC
    grpc::ServerContext ref_ctx;
    v1::RefreshSessionRequest ref_req;
    ref_req.set_refresh_token(auth_resp.refresh_token());
    ref_req.set_device_id(device.device_id.to_string());
    v1::RefreshSessionResponse ref_resp;

    auto ref_status = auth_service->RefreshSession(&ref_ctx, &ref_req, &ref_resp);
    ASSERT_TRUE(ref_status.ok()) << "RefreshSession failed: " << ref_status.error_message();

    EXPECT_EQ(ref_resp.session_id(), auth_resp.session_id());
    EXPECT_FALSE(ref_resp.access_token().empty());
    EXPECT_FALSE(ref_resp.new_refresh_token().empty());
    EXPECT_NE(ref_resp.access_token(), auth_resp.access_token());
    EXPECT_NE(ref_resp.new_refresh_token(), auth_resp.refresh_token());

    // 5. Gateway Perimeter Validation for Newly Rotated Access Token
    auto new_gateway_val = gateway_verifier_->validate(ref_resp.access_token(), ref_resp.session_id());
    ASSERT_TRUE(new_gateway_val.has_value());
    EXPECT_EQ(new_gateway_val.value().session_id(), auth_resp.session_id());
}

TEST_F(AuthTokenIntegrationTest, TokenDurabilityAcrossServiceRestart) {
    std::string email = "restart_user_" + Uuid::generate_v7().to_string() + "@securecloud.io";
    std::string raw_password = "SecurePassword123!";

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

    // 1. Authenticate on Instance 1
    auto service_instance_1 = create_auth_service();

    grpc::ServerContext auth_ctx;
    v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(email);
    auth_req.set_password(raw_password);
    auth_req.set_device_id(device.device_id.to_string());
    v1::AuthenticateResponse auth_resp;

    auto auth_status = service_instance_1->Authenticate(&auth_ctx, &auth_req, &auth_resp);
    ASSERT_TRUE(auth_status.ok());
    std::string refresh_token_secret = auth_resp.refresh_token();
    ASSERT_FALSE(refresh_token_secret.empty());

    // 2. Destroy Instance 1 (simulating process restart)
    service_instance_1.reset();

    // 3. Start Instance 2 and Refresh Token against persistent DB
    auto service_instance_2 = create_auth_service();

    grpc::ServerContext ref_ctx;
    v1::RefreshSessionRequest ref_req;
    ref_req.set_refresh_token(refresh_token_secret);
    ref_req.set_device_id(device.device_id.to_string());
    v1::RefreshSessionResponse ref_resp;

    auto ref_status = service_instance_2->RefreshSession(&ref_ctx, &ref_req, &ref_resp);
    ASSERT_TRUE(ref_status.ok()) << "Refresh on restarted instance failed: " << ref_status.error_message();

    EXPECT_EQ(ref_resp.session_id(), auth_resp.session_id());
    EXPECT_FALSE(ref_resp.access_token().empty());
    EXPECT_FALSE(ref_resp.new_refresh_token().empty());
}

TEST_F(AuthTokenIntegrationTest, TokenReuseAttackDetectionAgainstLiveDatabase) {
    std::string email = "reuse_user_" + Uuid::generate_v7().to_string() + "@securecloud.io";
    std::string raw_password = "SecurePassword123!";

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

    auto auth_service = create_auth_service();

    // 1. Authenticate to obtain initial Token A
    grpc::ServerContext auth_ctx;
    v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(email);
    auth_req.set_password(raw_password);
    auth_req.set_device_id(device.device_id.to_string());
    v1::AuthenticateResponse auth_resp;
    ASSERT_TRUE(auth_service->Authenticate(&auth_ctx, &auth_req, &auth_resp).ok());

    std::string token_a = auth_resp.refresh_token();
    auto session_id = *Uuid::from_string(auth_resp.session_id());

    // 2. Legitimate Client Rotates: Token A -> Token B
    grpc::ServerContext leg_ctx;
    v1::RefreshSessionRequest leg_req;
    leg_req.set_refresh_token(token_a);
    leg_req.set_device_id(device.device_id.to_string());
    v1::RefreshSessionResponse leg_resp;
    ASSERT_TRUE(auth_service->RefreshSession(&leg_ctx, &leg_req, &leg_resp).ok());

    std::string token_b = leg_resp.new_refresh_token();

    // Sleep past the 5-second concurrency grace window to simulate adversarial replay
    std::this_thread::sleep_for(std::chrono::milliseconds(5500));

    // 3. Attacker Replays Token A (Token Reuse Protocol Triggered)
    grpc::ServerContext atk_ctx;
    v1::RefreshSessionRequest atk_req;
    atk_req.set_refresh_token(token_a);
    atk_req.set_device_id(device.device_id.to_string());
    v1::RefreshSessionResponse atk_resp;

    auto atk_status = auth_service->RefreshSession(&atk_ctx, &atk_req, &atk_resp);
    EXPECT_EQ(atk_status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_THAT(atk_status.error_message(), ::testing::HasSubstr("Refresh token reuse detected; session revoked"));

    // 4. Assert Underlying Session in PostgreSQL is Revoked
    auto session_opt = session_repo_->find_by_id(session_id);
    ASSERT_TRUE(session_opt.has_value());
    EXPECT_EQ(session_opt->session_status, SessionStatus::Revoked);

    // 5. Subsequent Refresh with Token B MUST fail because entire session is revoked
    grpc::ServerContext post_ctx;
    v1::RefreshSessionRequest post_req;
    post_req.set_refresh_token(token_b);
    post_req.set_device_id(device.device_id.to_string());
    v1::RefreshSessionResponse post_resp;

    auto post_status = auth_service->RefreshSession(&post_ctx, &post_req, &post_resp);
    EXPECT_EQ(post_status.error_code(), grpc::StatusCode::UNAUTHENTICATED);

    // 6. Assert Security Audit Event Captured Compromise
    bool reuse_event_found = false;
    for (const auto& ev : audit_sink_->emitted_events) {
        if (ev.event_type == domain::AuditEventType::TokenReuseDetected) {
            reuse_event_found = true;
            EXPECT_EQ(ev.session_id, session_id);
            EXPECT_EQ(ev.device_id, device.device_id);
        }
    }
    EXPECT_TRUE(reuse_event_found) << "TokenReuseDetected audit event was not emitted!";
}

} // namespace
} // namespace securecloud::auth::integration::test
