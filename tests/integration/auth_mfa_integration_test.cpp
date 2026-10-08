#include "auth/auth_config.hpp"
#include "auth/crypto/argon2id_hasher.hpp"
#include "auth/crypto/base32.hpp"
#include "auth/crypto/mfa_secret_protector.hpp"
#include "auth/crypto/token_crypto.hpp"
#include "auth/crypto/totp_engine.hpp"
#include "auth/db/migration_runner.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/mfa_repository.hpp"
#include "auth/repository/refresh_token_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/repository/user_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/credential_verifier.hpp"
#include "auth/service/mfa_authenticator_interface.hpp"
#include "auth/service/mfa_manager.hpp"
#include "auth/service/session_manager.hpp"
#include "auth/service/token_manager.hpp"
#include "gateway/http/auth/gateway_security_policy.hpp"
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
using domain::DeviceEntity;
using domain::DeviceStatus;
using domain::SessionEntity;
using domain::SessionStatus;
using domain::UserEntity;
using domain::Uuid;
using securecloud::gateway::http::GatewaySecurityPolicy;
using securecloud::gateway::http::LocalTokenVerifier;
using securecloud::gateway::http::RouteAccess;

AuthConfig make_test_auth_config() {
    AuthConfig config;
    config.db_host = "127.0.0.1";
    config.db_port = 5433; // Strictly container port 5433 (PostgreSQL 17)
    config.db_name = "securecloud_auth";
    config.db_user = "auth_user";
    config.db_password = common::configuration::SecretString("auth_dev_db_secret");
    return config;
}

// Test sink capturing domain audit events during live test runs
class TestAuditSink final : public service::IAuditEventSink {
  public:
    void emit(const domain::AuditEvent& event, std::string_view /*json_payload*/) override {
        emitted_events.push_back(event);
    }
    std::vector<domain::AuditEvent> emitted_events;
};

// ============================================================================
// 1. Strict Port 5432 Protection Preflight Test
// ============================================================================

TEST(AuthMfaPreflightTest, StrictPort5432Protection) {
    AuthConfig forbidden_cfg = make_test_auth_config();
    forbidden_cfg.db_port = 5432;

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), db::PortForbiddenException);
}

// ============================================================================
// 2. Live MFA End-to-End Test Fixture (Containerized PostgreSQL 17)
// ============================================================================

class AuthMfaIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        config_ = make_test_auth_config();

        // Invariant: NEVER touch host PostgreSQL 14 on port 5432
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

        // Apply schema migrations
        db::MigrationRunner runner(*pool_);
        runner.run_migrations();

        audit_sink_ = std::make_shared<TestAuditSink>();
        audit_publisher_ = std::make_shared<service::AuditEventPublisher>(audit_sink_);

        user_repo_ = std::make_shared<repository::PostgresUserRepository>(*pool_);
        device_repo_ = std::make_shared<repository::PostgresDeviceRepository>(*pool_);
        session_repo_ = std::make_shared<repository::PostgresSessionRepository>(*pool_);
        refresh_token_repo_ = std::make_shared<repository::PostgresRefreshTokenRepository>(*pool_);
        mfa_repo_ = std::make_shared<repository::PostgresMfaRepository>(*pool_);

        hasher_ = std::make_shared<crypto::OpenSslArgon2idHasher>();
        token_signer_ = std::make_shared<crypto::Ed25519TokenSigner>("sc-auth-v1");

        // Perimeter Gateway verifier configured strictly with the public verification key
        gateway_verifier_ = LocalTokenVerifier::from_public_key_pem(token_signer_->get_public_key_pem());
        gateway_policy_ = std::make_unique<GatewaySecurityPolicy>(GatewaySecurityPolicy::create_default());

        // MFA cryptographic infrastructure
        test_kek_ = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        secret_protector_ = std::make_shared<crypto::MfaSecretProtector>(test_kek_);
        totp_engine_ = std::make_shared<crypto::TotpEngine>();
        authenticator_ = std::make_shared<service::TotpAuthenticator>(totp_engine_, secret_protector_);

        mfa_manager_ = std::make_shared<service::MfaManager>(
            mfa_repo_, session_repo_, user_repo_, authenticator_, totp_engine_, secret_protector_, audit_publisher_);
    }

    std::unique_ptr<service::AuthServiceImpl> create_auth_service(
        std::shared_ptr<service::IMfaManager> custom_mfa_mgr = nullptr) {
        auto verifier = std::make_shared<service::CredentialVerifier>(user_repo_, hasher_);
        auto session_mgr = std::make_shared<service::SessionManager>(session_repo_, device_repo_,
                                                                     std::chrono::hours(24), audit_publisher_);
        auto token_mgr = std::make_shared<service::TokenManager>(token_signer_, refresh_token_repo_, session_repo_,
                                                                 device_repo_, audit_publisher_);
        auto mgr = custom_mfa_mgr ? custom_mfa_mgr : mfa_manager_;
        return std::make_unique<service::AuthServiceImpl>(verifier, session_mgr, audit_publisher_, token_mgr, mgr);
    }

    struct SeededIdentity {
        UserEntity user;
        DeviceEntity device;
        std::string raw_password;
    };

    SeededIdentity seed_user_and_device() {
        std::string email = "mfa_user_" + Uuid::generate_v7().to_string() + "@securecloud.io";
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

        return {std::move(user), std::move(device), std::move(raw_password)};
    }

    AuthConfig config_;
    std::string test_kek_;
    std::unique_ptr<db::PostgresConnectionPool> pool_;
    std::shared_ptr<TestAuditSink> audit_sink_;
    std::shared_ptr<service::AuditEventPublisher> audit_publisher_;
    std::shared_ptr<repository::PostgresUserRepository> user_repo_;
    std::shared_ptr<repository::PostgresDeviceRepository> device_repo_;
    std::shared_ptr<repository::PostgresSessionRepository> session_repo_;
    std::shared_ptr<repository::PostgresRefreshTokenRepository> refresh_token_repo_;
    std::shared_ptr<repository::PostgresMfaRepository> mfa_repo_;
    std::shared_ptr<crypto::OpenSslArgon2idHasher> hasher_;
    std::shared_ptr<crypto::Ed25519TokenSigner> token_signer_;
    std::unique_ptr<LocalTokenVerifier> gateway_verifier_;
    std::unique_ptr<GatewaySecurityPolicy> gateway_policy_;
    std::shared_ptr<crypto::MfaSecretProtector> secret_protector_;
    std::shared_ptr<crypto::TotpEngine> totp_engine_;
    std::shared_ptr<service::TotpAuthenticator> authenticator_;
    std::shared_ptr<service::MfaManager> mfa_manager_;
};

// ============================================================================
// 3. Test Cases
// ============================================================================

TEST_F(AuthMfaIntegrationTest, FullEnrollmentAndChallengeE2E) {
    auto identity = seed_user_and_device();
    auto auth_service = create_auth_service();

    // 1. Initiate MFA Enrollment
    grpc::ServerContext init_ctx;
    v1::InitiateMfaEnrollmentRequest init_req;
    init_req.set_user_id(identity.user.user_id.to_string());
    init_req.set_issuer("SecureCloud");
    init_req.set_account_name(identity.user.credential_identifier);
    v1::InitiateMfaEnrollmentResponse init_resp;

    auto init_status = auth_service->InitiateMfaEnrollment(&init_ctx, &init_req, &init_resp);
    ASSERT_TRUE(init_status.ok()) << "InitiateMfaEnrollment failed: " << init_status.error_message();
    EXPECT_FALSE(init_resp.secret().empty());
    EXPECT_THAT(init_resp.otpauth_uri(), ::testing::HasSubstr("otpauth://totp/"));

    // 2. Generate valid TOTP code from returned Base32 secret
    auto raw_secret = crypto::Base32::decode(init_resp.secret());
    ASSERT_TRUE(raw_secret.has_value());
    auto now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto enrollment_code = totp_engine_->compute_code(*raw_secret, now_sec);

    // 3. Confirm MFA Enrollment
    grpc::ServerContext confirm_ctx;
    v1::ConfirmMfaEnrollmentRequest confirm_req;
    confirm_req.set_user_id(identity.user.user_id.to_string());
    confirm_req.set_code(enrollment_code);
    v1::ConfirmMfaEnrollmentResponse confirm_resp;

    auto confirm_status = auth_service->ConfirmMfaEnrollment(&confirm_ctx, &confirm_req, &confirm_resp);
    ASSERT_TRUE(confirm_status.ok()) << "ConfirmMfaEnrollment failed: " << confirm_status.error_message();
    EXPECT_TRUE(confirm_resp.success());
    EXPECT_EQ(confirm_resp.recovery_codes_size(), 8);

    // 4. Primary login via Authenticate -> Returns mfa_required = true & mfa_challenge_id
    grpc::ServerContext auth_ctx;
    v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(identity.user.credential_identifier);
    auth_req.set_password(identity.raw_password);
    auth_req.set_device_id(identity.device.device_id.to_string());
    v1::AuthenticateResponse auth_resp;

    auto auth_status = auth_service->Authenticate(&auth_ctx, &auth_req, &auth_resp);
    ASSERT_TRUE(auth_status.ok()) << "Authenticate failed: " << auth_status.error_message();
    EXPECT_TRUE(auth_resp.mfa_required());
    EXPECT_FALSE(auth_resp.mfa_challenge_id().empty());
    EXPECT_TRUE(auth_resp.access_token().empty()) << "Access token MUST be suppressed when MFA is required!";
    EXPECT_TRUE(auth_resp.refresh_token().empty()) << "Refresh token MUST be suppressed when MFA is required!";

    // 5. Verify MFA Challenge using live TOTP code
    now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto challenge_code = totp_engine_->compute_code(*raw_secret, now_sec);

    grpc::ServerContext challenge_ctx;
    v1::VerifyMfaChallengeRequest challenge_req;
    challenge_req.set_challenge_id(auth_resp.mfa_challenge_id());
    challenge_req.set_code(challenge_code);
    v1::VerifyMfaChallengeResponse challenge_resp;

    auto challenge_status = auth_service->VerifyMfaChallenge(&challenge_ctx, &challenge_req, &challenge_resp);
    ASSERT_TRUE(challenge_status.ok()) << "VerifyMfaChallenge failed: " << challenge_status.error_message();
    EXPECT_FALSE(challenge_resp.access_token().empty());
    EXPECT_FALSE(challenge_resp.refresh_token().empty());
    EXPECT_EQ(challenge_resp.authentication_level(), v1::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    // 6. Gateway Perimeter Verification
    auto gateway_validation = gateway_verifier_->validate(challenge_resp.access_token(), challenge_resp.session_id());
    ASSERT_TRUE(gateway_validation.has_value());
    const auto& context = gateway_validation.value();
    EXPECT_EQ(context.user_id(), identity.user.user_id.to_string());
    EXPECT_EQ(context.device_id(), identity.device.device_id.to_string());
    EXPECT_EQ(context.session_id(), challenge_resp.session_id());
    EXPECT_EQ(context.authentication_level(), v1::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    EXPECT_TRUE(context.is_mfa_verified());

    // 7. Verify Gateway Security Policy recognizes MFA_VERIFIED for sensitive route
    auto rule = gateway_policy_->evaluate("POST", "/api/v1/auth/mfa/disable");
    EXPECT_EQ(rule.access, RouteAccess::Sensitive);
    EXPECT_TRUE(rule.requires_mfa());
    EXPECT_TRUE(rule.satisfies(context));
}

TEST_F(AuthMfaIntegrationTest, ThreeAttemptLockoutProtection) {
    auto identity = seed_user_and_device();
    auto auth_service = create_auth_service();

    // 1. Enroll MFA
    grpc::ServerContext init_ctx;
    v1::InitiateMfaEnrollmentRequest init_req;
    init_req.set_user_id(identity.user.user_id.to_string());
    v1::InitiateMfaEnrollmentResponse init_resp;
    ASSERT_TRUE(auth_service->InitiateMfaEnrollment(&init_ctx, &init_req, &init_resp).ok());

    auto raw_secret = crypto::Base32::decode(init_resp.secret());
    ASSERT_TRUE(raw_secret.has_value());
    auto now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto enrollment_code = totp_engine_->compute_code(*raw_secret, now_sec);

    grpc::ServerContext confirm_ctx;
    v1::ConfirmMfaEnrollmentRequest confirm_req;
    confirm_req.set_user_id(identity.user.user_id.to_string());
    confirm_req.set_code(enrollment_code);
    v1::ConfirmMfaEnrollmentResponse confirm_resp;
    ASSERT_TRUE(auth_service->ConfirmMfaEnrollment(&confirm_ctx, &confirm_req, &confirm_resp).ok());

    // 2. Authenticate -> Get challenge_id
    grpc::ServerContext auth_ctx;
    v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(identity.user.credential_identifier);
    auth_req.set_password(identity.raw_password);
    auth_req.set_device_id(identity.device.device_id.to_string());
    v1::AuthenticateResponse auth_resp;
    ASSERT_TRUE(auth_service->Authenticate(&auth_ctx, &auth_req, &auth_resp).ok());
    ASSERT_TRUE(auth_resp.mfa_required());

    // 3. Attempt 1: Wrong Code -> UNAUTHENTICATED
    {
        grpc::ServerContext ctx;
        v1::VerifyMfaChallengeRequest req;
        req.set_challenge_id(auth_resp.mfa_challenge_id());
        req.set_code("000000");
        v1::VerifyMfaChallengeResponse resp;
        auto status = auth_service->VerifyMfaChallenge(&ctx, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
    }

    // 4. Attempt 2: Wrong Code -> UNAUTHENTICATED
    {
        grpc::ServerContext ctx;
        v1::VerifyMfaChallengeRequest req;
        req.set_challenge_id(auth_resp.mfa_challenge_id());
        req.set_code("111111");
        v1::VerifyMfaChallengeResponse resp;
        auto status = auth_service->VerifyMfaChallenge(&ctx, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
    }

    // 5. Attempt 3: Wrong Code -> PERMISSION_DENIED (Challenge Locked)
    {
        grpc::ServerContext ctx;
        v1::VerifyMfaChallengeRequest req;
        req.set_challenge_id(auth_resp.mfa_challenge_id());
        req.set_code("222222");
        v1::VerifyMfaChallengeResponse resp;
        auto status = auth_service->VerifyMfaChallenge(&ctx, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    }

    // 6. Attempt 4: Even with correct TOTP code -> PERMISSION_DENIED (Locked out)
    {
        now_sec = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        auto valid_code = totp_engine_->compute_code(*raw_secret, now_sec);

        grpc::ServerContext ctx;
        v1::VerifyMfaChallengeRequest req;
        req.set_challenge_id(auth_resp.mfa_challenge_id());
        req.set_code(valid_code);
        v1::VerifyMfaChallengeResponse resp;
        auto status = auth_service->VerifyMfaChallenge(&ctx, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    }
}

TEST_F(AuthMfaIntegrationTest, SingleUseRecoveryCodeFallback) {
    auto identity = seed_user_and_device();
    auto auth_service = create_auth_service();

    // 1. Enroll MFA and collect recovery codes
    grpc::ServerContext init_ctx;
    v1::InitiateMfaEnrollmentRequest init_req;
    init_req.set_user_id(identity.user.user_id.to_string());
    v1::InitiateMfaEnrollmentResponse init_resp;
    ASSERT_TRUE(auth_service->InitiateMfaEnrollment(&init_ctx, &init_req, &init_resp).ok());

    auto raw_secret = crypto::Base32::decode(init_resp.secret());
    ASSERT_TRUE(raw_secret.has_value());
    auto now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto enrollment_code = totp_engine_->compute_code(*raw_secret, now_sec);

    grpc::ServerContext confirm_ctx;
    v1::ConfirmMfaEnrollmentRequest confirm_req;
    confirm_req.set_user_id(identity.user.user_id.to_string());
    confirm_req.set_code(enrollment_code);
    v1::ConfirmMfaEnrollmentResponse confirm_resp;
    ASSERT_TRUE(auth_service->ConfirmMfaEnrollment(&confirm_ctx, &confirm_req, &confirm_resp).ok());
    ASSERT_GT(confirm_resp.recovery_codes_size(), 0);

    std::string test_recovery_code = confirm_resp.recovery_codes(0);

    // 2. Authenticate -> Get challenge_id
    grpc::ServerContext auth_ctx;
    v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(identity.user.credential_identifier);
    auth_req.set_password(identity.raw_password);
    auth_req.set_device_id(identity.device.device_id.to_string());
    v1::AuthenticateResponse auth_resp;
    ASSERT_TRUE(auth_service->Authenticate(&auth_ctx, &auth_req, &auth_resp).ok());

    // 3. Verify challenge using single-use recovery code
    grpc::ServerContext challenge_ctx;
    v1::VerifyMfaChallengeRequest challenge_req;
    challenge_req.set_challenge_id(auth_resp.mfa_challenge_id());
    challenge_req.set_code(test_recovery_code);
    v1::VerifyMfaChallengeResponse challenge_resp;

    auto challenge_status = auth_service->VerifyMfaChallenge(&challenge_ctx, &challenge_req, &challenge_resp);
    ASSERT_TRUE(challenge_status.ok()) << "Recovery code verification failed: " << challenge_status.error_message();
    EXPECT_FALSE(challenge_resp.access_token().empty());
    EXPECT_EQ(challenge_resp.authentication_level(), v1::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    // 4. Authenticate again for another session -> Get new challenge_id
    grpc::ServerContext auth_ctx2;
    v1::AuthenticateResponse auth_resp2;
    ASSERT_TRUE(auth_service->Authenticate(&auth_ctx2, &auth_req, &auth_resp2).ok());

    // 5. Try reusing the exact same recovery code -> Rejected (already consumed)
    grpc::ServerContext challenge_ctx2;
    v1::VerifyMfaChallengeRequest challenge_req2;
    challenge_req2.set_challenge_id(auth_resp2.mfa_challenge_id());
    challenge_req2.set_code(test_recovery_code);
    v1::VerifyMfaChallengeResponse challenge_resp2;

    auto reuse_status = auth_service->VerifyMfaChallenge(&challenge_ctx2, &challenge_req2, &challenge_resp2);
    EXPECT_EQ(reuse_status.error_code(), grpc::StatusCode::UNAUTHENTICATED)
        << "Single-use recovery code must not be reusable!";
}

TEST_F(AuthMfaIntegrationTest, DisableMfaFlow) {
    auto identity = seed_user_and_device();
    auto auth_service = create_auth_service();

    // 1. Enroll MFA
    grpc::ServerContext init_ctx;
    v1::InitiateMfaEnrollmentRequest init_req;
    init_req.set_user_id(identity.user.user_id.to_string());
    v1::InitiateMfaEnrollmentResponse init_resp;
    ASSERT_TRUE(auth_service->InitiateMfaEnrollment(&init_ctx, &init_req, &init_resp).ok());

    auto raw_secret = crypto::Base32::decode(init_resp.secret());
    ASSERT_TRUE(raw_secret.has_value());
    auto now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto enrollment_code = totp_engine_->compute_code(*raw_secret, now_sec);

    grpc::ServerContext confirm_ctx;
    v1::ConfirmMfaEnrollmentRequest confirm_req;
    confirm_req.set_user_id(identity.user.user_id.to_string());
    confirm_req.set_code(enrollment_code);
    v1::ConfirmMfaEnrollmentResponse confirm_resp;
    ASSERT_TRUE(auth_service->ConfirmMfaEnrollment(&confirm_ctx, &confirm_req, &confirm_resp).ok());

    // 2. Disable MFA with valid code (caller marked as MFA_VERIFIED)
    auth_service->set_caller_auth_level_for_testing(v1::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto disable_code = totp_engine_->compute_code(*raw_secret, now_sec);

    grpc::ServerContext disable_ctx;
    v1::DisableMfaRequest disable_req;
    disable_req.set_user_id(identity.user.user_id.to_string());
    disable_req.set_code(disable_code);
    v1::DisableMfaResponse disable_resp;

    auto disable_status = auth_service->DisableMfa(&disable_ctx, &disable_req, &disable_resp);
    ASSERT_TRUE(disable_status.ok()) << "DisableMfa failed: " << disable_status.error_message();
    EXPECT_TRUE(disable_resp.success());

    // 3. Subsequent Authenticate should succeed directly without MFA required
    auth_service->set_caller_auth_level_for_testing(std::nullopt);
    grpc::ServerContext auth_ctx;
    v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(identity.user.credential_identifier);
    auth_req.set_password(identity.raw_password);
    auth_req.set_device_id(identity.device.device_id.to_string());
    v1::AuthenticateResponse auth_resp;

    auto auth_status = auth_service->Authenticate(&auth_ctx, &auth_req, &auth_resp);
    ASSERT_TRUE(auth_status.ok()) << "Authenticate after DisableMfa failed: " << auth_status.error_message();
    EXPECT_FALSE(auth_resp.mfa_required());
    EXPECT_TRUE(auth_resp.mfa_challenge_id().empty());
    EXPECT_FALSE(auth_resp.access_token().empty());
    EXPECT_FALSE(auth_resp.refresh_token().empty());
}

TEST_F(AuthMfaIntegrationTest, AntiReplayWindowEnforcement) {
    auto identity = seed_user_and_device();
    auto auth_service = create_auth_service();

    // 1. Enroll MFA
    grpc::ServerContext init_ctx;
    v1::InitiateMfaEnrollmentRequest init_req;
    init_req.set_user_id(identity.user.user_id.to_string());
    v1::InitiateMfaEnrollmentResponse init_resp;
    ASSERT_TRUE(auth_service->InitiateMfaEnrollment(&init_ctx, &init_req, &init_resp).ok());

    auto raw_secret = crypto::Base32::decode(init_resp.secret());
    ASSERT_TRUE(raw_secret.has_value());
    auto now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto enrollment_code = totp_engine_->compute_code(*raw_secret, now_sec);

    grpc::ServerContext confirm_ctx;
    v1::ConfirmMfaEnrollmentRequest confirm_req;
    confirm_req.set_user_id(identity.user.user_id.to_string());
    confirm_req.set_code(enrollment_code);
    v1::ConfirmMfaEnrollmentResponse confirm_resp;
    ASSERT_TRUE(auth_service->ConfirmMfaEnrollment(&confirm_ctx, &confirm_req, &confirm_resp).ok());

    // 2. First login -> Get challenge 1
    grpc::ServerContext auth_ctx1;
    v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(identity.user.credential_identifier);
    auth_req.set_password(identity.raw_password);
    auth_req.set_device_id(identity.device.device_id.to_string());
    v1::AuthenticateResponse auth_resp1;
    ASSERT_TRUE(auth_service->Authenticate(&auth_ctx1, &auth_req, &auth_resp1).ok());
    ASSERT_TRUE(auth_resp1.mfa_required());

    now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto current_code = totp_engine_->compute_code(*raw_secret, now_sec);

    // 3. Verify challenge 1 with current code -> Success
    grpc::ServerContext ch1_ctx;
    v1::VerifyMfaChallengeRequest ch1_req;
    ch1_req.set_challenge_id(auth_resp1.mfa_challenge_id());
    ch1_req.set_code(current_code);
    v1::VerifyMfaChallengeResponse ch1_resp;
    ASSERT_TRUE(auth_service->VerifyMfaChallenge(&ch1_ctx, &ch1_req, &ch1_resp).ok());

    // 4. Second login in the same 30-second window -> Get challenge 2
    grpc::ServerContext auth_ctx2;
    v1::AuthenticateResponse auth_resp2;
    ASSERT_TRUE(auth_service->Authenticate(&auth_ctx2, &auth_req, &auth_resp2).ok());
    ASSERT_TRUE(auth_resp2.mfa_required());

    // 5. Try reusing the exact same TOTP code for challenge 2 -> Rejected by anti-replay
    grpc::ServerContext ch2_ctx;
    v1::VerifyMfaChallengeRequest ch2_req;
    ch2_req.set_challenge_id(auth_resp2.mfa_challenge_id());
    ch2_req.set_code(current_code);
    v1::VerifyMfaChallengeResponse ch2_resp;
    auto replay_status = auth_service->VerifyMfaChallenge(&ch2_ctx, &ch2_req, &ch2_resp);
    EXPECT_EQ(replay_status.error_code(), grpc::StatusCode::UNAUTHENTICATED)
        << "Reusing identical TOTP code within the same time-step window must be rejected!";
}

TEST_F(AuthMfaIntegrationTest, DurabilityAcrossServiceRestart) {
    auto identity = seed_user_and_device();
    std::string secret_str;
    std::string challenge_id;

    // 1. Phase 1: Service instance 1 creates enrollment and authenticates
    {
        auto auth_service1 = create_auth_service();

        grpc::ServerContext init_ctx;
        v1::InitiateMfaEnrollmentRequest init_req;
        init_req.set_user_id(identity.user.user_id.to_string());
        v1::InitiateMfaEnrollmentResponse init_resp;
        ASSERT_TRUE(auth_service1->InitiateMfaEnrollment(&init_ctx, &init_req, &init_resp).ok());
        secret_str = init_resp.secret();

        auto raw_secret = crypto::Base32::decode(secret_str);
        ASSERT_TRUE(raw_secret.has_value());
        auto now_sec = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        auto enrollment_code = totp_engine_->compute_code(*raw_secret, now_sec);

        grpc::ServerContext confirm_ctx;
        v1::ConfirmMfaEnrollmentRequest confirm_req;
        confirm_req.set_user_id(identity.user.user_id.to_string());
        confirm_req.set_code(enrollment_code);
        v1::ConfirmMfaEnrollmentResponse confirm_resp;
        ASSERT_TRUE(auth_service1->ConfirmMfaEnrollment(&confirm_ctx, &confirm_req, &confirm_resp).ok());

        // Login -> generates challenge in PostgreSQL
        grpc::ServerContext auth_ctx;
        v1::AuthenticateRequest auth_req;
        auth_req.set_credential_identifier(identity.user.credential_identifier);
        auth_req.set_password(identity.raw_password);
        auth_req.set_device_id(identity.device.device_id.to_string());
        v1::AuthenticateResponse auth_resp;
        ASSERT_TRUE(auth_service1->Authenticate(&auth_ctx, &auth_req, &auth_resp).ok());
        challenge_id = auth_resp.mfa_challenge_id();
        ASSERT_FALSE(challenge_id.empty());
    } // Service 1 destroyed completely

    // 2. Phase 2: Create completely fresh Service instance 2 connected to same PostgreSQL
    {
        auto new_mfa_manager = std::make_shared<service::MfaManager>(
            mfa_repo_, session_repo_, user_repo_, authenticator_, totp_engine_, secret_protector_, audit_publisher_);
        auto auth_service2 = create_auth_service(new_mfa_manager);

        auto raw_secret = crypto::Base32::decode(secret_str);
        ASSERT_TRUE(raw_secret.has_value());
        auto now_sec = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        auto challenge_code = totp_engine_->compute_code(*raw_secret, now_sec);

        grpc::ServerContext challenge_ctx;
        v1::VerifyMfaChallengeRequest challenge_req;
        challenge_req.set_challenge_id(challenge_id);
        challenge_req.set_code(challenge_code);
        v1::VerifyMfaChallengeResponse challenge_resp;

        // Challenge verification against persisted challenge entity
        auto challenge_status = auth_service2->VerifyMfaChallenge(&challenge_ctx, &challenge_req, &challenge_resp);
        ASSERT_TRUE(challenge_status.ok())
            << "Challenge verification across service restart failed: " << challenge_status.error_message();
        EXPECT_FALSE(challenge_resp.access_token().empty());
        EXPECT_EQ(challenge_resp.authentication_level(), v1::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    }
}

} // namespace
} // namespace securecloud::auth::integration::test
