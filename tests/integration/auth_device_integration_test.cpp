#include "auth/auth_config.hpp"
#include "auth/crypto/argon2id_hasher.hpp"
#include "auth/crypto/token_crypto.hpp"
#include "auth/db/migration_runner.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_public_key_repository.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/refresh_token_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/repository/user_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/credential_verifier.hpp"
#include "auth/service/device_manager.hpp"
#include "auth/service/session_manager.hpp"
#include "auth/service/token_manager.hpp"
#include "gateway/http/auth/gateway_security_policy.hpp"
#include "gateway/http/auth/local_token_verifier.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <chrono>
#include <future>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <openssl/evp.h>
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
using gateway::http::GatewaySecurityPolicy;
using gateway::http::LocalTokenVerifier;
using gateway::http::RouteAccess;

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
// Cryptographic Fixture Helpers (32-byte Ed25519 & X25519 Keys)
// ============================================================================

struct CryptoBundle {
    std::vector<uint8_t> identity_pub;
    std::vector<uint8_t> signed_prekey;
    std::vector<uint8_t> signature;
    std::vector<std::vector<uint8_t>> one_time_prekeys;
};

CryptoBundle generate_valid_crypto_bundle(std::size_t otk_count = 3) {
    CryptoBundle bundle;

    // 1. Ed25519 Identity Key
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY* id_pkey = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &id_pkey);
    EVP_PKEY_CTX_free(ctx);

    size_t id_len = 32;
    bundle.identity_pub.resize(id_len);
    EVP_PKEY_get_raw_public_key(id_pkey, bundle.identity_pub.data(), &id_len);

    // 2. X25519 Signed Prekey
    EVP_PKEY_CTX* spk_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* spk_pkey = nullptr;
    EVP_PKEY_keygen_init(spk_ctx);
    EVP_PKEY_keygen(spk_ctx, &spk_pkey);
    EVP_PKEY_CTX_free(spk_ctx);

    size_t spk_len = 32;
    bundle.signed_prekey.resize(spk_len);
    EVP_PKEY_get_raw_public_key(spk_pkey, bundle.signed_prekey.data(), &spk_len);
    EVP_PKEY_free(spk_pkey);

    // 3. Signature over signed prekey using Ed25519 identity key
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, id_pkey);
    size_t sig_len = 64;
    bundle.signature.resize(sig_len);
    EVP_DigestSign(md_ctx, bundle.signature.data(), &sig_len, bundle.signed_prekey.data(), bundle.signed_prekey.size());
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(id_pkey);

    // 4. One-time prekeys
    for (std::size_t i = 0; i < otk_count; ++i) {
        EVP_PKEY_CTX* otk_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY* otk_pkey = nullptr;
        EVP_PKEY_keygen_init(otk_ctx);
        EVP_PKEY_keygen(otk_ctx, &otk_pkey);
        EVP_PKEY_CTX_free(otk_ctx);

        size_t otk_len = 32;
        std::vector<uint8_t> otk(otk_len);
        EVP_PKEY_get_raw_public_key(otk_pkey, otk.data(), &otk_len);
        EVP_PKEY_free(otk_pkey);

        bundle.one_time_prekeys.push_back(std::move(otk));
    }

    return bundle;
}

// ============================================================================
// 1. Strict Port 5432 Protection Preflight Test
// ============================================================================

TEST(AuthDevicePreflightTest, StrictPort5432Protection) {
    AuthConfig forbidden_cfg = make_test_auth_config();
    forbidden_cfg.db_port = 5432;

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), db::PortForbiddenException);
}

// ============================================================================
// 2. Live Device Integration Test Fixture (PostgreSQL 17 on Port 5433)
// ============================================================================

class AuthDeviceIntegrationTest : public ::testing::Test {
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
        public_key_repo_ = std::make_shared<repository::PostgresDevicePublicKeyRepository>(*pool_);
        session_repo_ = std::make_shared<repository::PostgresSessionRepository>(*pool_);
        refresh_token_repo_ = std::make_shared<repository::PostgresRefreshTokenRepository>(*pool_);

        hasher_ = std::make_shared<crypto::OpenSslArgon2idHasher>();
        token_signer_ = std::make_shared<crypto::Ed25519TokenSigner>("sc-auth-v1");

        session_mgr_ = std::make_shared<service::SessionManager>(session_repo_, device_repo_, std::chrono::hours(24),
                                                                 audit_publisher_);
        token_mgr_ = std::make_shared<service::TokenManager>(token_signer_, refresh_token_repo_, session_repo_,
                                                             device_repo_, audit_publisher_);
        device_mgr_ =
            std::make_shared<service::DeviceManager>(device_repo_, public_key_repo_, session_mgr_, audit_publisher_);
    }

    std::unique_ptr<service::AuthServiceImpl> create_auth_service() {
        auto verifier = std::make_shared<service::CredentialVerifier>(user_repo_, hasher_);
        return std::make_unique<service::AuthServiceImpl>(verifier, session_mgr_, audit_publisher_, token_mgr_, nullptr,
                                                          device_mgr_);
    }

    struct SeededUser {
        UserEntity user;
        std::string raw_password;
    };

    SeededUser seed_user() {
        std::string email = "dev_user_" + Uuid::generate_v7().to_string() + "@securecloud.io";
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

        return {std::move(user), std::move(raw_password)};
    }

    AuthConfig config_;
    std::unique_ptr<db::PostgresConnectionPool> pool_;
    std::shared_ptr<TestAuditSink> audit_sink_;
    std::shared_ptr<service::AuditEventPublisher> audit_publisher_;
    std::shared_ptr<repository::PostgresUserRepository> user_repo_;
    std::shared_ptr<repository::PostgresDeviceRepository> device_repo_;
    std::shared_ptr<repository::PostgresDevicePublicKeyRepository> public_key_repo_;
    std::shared_ptr<repository::PostgresSessionRepository> session_repo_;
    std::shared_ptr<repository::PostgresRefreshTokenRepository> refresh_token_repo_;
    std::shared_ptr<crypto::OpenSslArgon2idHasher> hasher_;
    std::shared_ptr<crypto::Ed25519TokenSigner> token_signer_;
    std::shared_ptr<service::SessionManager> session_mgr_;
    std::shared_ptr<service::TokenManager> token_mgr_;
    std::shared_ptr<service::DeviceManager> device_mgr_;
};

// ============================================================================
// Test 2: Registration Rejects Ordinary JWT / PrimaryOnly Direct Activation
// ============================================================================

TEST_F(AuthDeviceIntegrationTest, RegistrationRejectsOrdinaryJwt) {
    auto seeded = seed_user();
    auto auth_service = create_auth_service();

    // Simulate caller with ordinary PRIMARY assurance (ordinary access token)
    auth_service->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    auto crypto = generate_valid_crypto_bundle();

    securecloud::auth::v1::RegisterDeviceRequest reg_req;
    reg_req.set_user_id(seeded.user.user_id.to_string());
    reg_req.set_identity_key(crypto.identity_pub.data(), crypto.identity_pub.size());
    reg_req.set_signed_prekey(crypto.signed_prekey.data(), crypto.signed_prekey.size());
    reg_req.set_signed_prekey_signature(crypto.signature.data(), crypto.signature.size());
    for (const auto& otk : crypto.one_time_prekeys) {
        reg_req.add_one_time_prekeys(otk.data(), otk.size());
    }

    securecloud::auth::v1::RegisterDeviceResponse reg_resp;
    ::grpc::ServerContext context;
    auto status = auth_service->RegisterDevice(&context, &reg_req, &reg_resp);

    ASSERT_TRUE(status.ok());
    // An ordinary JWT MUST NOT directly activate the device!
    EXPECT_EQ(reg_resp.status(), securecloud::auth::v1::DEVICE_STATUS_PENDING_AUTHORIZATION);
    EXPECT_FALSE(reg_resp.pairing_code().empty());
    EXPECT_GT(reg_resp.pairing_code_expires_at_epoch_ms(), 0);

    // Verify in database: Device exists strictly in PendingAuthorization state
    auto dev_id = domain::Uuid::from_string(reg_resp.device_id()).value();
    auto db_dev = device_repo_->find_by_id(dev_id);
    ASSERT_TRUE(db_dev.has_value());
    EXPECT_EQ(db_dev->device_status, domain::DeviceStatus::PendingAuthorization);
}

// ============================================================================
// Test 3: Full Device Enrollment & MFA Authorization E2E
// ============================================================================

TEST_F(AuthDeviceIntegrationTest, FullDeviceEnrollmentAndMfaAuthorizationE2E) {
    auto seeded = seed_user();
    auto auth_service = create_auth_service();

    // Direct registration with MFA_VERIFIED token immediately activates device
    auth_service->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    auto crypto = generate_valid_crypto_bundle(5);

    securecloud::auth::v1::RegisterDeviceRequest reg_req;
    reg_req.set_user_id(seeded.user.user_id.to_string());
    reg_req.set_identity_key(crypto.identity_pub.data(), crypto.identity_pub.size());
    reg_req.set_signed_prekey(crypto.signed_prekey.data(), crypto.signed_prekey.size());
    reg_req.set_signed_prekey_signature(crypto.signature.data(), crypto.signature.size());
    for (const auto& otk : crypto.one_time_prekeys) {
        reg_req.add_one_time_prekeys(otk.data(), otk.size());
    }

    securecloud::auth::v1::RegisterDeviceResponse reg_resp;
    ::grpc::ServerContext context;
    auto status = auth_service->RegisterDevice(&context, &reg_req, &reg_resp);

    ASSERT_TRUE(status.ok());
    EXPECT_EQ(reg_resp.status(), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    EXPECT_TRUE(reg_resp.pairing_code().empty());

    // Verify database device record
    auto dev_id = domain::Uuid::from_string(reg_resp.device_id()).value();
    auto db_dev = device_repo_->find_by_id(dev_id);
    ASSERT_TRUE(db_dev.has_value());
    EXPECT_EQ(db_dev->device_status, domain::DeviceStatus::Active);

    // Verify database public keys: 1 IdentityKey + 1 SignedPrekey + 5 OneTimePrekeys = 7 active keys
    auto keys = public_key_repo_->list_active_keys_by_device_id(dev_id);
    EXPECT_EQ(keys.size(), 7);
}

// ============================================================================
// Test 4: Cross-Device Pairing Flow
// ============================================================================

TEST_F(AuthDeviceIntegrationTest, CrossDevicePairingFlow) {
    auto seeded = seed_user();
    auto auth_service = create_auth_service();

    // Step 1: Device 1 registers with MFA_VERIFIED (Trusted Anchor)
    auth_service->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    auto crypto_dev1 = generate_valid_crypto_bundle();
    securecloud::auth::v1::RegisterDeviceRequest req1;
    req1.set_user_id(seeded.user.user_id.to_string());
    req1.set_identity_key(crypto_dev1.identity_pub.data(), crypto_dev1.identity_pub.size());
    req1.set_signed_prekey(crypto_dev1.signed_prekey.data(), crypto_dev1.signed_prekey.size());
    req1.set_signed_prekey_signature(crypto_dev1.signature.data(), crypto_dev1.signature.size());
    securecloud::auth::v1::RegisterDeviceResponse resp1;
    ::grpc::ServerContext ctx1;
    ASSERT_TRUE(auth_service->RegisterDevice(&ctx1, &req1, &resp1).ok());
    EXPECT_EQ(resp1.status(), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    auto dev1_id = domain::Uuid::from_string(resp1.device_id()).value();
    EXPECT_TRUE(device_repo_->find_by_id(dev1_id).has_value());

    // Step 2: Untrusted Device 2 initiates pairing (Primary-only caller)
    auth_service->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    auto crypto_dev2 = generate_valid_crypto_bundle();
    securecloud::auth::v1::RegisterDeviceRequest req2;
    req2.set_user_id(seeded.user.user_id.to_string());
    req2.set_identity_key(crypto_dev2.identity_pub.data(), crypto_dev2.identity_pub.size());
    req2.set_signed_prekey(crypto_dev2.signed_prekey.data(), crypto_dev2.signed_prekey.size());
    req2.set_signed_prekey_signature(crypto_dev2.signature.data(), crypto_dev2.signature.size());
    securecloud::auth::v1::RegisterDeviceResponse resp2;
    ::grpc::ServerContext ctx2;
    ASSERT_TRUE(auth_service->RegisterDevice(&ctx2, &req2, &resp2).ok());
    EXPECT_EQ(resp2.status(), securecloud::auth::v1::DEVICE_STATUS_PENDING_AUTHORIZATION);
    std::string pairing_pin = resp2.pairing_code();
    ASSERT_FALSE(pairing_pin.empty());
    auto dev2_id = domain::Uuid::from_string(resp2.device_id()).value();

    // Step 3: Device 2 cannot authenticate while pending authorization
    securecloud::auth::v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(seeded.user.credential_identifier);
    auth_req.set_password(seeded.raw_password);
    auth_req.set_device_id(dev2_id.to_string());
    securecloud::auth::v1::AuthenticateResponse auth_resp;
    ::grpc::ServerContext auth_ctx;
    auto auth_status = auth_service->Authenticate(&auth_ctx, &auth_req, &auth_resp);
    EXPECT_EQ(auth_status.error_code(), ::grpc::StatusCode::PERMISSION_DENIED);

    // Step 4: Trusted Device 1 (MFA-verified) approves pairing challenge for Device 2
    auth_service->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    securecloud::auth::v1::AuthorizeDeviceRequest approve_req;
    approve_req.set_user_id(seeded.user.user_id.to_string());
    approve_req.set_device_id(dev2_id.to_string());
    approve_req.set_pairing_code(pairing_pin);
    securecloud::auth::v1::AuthorizeDeviceResponse approve_resp;
    ::grpc::ServerContext approve_ctx;
    auto approve_status = auth_service->AuthorizeDevice(&approve_ctx, &approve_req, &approve_resp);
    ASSERT_TRUE(approve_status.ok());
    EXPECT_TRUE(approve_resp.authorized());
    EXPECT_EQ(approve_resp.status(), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    // Step 5: Device 2 is now Active in PostgreSQL and can authenticate
    auto db_dev2 = device_repo_->find_by_id(dev2_id);
    ASSERT_TRUE(db_dev2.has_value());
    EXPECT_EQ(db_dev2->device_status, domain::DeviceStatus::Active);

    securecloud::auth::v1::AuthenticateResponse auth_ok_resp;
    ::grpc::ServerContext auth_ok_ctx;
    auto auth_ok_status = auth_service->Authenticate(&auth_ok_ctx, &auth_req, &auth_ok_resp);
    ASSERT_TRUE(auth_ok_status.ok());
    EXPECT_FALSE(auth_ok_resp.access_token().empty());
}

// ============================================================================
// Test 5: Device Listing Active and Revoked
// ============================================================================

TEST_F(AuthDeviceIntegrationTest, DeviceListingActiveAndRevoked) {
    auto seeded = seed_user();
    auto auth_service = create_auth_service();

    auth_service->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    // Enroll Dev A & Dev B
    auto crypto_a = generate_valid_crypto_bundle();
    securecloud::auth::v1::RegisterDeviceRequest req_a;
    req_a.set_user_id(seeded.user.user_id.to_string());
    req_a.set_identity_key(crypto_a.identity_pub.data(), crypto_a.identity_pub.size());
    req_a.set_signed_prekey(crypto_a.signed_prekey.data(), crypto_a.signed_prekey.size());
    req_a.set_signed_prekey_signature(crypto_a.signature.data(), crypto_a.signature.size());
    securecloud::auth::v1::RegisterDeviceResponse resp_a;
    ::grpc::ServerContext ctx_a;
    ASSERT_TRUE(auth_service->RegisterDevice(&ctx_a, &req_a, &resp_a).ok());

    auto crypto_b = generate_valid_crypto_bundle();
    securecloud::auth::v1::RegisterDeviceRequest req_b;
    req_b.set_user_id(seeded.user.user_id.to_string());
    req_b.set_identity_key(crypto_b.identity_pub.data(), crypto_b.identity_pub.size());
    req_b.set_signed_prekey(crypto_b.signed_prekey.data(), crypto_b.signed_prekey.size());
    req_b.set_signed_prekey_signature(crypto_b.signature.data(), crypto_b.signature.size());
    securecloud::auth::v1::RegisterDeviceResponse resp_b;
    ::grpc::ServerContext ctx_b;
    ASSERT_TRUE(auth_service->RegisterDevice(&ctx_b, &req_b, &resp_b).ok());

    // Revoke Dev A
    securecloud::auth::v1::RevokeDeviceRequest rev_req;
    rev_req.set_user_id(seeded.user.user_id.to_string());
    rev_req.set_device_id(resp_a.device_id());
    rev_req.set_reason("Decommissioned Dev A");
    securecloud::auth::v1::RevokeDeviceResponse rev_resp;
    ::grpc::ServerContext rev_ctx;
    ASSERT_TRUE(auth_service->RevokeDevice(&rev_ctx, &rev_req, &rev_resp).ok());

    // Query list without revoked: Should only return Dev B
    securecloud::auth::v1::ListUserDevicesRequest list_req;
    list_req.set_user_id(seeded.user.user_id.to_string());
    list_req.set_include_revoked(false);
    securecloud::auth::v1::ListUserDevicesResponse list_resp;
    ::grpc::ServerContext list_ctx;
    ASSERT_TRUE(auth_service->ListUserDevices(&list_ctx, &list_req, &list_resp).ok());
    EXPECT_EQ(list_resp.devices_size(), 1);
    EXPECT_EQ(list_resp.devices(0).device_id(), resp_b.device_id());

    // Query list with include_revoked = true: Returns both
    list_req.set_include_revoked(true);
    securecloud::auth::v1::ListUserDevicesResponse list_all_resp;
    ::grpc::ServerContext list_all_ctx;
    ASSERT_TRUE(auth_service->ListUserDevices(&list_all_ctx, &list_req, &list_all_resp).ok());
    EXPECT_EQ(list_all_resp.devices_size(), 2);
}

// ============================================================================
// Test 6: Cascading Revocation & Application Session Invalidation
// ============================================================================

TEST_F(AuthDeviceIntegrationTest, CascadingRevocationAndSessionInvalidation) {
    auto seeded = seed_user();
    auto auth_service = create_auth_service();

    // Enroll Dev
    auth_service->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    auto crypto = generate_valid_crypto_bundle();
    securecloud::auth::v1::RegisterDeviceRequest reg_req;
    reg_req.set_user_id(seeded.user.user_id.to_string());
    reg_req.set_identity_key(crypto.identity_pub.data(), crypto.identity_pub.size());
    reg_req.set_signed_prekey(crypto.signed_prekey.data(), crypto.signed_prekey.size());
    reg_req.set_signed_prekey_signature(crypto.signature.data(), crypto.signature.size());
    securecloud::auth::v1::RegisterDeviceResponse reg_resp;
    ::grpc::ServerContext reg_ctx;
    ASSERT_TRUE(auth_service->RegisterDevice(&reg_ctx, &reg_req, &reg_resp).ok());
    auto dev_id = domain::Uuid::from_string(reg_resp.device_id()).value();

    // Authenticate and establish session
    securecloud::auth::v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(seeded.user.credential_identifier);
    auth_req.set_password(seeded.raw_password);
    auth_req.set_device_id(dev_id.to_string());
    securecloud::auth::v1::AuthenticateResponse auth_resp;
    ::grpc::ServerContext auth_ctx;
    ASSERT_TRUE(auth_service->Authenticate(&auth_ctx, &auth_req, &auth_resp).ok());
    std::string refresh_token = auth_resp.refresh_token();
    std::string session_id_str = auth_resp.session_id();
    auto session_id = domain::Uuid::from_string(session_id_str).value();

    // Verify session is active
    auto session_before = session_repo_->find_by_id(session_id);
    ASSERT_TRUE(session_before.has_value());
    EXPECT_EQ(session_before->session_status, domain::SessionStatus::Active);

    // Revoke device
    securecloud::auth::v1::RevokeDeviceRequest rev_req;
    rev_req.set_user_id(seeded.user.user_id.to_string());
    rev_req.set_device_id(dev_id.to_string());
    rev_req.set_reason("Device lost or compromised");
    securecloud::auth::v1::RevokeDeviceResponse rev_resp;
    ::grpc::ServerContext rev_ctx;
    ASSERT_TRUE(auth_service->RevokeDevice(&rev_ctx, &rev_req, &rev_resp).ok());
    EXPECT_TRUE(rev_resp.revoked());

    // 1. Invariant: Device is Revoked in database
    auto dev_after = device_repo_->find_by_id(dev_id);
    ASSERT_TRUE(dev_after.has_value());
    EXPECT_EQ(dev_after->device_status, domain::DeviceStatus::Revoked);

    // 2. Invariant: Cascading session invalidation (all sessions revoked)
    auto session_after = session_repo_->find_by_id(session_id);
    ASSERT_TRUE(session_after.has_value());
    EXPECT_EQ(session_after->session_status, domain::SessionStatus::Revoked);

    // 3. Invariant: Subsequent Authenticate using revoked device is PERMISSION_DENIED
    securecloud::auth::v1::AuthenticateResponse reauth_resp;
    ::grpc::ServerContext reauth_ctx;
    auto reauth_status = auth_service->Authenticate(&reauth_ctx, &auth_req, &reauth_resp);
    EXPECT_EQ(reauth_status.error_code(), ::grpc::StatusCode::PERMISSION_DENIED);

    // 4. Invariant: Subsequent RefreshSession using token from revoked device is PERMISSION_DENIED
    securecloud::auth::v1::RefreshSessionRequest ref_req;
    ref_req.set_refresh_token(refresh_token);
    ref_req.set_device_id(dev_id.to_string());
    securecloud::auth::v1::RefreshSessionResponse ref_resp;
    ::grpc::ServerContext ref_ctx;
    auto ref_status = auth_service->RefreshSession(&ref_ctx, &ref_req, &ref_resp);
    EXPECT_EQ(ref_status.error_code(), ::grpc::StatusCode::PERMISSION_DENIED);
}

// ============================================================================
// Test 7: Durability Across Service Restart
// ============================================================================

TEST_F(AuthDeviceIntegrationTest, DurabilityAcrossServiceRestart) {
    auto seeded = seed_user();
    std::string dev_id_str;

    {
        // Ephemeral service instance 1
        auto auth_service = create_auth_service();
        auth_service->set_caller_auth_level_for_testing(
            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

        auto crypto = generate_valid_crypto_bundle(4);
        securecloud::auth::v1::RegisterDeviceRequest reg_req;
        reg_req.set_user_id(seeded.user.user_id.to_string());
        reg_req.set_identity_key(crypto.identity_pub.data(), crypto.identity_pub.size());
        reg_req.set_signed_prekey(crypto.signed_prekey.data(), crypto.signed_prekey.size());
        reg_req.set_signed_prekey_signature(crypto.signature.data(), crypto.signature.size());
        for (const auto& otk : crypto.one_time_prekeys) {
            reg_req.add_one_time_prekeys(otk.data(), otk.size());
        }

        securecloud::auth::v1::RegisterDeviceResponse reg_resp;
        ::grpc::ServerContext context;
        ASSERT_TRUE(auth_service->RegisterDevice(&context, &reg_req, &reg_resp).ok());
        dev_id_str = reg_resp.device_id();
    } // Service 1 completely destroyed

    // Reconstitute service instance 2 against the persistent PostgreSQL database
    auto auth_service_restarted = create_auth_service();

    securecloud::auth::v1::GetDeviceRequest get_req;
    get_req.set_device_id(dev_id_str);
    securecloud::auth::v1::GetDeviceResponse get_resp;
    ::grpc::ServerContext get_ctx;
    auto get_status = auth_service_restarted->GetDevice(&get_ctx, &get_req, &get_resp);

    ASSERT_TRUE(get_status.ok());
    EXPECT_EQ(get_resp.device().device_id(), dev_id_str);
    EXPECT_EQ(get_resp.device().user_id(), seeded.user.user_id.to_string());
    EXPECT_EQ(get_resp.device().device_status(), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    // Verify cryptographic public keys survived restart
    auto dev_id = domain::Uuid::from_string(dev_id_str).value();
    auto keys = public_key_repo_->list_active_keys_by_device_id(dev_id);
    EXPECT_EQ(keys.size(), 6); // 1 id + 1 spk + 4 otk
}

// ============================================================================
// Test 8: Concurrent Authorization & Revocation Safety
// ============================================================================

TEST_F(AuthDeviceIntegrationTest, ConcurrentAuthorizationAndRevocation) {
    auto seeded = seed_user();
    auto auth_service = create_auth_service();

    // Register pending device
    auth_service->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    auto crypto = generate_valid_crypto_bundle();
    securecloud::auth::v1::RegisterDeviceRequest reg_req;
    reg_req.set_user_id(seeded.user.user_id.to_string());
    reg_req.set_identity_key(crypto.identity_pub.data(), crypto.identity_pub.size());
    reg_req.set_signed_prekey(crypto.signed_prekey.data(), crypto.signed_prekey.size());
    reg_req.set_signed_prekey_signature(crypto.signature.data(), crypto.signature.size());
    securecloud::auth::v1::RegisterDeviceResponse reg_resp;
    ::grpc::ServerContext reg_ctx;
    ASSERT_TRUE(auth_service->RegisterDevice(&reg_ctx, &reg_req, &reg_resp).ok());
    std::string dev_id_str = reg_resp.device_id();
    std::string pin = reg_resp.pairing_code();
    auto dev_id = domain::Uuid::from_string(dev_id_str).value();

    // Launch concurrent threads attempting Authorize and Revoke
    auto auth_fut = std::async(std::launch::async, [&]() {
        auto s = create_auth_service();
        s->set_caller_auth_level_for_testing(
            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
        securecloud::auth::v1::AuthorizeDeviceRequest req;
        req.set_user_id(seeded.user.user_id.to_string());
        req.set_device_id(dev_id_str);
        req.set_pairing_code(pin);
        securecloud::auth::v1::AuthorizeDeviceResponse resp;
        ::grpc::ServerContext ctx;
        return s->AuthorizeDevice(&ctx, &req, &resp);
    });

    auto rev_fut = std::async(std::launch::async, [&]() {
        auto s = create_auth_service();
        s->set_caller_auth_level_for_testing(
            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
        securecloud::auth::v1::RevokeDeviceRequest req;
        req.set_user_id(seeded.user.user_id.to_string());
        req.set_device_id(dev_id_str);
        req.set_reason("Concurrent test revocation");
        securecloud::auth::v1::RevokeDeviceResponse resp;
        ::grpc::ServerContext ctx;
        return s->RevokeDevice(&ctx, &req, &resp);
    });

    auto auth_status = auth_fut.get();
    auto rev_status = rev_fut.get();

    // Both calls must complete cleanly without throwing unhandled exceptions
    EXPECT_TRUE(auth_status.ok() || auth_status.error_code() == ::grpc::StatusCode::PERMISSION_DENIED ||
                auth_status.error_code() == ::grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_TRUE(rev_status.ok());

    // Invariant: Final device state in database must be valid and deterministic
    auto dev_final = device_repo_->find_by_id(dev_id);
    ASSERT_TRUE(dev_final.has_value());
    EXPECT_TRUE(dev_final->device_status == domain::DeviceStatus::Active ||
                dev_final->device_status == domain::DeviceStatus::Revoked);
}

} // namespace
} // namespace securecloud::auth::integration::test
