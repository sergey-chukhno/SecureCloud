#include "auth/auth_config.hpp"
#include "auth/crypto/argon2id_hasher.hpp"
#include "auth/crypto/key_fingerprint.hpp"
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
#include "auth/service/crypto_directory_manager.hpp"
#include "auth/service/device_manager.hpp"
#include "auth/service/session_manager.hpp"
#include "auth/service/token_manager.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <chrono>
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
using domain::DeviceEntity;
using domain::DevicePublicKeyEntity;
using domain::DeviceStatus;
using domain::KeyStatus;
using domain::KeyType;
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
    // Private identity key for signing rotations in tests
    std::shared_ptr<EVP_PKEY> id_pkey;
};

CryptoBundle generate_valid_crypto_bundle(std::size_t otk_count = 3) {
    CryptoBundle bundle;

    // 1. Ed25519 Identity Key
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY* raw_id_pkey = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &raw_id_pkey);
    EVP_PKEY_CTX_free(ctx);
    bundle.id_pkey = std::shared_ptr<EVP_PKEY>(raw_id_pkey, EVP_PKEY_free);

    size_t id_len = 32;
    bundle.identity_pub.resize(id_len);
    EVP_PKEY_get_raw_public_key(bundle.id_pkey.get(), bundle.identity_pub.data(), &id_len);

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
    EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, bundle.id_pkey.get());
    size_t sig_len = 64;
    bundle.signature.resize(sig_len);
    EVP_DigestSign(md_ctx, bundle.signature.data(), &sig_len, bundle.signed_prekey.data(), bundle.signed_prekey.size());
    EVP_MD_CTX_free(md_ctx);

    // 4. One-time prekeys (X25519)
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

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> create_signed_prekey(EVP_PKEY* id_pkey) {
    EVP_PKEY_CTX* spk_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* spk_pkey = nullptr;
    EVP_PKEY_keygen_init(spk_ctx);
    EVP_PKEY_keygen(spk_ctx, &spk_pkey);
    EVP_PKEY_CTX_free(spk_ctx);

    size_t spk_len = 32;
    std::vector<uint8_t> spk_bytes(spk_len);
    EVP_PKEY_get_raw_public_key(spk_pkey, spk_bytes.data(), &spk_len);
    EVP_PKEY_free(spk_pkey);

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, id_pkey);
    size_t sig_len = 64;
    std::vector<uint8_t> sig(sig_len);
    EVP_DigestSign(md_ctx, sig.data(), &sig_len, spk_bytes.data(), spk_bytes.size());
    EVP_MD_CTX_free(md_ctx);

    return {spk_bytes, sig};
}

std::vector<std::vector<uint8_t>> generate_x25519_otks(std::size_t count) {
    std::vector<std::vector<uint8_t>> otks;
    otks.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        EVP_PKEY_CTX* otk_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY* otk_pkey = nullptr;
        EVP_PKEY_keygen_init(otk_ctx);
        EVP_PKEY_keygen(otk_ctx, &otk_pkey);
        EVP_PKEY_CTX_free(otk_ctx);

        size_t otk_len = 32;
        std::vector<uint8_t> otk(otk_len);
        EVP_PKEY_get_raw_public_key(otk_pkey, otk.data(), &otk_len);
        EVP_PKEY_free(otk_pkey);
        otks.push_back(std::move(otk));
    }
    return otks;
}

} // namespace

// ============================================================================
// 1. Strict Port 5432 Protection Preflight Test
// ============================================================================

TEST(AuthCryptoIdentityPreflightTest, StrictPort5432Protection) {
    AuthConfig forbidden_cfg = make_test_auth_config();
    forbidden_cfg.db_port = 5432;

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), db::PortForbiddenException);
}

// ============================================================================
// 2. Live Cryptographic Identity Integration Test Fixture (Port 5433)
// ============================================================================

class AuthCryptoIdentityIntegrationTest : public ::testing::Test {
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
        crypto_directory_mgr_ =
            std::make_shared<service::CryptoDirectoryManager>(device_repo_, public_key_repo_, audit_publisher_);

        auth_service_ = create_auth_service();
    }

    std::unique_ptr<service::AuthServiceImpl> create_auth_service() {
        auto verifier = std::make_shared<service::CredentialVerifier>(user_repo_, hasher_);
        return std::make_unique<service::AuthServiceImpl>(verifier, session_mgr_, audit_publisher_, token_mgr_, nullptr,
                                                          device_mgr_, crypto_directory_mgr_);
    }

    struct SeededUser {
        UserEntity user;
        std::string raw_password;
    };

    SeededUser seed_user() {
        std::string email = "crypto_user_" + Uuid::generate_v7().to_string() + "@securecloud.io";
        std::string raw_password = "CryptoPass123!";

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

    DeviceEntity seed_device_with_crypto_keys(const Uuid& user_id, const CryptoBundle& bundle,
                                              DeviceStatus status = DeviceStatus::Active) {
        const auto device_id = Uuid::generate_v7();
        const auto now = std::chrono::system_clock::now();

        DeviceEntity dev{
            .device_id = device_id,
            .user_id = user_id,
            .device_status = status,
            .registered_at = now,
            .revoked_at = (status == DeviceStatus::Revoked) ? std::optional<domain::time_point>{now} : std::nullopt,
            .revocation_reason =
                (status == DeviceStatus::Revoked) ? std::optional<std::string>{"Revoked in test"} : std::nullopt,
            .last_authenticated_at = now,
            .created_at = now,
            .updated_at = now,
        };
        device_repo_->register_device(dev);

        // Store identity key
        DevicePublicKeyEntity id_key{
            .key_id = Uuid::generate_v7(),
            .device_id = device_id,
            .key_type = KeyType::IdentitySigning,
            .public_key = bundle.identity_pub,
            .key_status = (status == DeviceStatus::Revoked) ? KeyStatus::Revoked : KeyStatus::Active,
            .created_at = now,
            .revoked_at = (status == DeviceStatus::Revoked) ? std::optional<domain::time_point>{now} : std::nullopt,
            .replaced_by_key_id = std::nullopt,
            .signature = std::nullopt,
        };
        public_key_repo_->store_public_key(id_key);

        // Store signed prekey
        DevicePublicKeyEntity spk{
            .key_id = Uuid::generate_v7(),
            .device_id = device_id,
            .key_type = KeyType::SignedPrekey,
            .public_key = bundle.signed_prekey,
            .key_status = (status == DeviceStatus::Revoked) ? KeyStatus::Revoked : KeyStatus::Active,
            .created_at = now,
            .revoked_at = (status == DeviceStatus::Revoked) ? std::optional<domain::time_point>{now} : std::nullopt,
            .replaced_by_key_id = std::nullopt,
            .signature = bundle.signature,
        };
        public_key_repo_->store_public_key(spk);

        // Store one-time prekeys
        if (!bundle.one_time_prekeys.empty() && status == DeviceStatus::Active) {
            public_key_repo_->store_one_time_prekeys(device_id, bundle.one_time_prekeys);
        }

        return dev;
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
    std::shared_ptr<service::CryptoDirectoryManager> crypto_directory_mgr_;
    std::unique_ptr<service::AuthServiceImpl> auth_service_;
};

// ============================================================================
// 3. Multi-Device Directory Discovery & Cryptographic Verification E2E
// ============================================================================

TEST_F(AuthCryptoIdentityIntegrationTest, FullMultiDeviceDirectoryDiscoveryE2E) {
    const auto seeded = seed_user();
    const auto user_id = seeded.user.user_id;

    // Provision 3 devices with distinct crypto bundles
    auto bundle1 = generate_valid_crypto_bundle(5);
    auto bundle2 = generate_valid_crypto_bundle(5);
    auto bundle3 = generate_valid_crypto_bundle(5);

    auto dev1 = seed_device_with_crypto_keys(user_id, bundle1);
    auto dev2 = seed_device_with_crypto_keys(user_id, bundle2);
    auto dev3 = seed_device_with_crypto_keys(user_id, bundle3);

    // Call GetDeviceCryptoDirectory
    grpc::ServerContext context;
    securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
    req.set_user_id(user_id.to_string());
    securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

    auto status = auth_service_->GetDeviceCryptoDirectory(&context, &req, &resp);
    ASSERT_TRUE(status.ok()) << "gRPC error: " << status.error_message();
    ASSERT_EQ(resp.devices_size(), 3);

    // Verify all 3 devices are present and contain valid cryptographic material
    std::map<std::string, const securecloud::auth::v1::DeviceCryptoRecord*> record_map;
    for (int i = 0; i < resp.devices_size(); ++i) {
        const auto& rec = resp.devices(i);
        record_map[rec.device_id()] = &rec;
    }

    EXPECT_NE(record_map.find(dev1.device_id.to_string()), record_map.end());
    EXPECT_NE(record_map.find(dev2.device_id.to_string()), record_map.end());
    EXPECT_NE(record_map.find(dev3.device_id.to_string()), record_map.end());

    const auto* rec1 = record_map[dev1.device_id.to_string()];
    EXPECT_EQ(rec1->identity_key().size(), 32);
    EXPECT_EQ(std::vector<uint8_t>(rec1->identity_key().begin(), rec1->identity_key().end()), bundle1.identity_pub);
    EXPECT_EQ(rec1->identity_key_fingerprint(), crypto::KeyFingerprint::compute_sha256(bundle1.identity_pub));
    EXPECT_EQ(rec1->signed_prekey().size(), 32);
    EXPECT_EQ(std::vector<uint8_t>(rec1->signed_prekey().begin(), rec1->signed_prekey().end()), bundle1.signed_prekey);
    EXPECT_EQ(rec1->signed_prekey_signature().size(), 64);
    EXPECT_EQ(std::vector<uint8_t>(rec1->signed_prekey_signature().begin(), rec1->signed_prekey_signature().end()),
              bundle1.signature);
    EXPECT_EQ(rec1->status(), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    EXPECT_EQ(rec1->one_time_prekey().size(), 32);
    EXPECT_FALSE(rec1->one_time_prekey_id().empty());
    EXPECT_EQ(rec1->remaining_one_time_prekeys(), 4); // 5 - 1 claimed
}

// ============================================================================
// 4. Single-Use OTK Claiming & Depletion Fallback
// ============================================================================

TEST_F(AuthCryptoIdentityIntegrationTest, SingleUseOtkClaimingAndDepletionFallback) {
    const auto seeded = seed_user();
    const auto user_id = seeded.user.user_id;

    // Device provisioned with exactly 2 OTKs
    auto bundle = generate_valid_crypto_bundle(2);
    auto dev = seed_device_with_crypto_keys(user_id, bundle);

    // First lookup: claims OTK 1
    {
        grpc::ServerContext context;
        securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
        req.set_user_id(user_id.to_string());
        securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

        auto status = auth_service_->GetDeviceCryptoDirectory(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        ASSERT_EQ(resp.devices_size(), 1);
        EXPECT_EQ(resp.devices(0).remaining_one_time_prekeys(), 1);
        EXPECT_EQ(resp.devices(0).one_time_prekey().size(), 32);
    }

    // Second lookup: claims OTK 2
    std::string otk2_id;
    std::string otk2_bytes;
    {
        grpc::ServerContext context;
        securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
        req.set_user_id(user_id.to_string());
        securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

        auto status = auth_service_->GetDeviceCryptoDirectory(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        ASSERT_EQ(resp.devices_size(), 1);
        EXPECT_EQ(resp.devices(0).remaining_one_time_prekeys(), 0);
        EXPECT_EQ(resp.devices(0).one_time_prekey().size(), 32);
        otk2_id = resp.devices(0).one_time_prekey_id();
        otk2_bytes = resp.devices(0).one_time_prekey();
    }

    // Third lookup: Pool is exhausted -> falls back cleanly to signed prekey only
    {
        grpc::ServerContext context;
        securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
        req.set_user_id(user_id.to_string());
        securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

        auto status = auth_service_->GetDeviceCryptoDirectory(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        ASSERT_EQ(resp.devices_size(), 1);
        EXPECT_EQ(resp.devices(0).remaining_one_time_prekeys(), 0);
        EXPECT_TRUE(resp.devices(0).one_time_prekey().empty());
        EXPECT_TRUE(resp.devices(0).one_time_prekey_id().empty());
        EXPECT_EQ(resp.devices(0).signed_prekey().size(), 32);
    }
}

// ============================================================================
// 5. Revoked Device Handling
// ============================================================================

TEST_F(AuthCryptoIdentityIntegrationTest, RevokedDeviceHandling) {
    const auto seeded = seed_user();
    const auto user_id = seeded.user.user_id;

    auto bundle1 = generate_valid_crypto_bundle(2);
    auto bundle2 = generate_valid_crypto_bundle(2);

    auto dev1 = seed_device_with_crypto_keys(user_id, bundle1, DeviceStatus::Active);
    auto dev2 = seed_device_with_crypto_keys(user_id, bundle2, DeviceStatus::Active);

    // Revoke Device 2
    const auto now = std::chrono::system_clock::now();
    device_repo_->revoke_device(dev2.device_id, "Device decommissioned", now);
    public_key_repo_->revoke_all_device_keys(dev2.device_id, now);

    // Directory lookup: only active Device 1 is returned
    {
        grpc::ServerContext context;
        securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
        req.set_user_id(user_id.to_string());
        securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

        auto status = auth_service_->GetDeviceCryptoDirectory(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        ASSERT_EQ(resp.devices_size(), 1);
        EXPECT_EQ(resp.devices(0).device_id(), dev1.device_id.to_string());
    }

    // Direct GetCryptoIdentity lookup for Revoked Device 2: returns REVOKED and omits prekeys
    {
        grpc::ServerContext context;
        securecloud::auth::v1::GetCryptoIdentityRequest req;
        req.set_device_id(dev2.device_id.to_string());
        securecloud::auth::v1::GetCryptoIdentityResponse resp;

        auto status = auth_service_->GetCryptoIdentity(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        EXPECT_EQ(resp.status(), securecloud::auth::v1::DEVICE_STATUS_REVOKED);
        EXPECT_TRUE(resp.signed_prekey().empty());
        EXPECT_TRUE(resp.signed_prekey_signature().empty());
    }
}

// ============================================================================
// 6. Signed Prekey Rotation with Signature Verification
// ============================================================================

TEST_F(AuthCryptoIdentityIntegrationTest, SignedPrekeyRotationWithSignatureVerification) {
    const auto seeded = seed_user();
    const auto user_id = seeded.user.user_id;

    auto bundle = generate_valid_crypto_bundle(2);
    auto dev = seed_device_with_crypto_keys(user_id, bundle);

    // Generate new signed prekey signed by the device's original private Ed25519 identity key
    auto [new_spk, new_sig] = create_signed_prekey(bundle.id_pkey.get());

    // 1. Authorized update with valid cryptographic signature succeeds
    {
        auth_service_->set_caller_identity_for_testing(user_id, dev.device_id);

        grpc::ServerContext context;
        securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
        req.set_device_id(dev.device_id.to_string());
        req.set_signed_prekey(new_spk.data(), new_spk.size());
        req.set_signed_prekey_signature(new_sig.data(), new_sig.size());
        securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

        auto status = auth_service_->UpdateCryptoPrekeys(&context, &req, &resp);
        ASSERT_TRUE(status.ok()) << "gRPC error: " << status.error_message();
        EXPECT_GT(resp.updated_at_epoch_ms(), 0);
    }

    // 2. Direct GetCryptoIdentity reflects the newly rotated signed prekey and signature
    {
        grpc::ServerContext context;
        securecloud::auth::v1::GetCryptoIdentityRequest req;
        req.set_device_id(dev.device_id.to_string());
        securecloud::auth::v1::GetCryptoIdentityResponse resp;

        auto status = auth_service_->GetCryptoIdentity(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        EXPECT_EQ(std::vector<uint8_t>(resp.signed_prekey().begin(), resp.signed_prekey().end()), new_spk);
        EXPECT_EQ(std::vector<uint8_t>(resp.signed_prekey_signature().begin(), resp.signed_prekey_signature().end()),
                  new_sig);
    }

    // 3. Attempting to rotate with a corrupted signature is strictly rejected
    {
        auto [another_spk, another_sig] = create_signed_prekey(bundle.id_pkey.get());
        another_sig[0] ^= 0xFF; // Corrupt signature byte

        auth_service_->set_caller_identity_for_testing(user_id, dev.device_id);

        grpc::ServerContext context;
        securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
        req.set_device_id(dev.device_id.to_string());
        req.set_signed_prekey(another_spk.data(), another_spk.size());
        req.set_signed_prekey_signature(another_sig.data(), another_sig.size());
        securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

        auto status = auth_service_->UpdateCryptoPrekeys(&context, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    }
}

// ============================================================================
// 7. One-Time Prekey Replenishment
// ============================================================================

TEST_F(AuthCryptoIdentityIntegrationTest, OneTimePrekeyReplenishment) {
    const auto seeded = seed_user();
    const auto user_id = seeded.user.user_id;

    // Device provisioned with 0 OTKs
    auto bundle = generate_valid_crypto_bundle(0);
    auto dev = seed_device_with_crypto_keys(user_id, bundle);

    // Initial query shows 0 remaining OTKs
    {
        grpc::ServerContext context;
        securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
        req.set_user_id(user_id.to_string());
        securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

        auto status = auth_service_->GetDeviceCryptoDirectory(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        ASSERT_EQ(resp.devices_size(), 1);
        EXPECT_EQ(resp.devices(0).remaining_one_time_prekeys(), 0);
    }

    // Replenish with 10 new X25519 OTKs
    auto new_otks = generate_x25519_otks(10);
    {
        auth_service_->set_caller_identity_for_testing(user_id, dev.device_id);

        grpc::ServerContext context;
        securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
        req.set_device_id(dev.device_id.to_string());
        for (const auto& otk : new_otks) {
            req.add_one_time_prekeys(otk.data(), otk.size());
        }
        securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

        auto status = auth_service_->UpdateCryptoPrekeys(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        EXPECT_EQ(resp.active_one_time_prekey_count(), 10);
    }

    // Subsequent directory query successfully dispenses an OTK from the replenished pool
    {
        grpc::ServerContext context;
        securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
        req.set_user_id(user_id.to_string());
        securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

        auto status = auth_service_->GetDeviceCryptoDirectory(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        ASSERT_EQ(resp.devices_size(), 1);
        EXPECT_EQ(resp.devices(0).one_time_prekey().size(), 32);
        EXPECT_EQ(resp.devices(0).remaining_one_time_prekeys(), 9);
    }
}

// ============================================================================
// 8. Unauthorized Key Management Rejection
// ============================================================================

TEST_F(AuthCryptoIdentityIntegrationTest, UnauthorizedKeyManagementRejection) {
    const auto seeded_a = seed_user();
    const auto seeded_b = seed_user();

    auto bundle_a = generate_valid_crypto_bundle(2);
    auto bundle_b = generate_valid_crypto_bundle(2);

    auto dev_a = seed_device_with_crypto_keys(seeded_a.user.user_id, bundle_a);
    auto dev_b = seed_device_with_crypto_keys(seeded_b.user.user_id, bundle_b);

    auto [new_spk, new_sig] = create_signed_prekey(bundle_b.id_pkey.get());

    // 1. Cross-device attack: Device A attempts to update Device B's prekeys
    {
        auth_service_->set_caller_identity_for_testing(seeded_a.user.user_id, dev_a.device_id);

        grpc::ServerContext context;
        securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
        req.set_device_id(dev_b.device_id.to_string()); // Target is Device B
        req.set_signed_prekey(new_spk.data(), new_spk.size());
        req.set_signed_prekey_signature(new_sig.data(), new_sig.size());
        securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

        auto status = auth_service_->UpdateCryptoPrekeys(&context, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    }

    // 2. Unauthenticated request: No caller identity metadata
    {
        auth_service_->set_caller_identity_for_testing(std::nullopt, std::nullopt);

        grpc::ServerContext context;
        securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
        req.set_device_id(dev_b.device_id.to_string());
        req.set_signed_prekey(new_spk.data(), new_spk.size());
        req.set_signed_prekey_signature(new_sig.data(), new_sig.size());
        securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

        auto status = auth_service_->UpdateCryptoPrekeys(&context, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
    }
}

// ============================================================================
// 9. Key Change Detectability
// ============================================================================

TEST_F(AuthCryptoIdentityIntegrationTest, KeyChangeDetectability) {
    const auto seeded = seed_user();
    const auto user_id = seeded.user.user_id;

    auto bundle = generate_valid_crypto_bundle(2);
    auto dev = seed_device_with_crypto_keys(user_id, bundle);

    // Initial identity query
    int64_t initial_created_at = 0;
    std::string initial_fingerprint;
    {
        grpc::ServerContext context;
        securecloud::auth::v1::GetCryptoIdentityRequest req;
        req.set_device_id(dev.device_id.to_string());
        securecloud::auth::v1::GetCryptoIdentityResponse resp;

        auto status = auth_service_->GetCryptoIdentity(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        initial_created_at = resp.signed_prekey_created_at_epoch_ms();
        initial_fingerprint = resp.identity_key_fingerprint();
        EXPECT_THAT(initial_fingerprint, ::testing::StartsWith("SHA256:"));
    }

    // Rotate signed prekey
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto [new_spk, new_sig] = create_signed_prekey(bundle.id_pkey.get());

    {
        auth_service_->set_caller_identity_for_testing(user_id, dev.device_id);

        grpc::ServerContext context;
        securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
        req.set_device_id(dev.device_id.to_string());
        req.set_signed_prekey(new_spk.data(), new_spk.size());
        req.set_signed_prekey_signature(new_sig.data(), new_sig.size());
        securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

        auto status = auth_service_->UpdateCryptoPrekeys(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
    }

    // Verify key changes are detectable by client: timestamp updated, identity fingerprint preserved
    {
        grpc::ServerContext context;
        securecloud::auth::v1::GetCryptoIdentityRequest req;
        req.set_device_id(dev.device_id.to_string());
        securecloud::auth::v1::GetCryptoIdentityResponse resp;

        auto status = auth_service_->GetCryptoIdentity(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        EXPECT_EQ(resp.identity_key_fingerprint(), initial_fingerprint);
        EXPECT_GT(resp.signed_prekey_created_at_epoch_ms(), initial_created_at);
    }
}

// ============================================================================
// 10. Durability Across Service Restart
// ============================================================================

TEST_F(AuthCryptoIdentityIntegrationTest, DurabilityAcrossServiceRestart) {
    const auto seeded = seed_user();
    const auto user_id = seeded.user.user_id;

    auto bundle = generate_valid_crypto_bundle(3);
    auto dev = seed_device_with_crypto_keys(user_id, bundle);

    // Claim 1 OTK
    {
        grpc::ServerContext context;
        securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
        req.set_user_id(user_id.to_string());
        securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

        auto status = auth_service_->GetDeviceCryptoDirectory(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        EXPECT_EQ(resp.devices(0).remaining_one_time_prekeys(), 2);
    }

    // Simulate complete daemon shutdown and restart by tearing down and rebuilding domain components
    auth_service_.reset();
    crypto_directory_mgr_.reset();
    device_mgr_.reset();
    token_mgr_.reset();
    session_mgr_.reset();
    public_key_repo_.reset();
    device_repo_.reset();
    user_repo_.reset();
    pool_.reset();

    // Reconnect to PostgreSQL 17
    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 10;
    pool_ = std::make_unique<db::PostgresConnectionPool>(config_, pool_cfg);

    user_repo_ = std::make_shared<repository::PostgresUserRepository>(*pool_);
    device_repo_ = std::make_shared<repository::PostgresDeviceRepository>(*pool_);
    public_key_repo_ = std::make_shared<repository::PostgresDevicePublicKeyRepository>(*pool_);
    session_repo_ = std::make_shared<repository::PostgresSessionRepository>(*pool_);
    refresh_token_repo_ = std::make_shared<repository::PostgresRefreshTokenRepository>(*pool_);

    session_mgr_ = std::make_shared<service::SessionManager>(session_repo_, device_repo_, std::chrono::hours(24),
                                                             audit_publisher_);
    token_mgr_ = std::make_shared<service::TokenManager>(token_signer_, refresh_token_repo_, session_repo_,
                                                         device_repo_, audit_publisher_);
    device_mgr_ =
        std::make_shared<service::DeviceManager>(device_repo_, public_key_repo_, session_mgr_, audit_publisher_);
    crypto_directory_mgr_ =
        std::make_shared<service::CryptoDirectoryManager>(device_repo_, public_key_repo_, audit_publisher_);
    auth_service_ = create_auth_service();

    // Verify persisted state survived restart: identity key, fingerprint, and remaining count (2 -> 1)
    {
        grpc::ServerContext context;
        securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
        req.set_user_id(user_id.to_string());
        securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

        auto status = auth_service_->GetDeviceCryptoDirectory(&context, &req, &resp);
        ASSERT_TRUE(status.ok());
        ASSERT_EQ(resp.devices_size(), 1);
        EXPECT_EQ(resp.devices(0).identity_key_fingerprint(),
                  crypto::KeyFingerprint::compute_sha256(bundle.identity_pub));
        EXPECT_EQ(resp.devices(0).remaining_one_time_prekeys(), 1); // 2 remaining - 1 claimed
    }
}

} // namespace securecloud::auth::integration::test
