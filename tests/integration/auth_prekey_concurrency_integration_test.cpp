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
#include "auth/service/prekey_manager.hpp"
#include "auth/service/session_manager.hpp"
#include "auth/service/token_manager.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <atomic>
#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <openssl/evp.h>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::auth::integration::test {
namespace {

using domain::AccountStatus;
using domain::AuditEventType;
using domain::DeviceEntity;
using domain::DevicePublicKeyEntity;
using domain::DeviceStatus;
using domain::KeyStatus;
using domain::KeyType;
using domain::PrekeyExhaustionState;
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

// Thread-safe audit sink capturing domain audit events during live concurrent tests
class ThreadSafeTestAuditSink final : public service::IAuditEventSink {
  public:
    void emit(const domain::AuditEvent& event, std::string_view /*json_payload*/) override {
        std::lock_guard<std::mutex> lock(mu_);
        emitted_events.push_back(event);
    }

    bool has_event_type(domain::AuditEventType type) const {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& ev : emitted_events) {
            if (ev.event_type == type) {
                return true;
            }
        }
        return false;
    }

    std::size_t count_event_type(domain::AuditEventType type) const {
        std::lock_guard<std::mutex> lock(mu_);
        std::size_t cnt = 0;
        for (const auto& ev : emitted_events) {
            if (ev.event_type == type) {
                ++cnt;
            }
        }
        return cnt;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mu_);
        emitted_events.clear();
    }

    mutable std::mutex mu_;
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
    std::shared_ptr<EVP_PKEY> id_pkey;
};

CryptoBundle generate_valid_crypto_bundle(std::size_t otk_count = 50) {
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

TEST(AuthPrekeyConcurrencyPreflightTest, StrictPort5432Protection) {
    AuthConfig forbidden_cfg = make_test_auth_config();
    forbidden_cfg.db_port = 5432;

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), db::PortForbiddenException);
}

// ============================================================================
// 2. Live PostgreSQL 17 Prekey Concurrency & Stress Integration Fixture
// ============================================================================

class AuthPrekeyConcurrencyIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        config_ = make_test_auth_config();

        // Invariant: NEVER touch host PostgreSQL 14 on port 5432
        ASSERT_NE(config_.db_port, 5432) << "CRITICAL ERROR: Tests must NEVER connect to host PostgreSQL on port 5432!";
        ASSERT_EQ(config_.db_port, 5433) << "Tests must strictly connect to containerized PostgreSQL 17 on port 5433!";

        // Sufficient max_connections for 50 concurrent stress threads
        db::ConnectionPoolConfig pool_cfg;
        pool_cfg.min_connections = 0;
        pool_cfg.max_connections = 60;
        pool_cfg.acquire_timeout = std::chrono::milliseconds{10000};
        pool_cfg.connect_timeout = std::chrono::seconds{3};

        pool_ = std::make_unique<db::PostgresConnectionPool>(config_, pool_cfg);

        if (!pool_->ping()) {
            GTEST_SKIP() << "PostgreSQL 17 container on 127.0.0.1:5433 is not reachable. Skipping live database "
                            "integration tests.";
        }

        // Apply schema migrations
        db::MigrationRunner runner(*pool_);
        runner.run_migrations();

        audit_sink_ = std::make_shared<ThreadSafeTestAuditSink>();
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
        prekey_mgr_ = std::make_shared<service::PrekeyManager>(device_repo_, public_key_repo_, audit_publisher_);

        auth_service_ = create_auth_service();
    }

    std::unique_ptr<service::AuthServiceImpl> create_auth_service() {
        auto verifier = std::make_shared<service::CredentialVerifier>(user_repo_, hasher_);
        return std::make_unique<service::AuthServiceImpl>(verifier, session_mgr_, audit_publisher_, token_mgr_, nullptr,
                                                          device_mgr_, crypto_directory_mgr_, prekey_mgr_);
    }

    struct SeededUser {
        UserEntity user;
        std::string raw_password;
    };

    SeededUser seed_user() {
        std::string email = "prekey_user_" + Uuid::generate_v7().to_string() + "@securecloud.io";
        std::string raw_password = "PrekeyPass123!";

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
    std::shared_ptr<ThreadSafeTestAuditSink> audit_sink_;
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
    std::shared_ptr<service::PrekeyManager> prekey_mgr_;
    std::unique_ptr<service::AuthServiceImpl> auth_service_;
};

// ============================================================================
// 3. Heavy Multi-Threaded Concurrent Consumption Race (50 Threads)
// ============================================================================

TEST_F(AuthPrekeyConcurrencyIntegrationTest, HeavyMultiThreadedConcurrentConsumptionRace) {
    constexpr std::size_t kNumThreads = 50;
    auto [user, _] = seed_user();
    auto bundle = generate_valid_crypto_bundle(kNumThreads);
    auto dev = seed_device_with_crypto_keys(user.user_id, bundle);

    // Verify initial inventory
    auto inv_res = prekey_mgr_->get_inventory_status(dev.device_id);
    ASSERT_TRUE(inv_res.is_success());
    EXPECT_EQ(inv_res.inventory_status.active_one_time_prekeys, kNumThreads);
    EXPECT_EQ(inv_res.inventory_status.claimed_one_time_prekeys, 0);
    EXPECT_FALSE(inv_res.inventory_status.is_exhausted);

    std::atomic<bool> start_latch{false};
    std::vector<std::thread> workers;
    workers.reserve(kNumThreads);

    struct ClaimResult {
        bool success = false;
        std::string otk_fingerprint;
        std::string otk_id;
        PrekeyExhaustionState state{PrekeyExhaustionState::InventoryHealthy};
    };

    std::vector<ClaimResult> results(kNumThreads);

    for (std::size_t i = 0; i < kNumThreads; ++i) {
        workers.emplace_back([this, &dev, &start_latch, &results, i]() {
            while (!start_latch.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            auto res = prekey_mgr_->claim_device_prekey_bundle(dev.device_id);
            if (res.is_success()) {
                results[i].success = true;
                results[i].state = res.exhaustion_state;
                if (res.one_time_prekey.has_value()) {
                    results[i].otk_fingerprint = crypto::KeyFingerprint::compute_sha256(*res.one_time_prekey);
                }
                if (res.one_time_prekey_id.has_value()) {
                    results[i].otk_id = res.one_time_prekey_id->to_string();
                }
            }
        });
    }

    // Release all 50 threads simultaneously to race for the 50 prekeys
    start_latch.store(true, std::memory_order_release);

    for (auto& w : workers) {
        w.join();
    }

    // Assert: Every single thread successfully claimed a bundle
    std::set<std::string> unique_otk_fingerprints;
    std::set<std::string> unique_otk_ids;

    for (std::size_t i = 0; i < kNumThreads; ++i) {
        ASSERT_TRUE(results[i].success) << "Thread " << i << " failed to claim bundle!";
        ASSERT_FALSE(results[i].otk_fingerprint.empty()) << "Thread " << i << " did not receive an OTK!";
        ASSERT_FALSE(results[i].otk_id.empty()) << "Thread " << i << " did not receive an OTK ID!";

        unique_otk_fingerprints.insert(results[i].otk_fingerprint);
        unique_otk_ids.insert(results[i].otk_id);
    }

    // CONCURRENCY PROOF: Exactly 50 unique OTKs claimed by 50 threads. ZERO duplicates!
    EXPECT_EQ(unique_otk_fingerprints.size(), kNumThreads)
        << "Concurrency race violation: duplicate OTKs dispensed to distinct callers!";
    EXPECT_EQ(unique_otk_ids.size(), kNumThreads)
        << "Concurrency race violation: duplicate OTK IDs dispensed to distinct callers!";

    // Verify database state
    auto final_inv = prekey_mgr_->get_inventory_status(dev.device_id);
    ASSERT_TRUE(final_inv.is_success());
    EXPECT_EQ(final_inv.inventory_status.active_one_time_prekeys, 0);
    EXPECT_EQ(final_inv.inventory_status.claimed_one_time_prekeys, kNumThreads);
    EXPECT_TRUE(final_inv.inventory_status.is_exhausted);
}

// ============================================================================
// 4. Concurrent Claim vs. Replenishment Race
// ============================================================================

TEST_F(AuthPrekeyConcurrencyIntegrationTest, ConcurrentClaimVsReplenishmentRace) {
    constexpr std::size_t kInitialOtks = 10;
    constexpr std::size_t kReplenishBatches = 4;
    constexpr std::size_t kKeysPerBatch = 10;
    // Total OTKs = 10 + 40 = 50

    auto [user, _] = seed_user();
    auto bundle = generate_valid_crypto_bundle(kInitialOtks);
    auto dev = seed_device_with_crypto_keys(user.user_id, bundle);

    std::atomic<bool> stop_flag{false};
    std::atomic<int> successful_claims{0};
    std::mutex collected_keys_mu;
    std::set<std::string> claimed_keys;

    // Replenishment thread: asynchronously adds batches of keys
    std::thread replenisher([this, &user, &dev, &stop_flag]() {
        for (std::size_t b = 0; b < kReplenishBatches; ++b) {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
            auto new_otks = generate_x25519_otks(kKeysPerBatch);
            auto res = prekey_mgr_->replenish_one_time_prekeys(user.user_id, dev.device_id, dev.device_id, new_otks);
            EXPECT_TRUE(res.is_success());
        }
        stop_flag.store(true, std::memory_order_release);
    });

    // 10 concurrent claimer threads
    constexpr std::size_t kClaimerThreads = 10;
    std::vector<std::thread> claimers;
    claimers.reserve(kClaimerThreads);

    for (std::size_t t = 0; t < kClaimerThreads; ++t) {
        claimers.emplace_back([this, &dev, &stop_flag, &successful_claims, &collected_keys_mu, &claimed_keys]() {
            while (!stop_flag.load(std::memory_order_acquire) ||
                   successful_claims.load(std::memory_order_acquire) < 50) {
                auto res = prekey_mgr_->claim_device_prekey_bundle(dev.device_id);
                if (res.is_success() && res.one_time_prekey.has_value()) {
                    successful_claims.fetch_add(1, std::memory_order_relaxed);
                    std::string fp = crypto::KeyFingerprint::compute_sha256(*res.one_time_prekey);
                    {
                        std::lock_guard<std::mutex> lock(collected_keys_mu);
                        claimed_keys.insert(std::move(fp));
                    }
                } else {
                    // Small backoff if pool is momentarily empty waiting for next replenishment batch
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
                if (stop_flag.load(std::memory_order_acquire) &&
                    prekey_mgr_->get_inventory_status(dev.device_id).inventory_status.active_one_time_prekeys == 0) {
                    break;
                }
            }
        });
    }

    replenisher.join();
    for (auto& c : claimers) {
        c.join();
    }

    // All claimed keys must be mutually unique (zero double-allocation during concurrent replenishment)
    {
        std::lock_guard<std::mutex> lock(collected_keys_mu);
        EXPECT_EQ(claimed_keys.size(), static_cast<std::size_t>(successful_claims.load()));
    }
}

// ============================================================================
// 5. Deterministic Pool Depletion & Explicit Exhaustion
// ============================================================================

TEST_F(AuthPrekeyConcurrencyIntegrationTest, DeterministicPoolDepletionAndExplicitExhaustion) {
    auto [user, _] = seed_user();
    // Seed with exactly 2 OTKs
    auto bundle = generate_valid_crypto_bundle(2);
    auto dev = seed_device_with_crypto_keys(user.user_id, bundle);

    // Claim 1: Should succeed with an OTK (remaining: 1 <= 20 threshold -> LowInventory)
    auto claim1 = prekey_mgr_->claim_device_prekey_bundle(dev.device_id);
    ASSERT_TRUE(claim1.is_success());
    EXPECT_TRUE(claim1.one_time_prekey.has_value());
    EXPECT_EQ(claim1.exhaustion_state, PrekeyExhaustionState::InventoryLow);

    // Claim 2: Should succeed with an OTK, remaining: 0 <= 20 -> LowInventory
    auto claim2 = prekey_mgr_->claim_device_prekey_bundle(dev.device_id);
    ASSERT_TRUE(claim2.is_success());
    EXPECT_TRUE(claim2.one_time_prekey.has_value());
    EXPECT_EQ(claim2.exhaustion_state, PrekeyExhaustionState::InventoryLow);

    // Claim 3: Depleted pool! Must return bundle with signed prekey + identity key, but NO OTK
    auto claim3 = prekey_mgr_->claim_device_prekey_bundle(dev.device_id);
    ASSERT_TRUE(claim3.is_success());
    EXPECT_FALSE(claim3.one_time_prekey.has_value());
    EXPECT_FALSE(claim3.one_time_prekey_id.has_value());
    EXPECT_EQ(claim3.exhaustion_state, PrekeyExhaustionState::InventoryExhausted);
    EXPECT_EQ(claim3.device_id, dev.device_id);
    EXPECT_EQ(claim3.identity_key, bundle.identity_pub);
    EXPECT_EQ(claim3.signed_prekey, bundle.signed_prekey);

    // Verify audit event emission
    EXPECT_TRUE(audit_sink_->has_event_type(AuditEventType::PrekeyInventoryExhausted));

    // Also verify via gRPC AuthServiceImpl contract
    grpc::ServerContext server_ctx;
    securecloud::auth::v1::ClaimPrekeyBundleRequest grpc_req;
    grpc_req.set_device_id(dev.device_id.to_string());
    securecloud::auth::v1::ClaimPrekeyBundleResponse grpc_resp;

    auto status = auth_service_->ClaimPrekeyBundle(&server_ctx, &grpc_req, &grpc_resp);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(grpc_resp.exhaustion_state(), securecloud::auth::v1::PREKEY_EXHAUSTION_STATE_EXHAUSTED);
    EXPECT_TRUE(grpc_resp.bundle().one_time_prekey().empty());
    EXPECT_EQ(grpc_resp.bundle().device_id(), dev.device_id.to_string());
}

// ============================================================================
// 6. Revoked Device Immediate Prohibition
// ============================================================================

TEST_F(AuthPrekeyConcurrencyIntegrationTest, RevokedDeviceImmediateProhibition) {
    auto [user, _] = seed_user();
    auto bundle = generate_valid_crypto_bundle(5);
    auto dev = seed_device_with_crypto_keys(user.user_id, bundle);

    // Revoke the device
    device_repo_->revoke_device(dev.device_id, "Compromised device", std::chrono::system_clock::now());

    // 1. Claim must fail immediately
    auto claim_res = prekey_mgr_->claim_device_prekey_bundle(dev.device_id);
    EXPECT_FALSE(claim_res.is_success());
    EXPECT_TRUE(claim_res.is_device_revoked());

    // gRPC claim must return PERMISSION_DENIED
    grpc::ServerContext s_ctx;
    securecloud::auth::v1::ClaimPrekeyBundleRequest c_req;
    c_req.set_device_id(dev.device_id.to_string());
    securecloud::auth::v1::ClaimPrekeyBundleResponse c_resp;
    auto g_status = auth_service_->ClaimPrekeyBundle(&s_ctx, &c_req, &c_resp);
    EXPECT_EQ(g_status.error_code(), grpc::StatusCode::PERMISSION_DENIED);

    // 2. Replenishment must fail immediately
    auto new_otks = generate_x25519_otks(5);
    auto replen_res = prekey_mgr_->replenish_one_time_prekeys(user.user_id, dev.device_id, dev.device_id, new_otks);
    EXPECT_FALSE(replen_res.is_success());
    EXPECT_TRUE(replen_res.is_device_revoked());
}

// ============================================================================
// 7. Inventory Health & Age Metrics Across Reconnects
// ============================================================================

TEST_F(AuthPrekeyConcurrencyIntegrationTest, InventoryHealthAndAgeMetrics) {
    auto [user, _] = seed_user();
    auto bundle = generate_valid_crypto_bundle(25);
    auto dev = seed_device_with_crypto_keys(user.user_id, bundle);

    // Initial state: 25 active, 0 claimed, threshold 20 -> Healthy
    auto res1 = prekey_mgr_->get_inventory_status(dev.device_id);
    ASSERT_TRUE(res1.is_success());
    EXPECT_EQ(res1.inventory_status.active_one_time_prekeys, 25);
    EXPECT_EQ(res1.inventory_status.claimed_one_time_prekeys, 0);
    EXPECT_EQ(res1.inventory_status.low_inventory_threshold, 20);
    EXPECT_FALSE(res1.inventory_status.is_low_inventory);
    EXPECT_FALSE(res1.inventory_status.is_exhausted);
    EXPECT_FALSE(res1.inventory_status.signed_prekey_needs_rotation);

    // Claim 10 prekeys -> 15 active remaining -> LowInventory triggered
    for (int i = 0; i < 10; ++i) {
        auto c = prekey_mgr_->claim_device_prekey_bundle(dev.device_id);
        ASSERT_TRUE(c.is_success());
    }

    auto res2 = prekey_mgr_->get_inventory_status(dev.device_id);
    ASSERT_TRUE(res2.is_success());
    EXPECT_EQ(res2.inventory_status.active_one_time_prekeys, 15);
    EXPECT_EQ(res2.inventory_status.claimed_one_time_prekeys, 10);
    EXPECT_TRUE(res2.inventory_status.is_low_inventory);
    EXPECT_FALSE(res2.inventory_status.is_exhausted);

    // Verify low inventory audit event
    EXPECT_TRUE(audit_sink_->has_event_type(AuditEventType::PrekeyInventoryLow));

    // Simulate database reconnect with fresh repository instance
    auto fresh_repo = std::make_shared<repository::PostgresDevicePublicKeyRepository>(*pool_);
    auto fresh_mgr = std::make_shared<service::PrekeyManager>(device_repo_, fresh_repo, audit_publisher_);

    auto res_reconnect = fresh_mgr->get_inventory_status(dev.device_id);
    ASSERT_TRUE(res_reconnect.is_success());
    EXPECT_EQ(res_reconnect.inventory_status.active_one_time_prekeys, 15);
    EXPECT_EQ(res_reconnect.inventory_status.claimed_one_time_prekeys, 10);
    EXPECT_TRUE(res_reconnect.inventory_status.is_low_inventory);
    EXPECT_GE(res_reconnect.inventory_status.signed_prekey_age_seconds, 0);
}

} // namespace securecloud::auth::integration::test
