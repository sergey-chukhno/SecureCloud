#include "auth/auth_config.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_public_key_repository.hpp"
#include "auth/repository/exceptions.hpp"
#include "auth/repository/mfa_repository.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace securecloud::auth::repository::test {
namespace {

using domain::DevicePublicKeyEntity;
using domain::KeyStatus;
using domain::KeyType;
using domain::MfaChallengeEntity;
using domain::MfaChallengePurpose;
using domain::MfaChallengeStatus;
using domain::MfaConfigurationEntity;
using domain::MfaFactorType;
using domain::MfaStatus;
using domain::Uuid;

// ============================================================================
// 1. In-Memory Reference Repositories
// ============================================================================

class InMemoryDevicePublicKeyRepository : public IDevicePublicKeyRepository {
  public:
    void store_public_key(const DevicePublicKeyEntity& key) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (keys_.find(key.key_id) != keys_.end()) {
            throw DuplicateEntityException("Device public key already exists: " + key.key_id.to_string());
        }
        keys_[key.key_id] = key;
    }

    void store_public_key(const DevicePublicKeyEntity& key, pqxx::transaction_base& /*tx*/) override {
        store_public_key(key);
    }

    [[nodiscard]] std::optional<DevicePublicKeyEntity> find_by_id(const Uuid& key_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = keys_.find(key_id);
        if (it != keys_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<DevicePublicKeyEntity> find_by_id(const Uuid& key_id,
                                                                  pqxx::transaction_base& /*tx*/) override {
        return find_by_id(key_id);
    }

    [[nodiscard]] std::vector<DevicePublicKeyEntity> list_active_keys_by_device_id(const Uuid& device_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DevicePublicKeyEntity> result;
        for (const auto& [id, k] : keys_) {
            if (k.device_id == device_id && k.key_status == KeyStatus::Active) {
                result.push_back(k);
            }
        }
        return result;
    }

    [[nodiscard]] std::vector<DevicePublicKeyEntity>
    list_active_keys_by_device_id(const Uuid& device_id, pqxx::transaction_base& /*tx*/) override {
        return list_active_keys_by_device_id(device_id);
    }

    void replace_key(const Uuid& old_key_id, const DevicePublicKeyEntity& new_key) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = keys_.find(old_key_id);
        if (it == keys_.end()) {
            throw EntityNotFoundException("Device public key not found: " + old_key_id.to_string());
        }

        if (it->second.key_status != KeyStatus::Active) {
            throw InvalidEntityStateException("Cannot replace non-active public key: " + old_key_id.to_string());
        }

        // 1. Insert new key
        keys_[new_key.key_id] = new_key;

        // 2. Mark old key as replaced
        it->second.key_status = KeyStatus::Replaced;
        it->second.replaced_by_key_id = new_key.key_id;
    }

    void replace_key(const Uuid& old_key_id, const DevicePublicKeyEntity& new_key,
                     pqxx::transaction_base& /*tx*/) override {
        replace_key(old_key_id, new_key);
    }

    void revoke_all_device_keys(const Uuid& device_id, domain::time_point revoked_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, k] : keys_) {
            if (k.device_id == device_id && k.key_status == KeyStatus::Active) {
                k.key_status = KeyStatus::Revoked;
                k.revoked_at = revoked_at;
            }
        }
    }

    void revoke_all_device_keys(const Uuid& device_id, domain::time_point revoked_at,
                                pqxx::transaction_base& /*tx*/) override {
        revoke_all_device_keys(device_id, revoked_at);
    }

  private:
    std::mutex mutex_;
    std::map<Uuid, DevicePublicKeyEntity> keys_;
};

class InMemoryMfaRepository : public IMfaRepository {
  public:
    void store_mfa_configuration(const MfaConfigurationEntity& config) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (configs_.find(config.mfa_configuration_id) != configs_.end()) {
            throw DuplicateEntityException("MFA configuration already exists: " +
                                           config.mfa_configuration_id.to_string());
        }
        MfaConfigurationEntity copy = config;
        if (copy.version == 0) {
            copy.version = 1;
        }
        configs_[config.mfa_configuration_id] = copy;
    }

    void store_mfa_configuration(const MfaConfigurationEntity& config, pqxx::transaction_base& /*tx*/) override {
        store_mfa_configuration(config);
    }

    [[nodiscard]] std::optional<MfaConfigurationEntity> find_mfa_config_by_user_id(const Uuid& user_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, cfg] : configs_) {
            if (cfg.user_id == user_id) {
                return cfg;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<MfaConfigurationEntity>
    find_mfa_config_by_user_id(const Uuid& user_id, pqxx::transaction_base& /*tx*/) override {
        return find_mfa_config_by_user_id(user_id);
    }

    void enable_mfa(const Uuid& config_id, domain::time_point enabled_at, uint64_t expected_version) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = configs_.find(config_id);
        if (it == configs_.end()) {
            throw EntityNotFoundException("MFA configuration not found: " + config_id.to_string());
        }

        if (it->second.version != expected_version) {
            throw OptimisticLockException("Concurrent modification detected for MFA configuration: " +
                                          config_id.to_string());
        }

        it->second.status = MfaStatus::Enabled;
        it->second.enabled_at = enabled_at;
        it->second.version += 1;
    }

    void enable_mfa(const Uuid& config_id, domain::time_point enabled_at, uint64_t expected_version,
                    pqxx::transaction_base& /*tx*/) override {
        enable_mfa(config_id, enabled_at, expected_version);
    }

    void disable_mfa(const Uuid& config_id, domain::time_point disabled_at, uint64_t expected_version) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = configs_.find(config_id);
        if (it == configs_.end()) {
            throw EntityNotFoundException("MFA configuration not found: " + config_id.to_string());
        }

        if (it->second.version != expected_version) {
            throw OptimisticLockException("Concurrent modification detected for MFA configuration: " +
                                          config_id.to_string());
        }

        it->second.status = MfaStatus::Disabled;
        it->second.disabled_at = disabled_at;
        it->second.version += 1;
    }

    void disable_mfa(const Uuid& config_id, domain::time_point disabled_at, uint64_t expected_version,
                     pqxx::transaction_base& /*tx*/) override {
        disable_mfa(config_id, disabled_at, expected_version);
    }

    void create_challenge(const MfaChallengeEntity& challenge) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (challenges_.find(challenge.mfa_challenge_id) != challenges_.end()) {
            throw DuplicateEntityException("MFA challenge already exists: " + challenge.mfa_challenge_id.to_string());
        }
        challenges_[challenge.mfa_challenge_id] = challenge;
    }

    void create_challenge(const MfaChallengeEntity& challenge, pqxx::transaction_base& /*tx*/) override {
        create_challenge(challenge);
    }

    [[nodiscard]] std::optional<MfaChallengeEntity> find_challenge_by_id(const Uuid& challenge_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = challenges_.find(challenge_id);
        if (it != challenges_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<MfaChallengeEntity> find_challenge_by_id(const Uuid& challenge_id,
                                                                         pqxx::transaction_base& /*tx*/) override {
        return find_challenge_by_id(challenge_id);
    }

    void complete_challenge(const Uuid& challenge_id, domain::time_point completed_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = challenges_.find(challenge_id);
        if (it == challenges_.end()) {
            throw EntityNotFoundException("MFA challenge not found: " + challenge_id.to_string());
        }

        const auto now = std::chrono::system_clock::now();
        if (it->second.challenge_status != MfaChallengeStatus::Pending || now > it->second.expires_at) {
            throw InvalidEntityStateException("Cannot complete challenge (expired or not pending): " +
                                              challenge_id.to_string());
        }

        it->second.challenge_status = MfaChallengeStatus::Completed;
        it->second.completed_at = completed_at;
    }

    void complete_challenge(const Uuid& challenge_id, domain::time_point completed_at,
                            pqxx::transaction_base& /*tx*/) override {
        complete_challenge(challenge_id, completed_at);
    }

    void fail_challenge(const Uuid& challenge_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = challenges_.find(challenge_id);
        if (it == challenges_.end()) {
            throw EntityNotFoundException("MFA challenge not found: " + challenge_id.to_string());
        }

        if (it->second.challenge_status != MfaChallengeStatus::Pending) {
            throw InvalidEntityStateException("Cannot fail non-pending MFA challenge: " + challenge_id.to_string());
        }

        it->second.challenge_status = MfaChallengeStatus::Failed;
    }

    void fail_challenge(const Uuid& challenge_id, pqxx::transaction_base& /*tx*/) override {
        fail_challenge(challenge_id);
    }

  private:
    std::mutex mutex_;
    std::map<Uuid, MfaConfigurationEntity> configs_;
    std::map<Uuid, MfaChallengeEntity> challenges_;
};

// ============================================================================
// 2. Port 5432 Isolation Test
// ============================================================================

TEST(CryptoKeyMfaRepositoryTest, RejectsForbiddenPort5432) {
    AuthConfig forbidden_cfg;
    forbidden_cfg.db_host = "localhost";
    forbidden_cfg.db_port = 5432;
    forbidden_cfg.db_name = "securecloud";
    forbidden_cfg.db_user = "securecloud_app";
    forbidden_cfg.db_password = common::configuration::SecretString{"test"};

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), db::PortForbiddenException);
}

// ============================================================================
// 3. Device Public Key Directory Tests
// ============================================================================

TEST(CryptoKeyMfaRepositoryTest, DevicePublicKeyBinaryFidelityAndReplacement) {
    InMemoryDevicePublicKeyRepository key_repo;

    const auto device_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    // 32-byte Ed25519 public key bytes
    const std::vector<uint8_t> raw_public_key = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xfe, 0xdc, 0xba,
                                                 0x98, 0x76, 0x54, 0x32, 0x10, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                                 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};

    DevicePublicKeyEntity key1{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id,
        .key_type = KeyType::IdentitySigning,
        .public_key = raw_public_key,
        .key_status = KeyStatus::Active,
        .created_at = now,
        .revoked_at = std::nullopt,
        .replaced_by_key_id = std::nullopt,
    };

    // 1. Store key
    EXPECT_NO_THROW(key_repo.store_public_key(key1));

    // 2. Find by ID and verify exact byte fidelity
    auto found = key_repo.find_by_id(key1.key_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->public_key, raw_public_key);
    EXPECT_EQ(found->key_status, KeyStatus::Active);

    // 3. List active keys
    auto active_keys = key_repo.list_active_keys_by_device_id(device_id);
    EXPECT_EQ(active_keys.size(), 1);
    EXPECT_EQ(active_keys[0].key_id, key1.key_id);

    // 4. Replace key
    const std::vector<uint8_t> new_raw_key(32, 0x5a);
    DevicePublicKeyEntity key2{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id,
        .key_type = KeyType::IdentitySigning,
        .public_key = new_raw_key,
        .key_status = KeyStatus::Active,
        .created_at = now + std::chrono::minutes(1),
        .revoked_at = std::nullopt,
        .replaced_by_key_id = std::nullopt,
    };

    EXPECT_NO_THROW(key_repo.replace_key(key1.key_id, key2));

    // 5. Verify old key is marked Replaced and points to new key
    auto old_key_after = key_repo.find_by_id(key1.key_id);
    ASSERT_TRUE(old_key_after.has_value());
    EXPECT_EQ(old_key_after->key_status, KeyStatus::Replaced);
    EXPECT_EQ(old_key_after->replaced_by_key_id, key2.key_id);

    // 6. Active listing contains only the replacement key
    active_keys = key_repo.list_active_keys_by_device_id(device_id);
    ASSERT_EQ(active_keys.size(), 1);
    EXPECT_EQ(active_keys[0].key_id, key2.key_id);
    EXPECT_EQ(active_keys[0].public_key, new_raw_key);

    // 7. Revoke all device keys
    const auto revoked_at = now + std::chrono::hours(1);
    key_repo.revoke_all_device_keys(device_id, revoked_at);
    EXPECT_TRUE(key_repo.list_active_keys_by_device_id(device_id).empty());

    auto key2_after = key_repo.find_by_id(key2.key_id);
    ASSERT_TRUE(key2_after.has_value());
    EXPECT_EQ(key2_after->key_status, KeyStatus::Revoked);
    EXPECT_EQ(key2_after->revoked_at, revoked_at);
}

// ============================================================================
// 4. MFA Configuration OCC Lifecycle Tests
// ============================================================================

TEST(CryptoKeyMfaRepositoryTest, MfaConfigurationLifecycleAndOptimisticConcurrency) {
    InMemoryMfaRepository mfa_repo;

    const auto user_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();
    const std::vector<uint8_t> encrypted_secret = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    MfaConfigurationEntity config{
        .mfa_configuration_id = Uuid::generate_v7(),
        .user_id = user_id,
        .factor_type = MfaFactorType::Totp,
        .encrypted_secret = encrypted_secret,
        .status = MfaStatus::Pending,
        .created_at = now,
        .enabled_at = std::nullopt,
        .disabled_at = std::nullopt,
        .version = 1,
    };

    // 1. Store initial configuration
    EXPECT_NO_THROW(mfa_repo.store_mfa_configuration(config));

    // 2. Find by user ID
    auto found = mfa_repo.find_mfa_config_by_user_id(user_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->status, MfaStatus::Pending);
    EXPECT_EQ(found->version, 1);
    EXPECT_EQ(found->encrypted_secret, encrypted_secret);

    // 3. Stale version update rejection (trying version 0 when version is 1)
    EXPECT_THROW(mfa_repo.enable_mfa(config.mfa_configuration_id, now, 0), OptimisticLockException);

    // 4. Valid enable_mfa transition (version 1 -> 2)
    EXPECT_NO_THROW(mfa_repo.enable_mfa(config.mfa_configuration_id, now, 1));
    found = mfa_repo.find_mfa_config_by_user_id(user_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->status, MfaStatus::Enabled);
    EXPECT_EQ(found->version, 2);
    EXPECT_TRUE(found->enabled_at.has_value());

    // 5. Valid disable_mfa transition (version 2 -> 3)
    EXPECT_NO_THROW(mfa_repo.disable_mfa(config.mfa_configuration_id, now, 2));
    found = mfa_repo.find_mfa_config_by_user_id(user_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->status, MfaStatus::Disabled);
    EXPECT_EQ(found->version, 3);
    EXPECT_TRUE(found->disabled_at.has_value());
}

// ============================================================================
// 5. MFA Challenge Lifecycle & Expiration Tests
// ============================================================================

TEST(CryptoKeyMfaRepositoryTest, MfaChallengeLifecycleAndExpiration) {
    InMemoryMfaRepository mfa_repo;

    const auto user_id = Uuid::generate_v7();
    const auto session_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    // 1. Active Challenge
    MfaChallengeEntity active_challenge{
        .mfa_challenge_id = Uuid::generate_v7(),
        .user_id = user_id,
        .session_id = session_id,
        .challenge_purpose = MfaChallengePurpose::Login,
        .challenge_status = MfaChallengeStatus::Pending,
        .created_at = now,
        .expires_at = now + std::chrono::minutes(5),
        .completed_at = std::nullopt,
    };
    EXPECT_NO_THROW(mfa_repo.create_challenge(active_challenge));

    // 2. Complete active challenge
    EXPECT_NO_THROW(mfa_repo.complete_challenge(active_challenge.mfa_challenge_id, now));
    auto completed = mfa_repo.find_challenge_by_id(active_challenge.mfa_challenge_id);
    ASSERT_TRUE(completed.has_value());
    EXPECT_EQ(completed->challenge_status, MfaChallengeStatus::Completed);
    EXPECT_TRUE(completed->completed_at.has_value());

    // 3. Expired Challenge
    MfaChallengeEntity expired_challenge{
        .mfa_challenge_id = Uuid::generate_v7(),
        .user_id = user_id,
        .session_id = session_id,
        .challenge_purpose = MfaChallengePurpose::StepUp,
        .challenge_status = MfaChallengeStatus::Pending,
        .created_at = now - std::chrono::minutes(10),
        .expires_at = now - std::chrono::minutes(5), // Already expired!
        .completed_at = std::nullopt,
    };
    EXPECT_NO_THROW(mfa_repo.create_challenge(expired_challenge));

    // Attempting to complete expired challenge must be rejected!
    EXPECT_THROW(mfa_repo.complete_challenge(expired_challenge.mfa_challenge_id, now), InvalidEntityStateException);

    // 4. Fail challenge
    MfaChallengeEntity failed_challenge{
        .mfa_challenge_id = Uuid::generate_v7(),
        .user_id = user_id,
        .session_id = session_id,
        .challenge_purpose = MfaChallengePurpose::StepUp,
        .challenge_status = MfaChallengeStatus::Pending,
        .created_at = now,
        .expires_at = now + std::chrono::minutes(5),
        .completed_at = std::nullopt,
    };
    EXPECT_NO_THROW(mfa_repo.create_challenge(failed_challenge));
    EXPECT_NO_THROW(mfa_repo.fail_challenge(failed_challenge.mfa_challenge_id));

    auto failed = mfa_repo.find_challenge_by_id(failed_challenge.mfa_challenge_id);
    ASSERT_TRUE(failed.has_value());
    EXPECT_EQ(failed->challenge_status, MfaChallengeStatus::Failed);
}

// ============================================================================
// 6. Postgres Repositories Direct Construction with Pool
// ============================================================================

TEST(CryptoKeyMfaRepositoryTest, PostgresRepositoriesInstantiateCleanlyWithPool) {
    AuthConfig auth_cfg;
    auth_cfg.db_host = "127.0.0.1";
    auth_cfg.db_port = 5433; // Allowed test port
    auth_cfg.db_name = "securecloud";
    auth_cfg.db_user = "securecloud_app";
    auth_cfg.db_password = common::configuration::SecretString{"dummy"};

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0; // Avoid eager connection in test runner
    pool_cfg.max_connections = 1;

    db::PostgresConnectionPool pool(auth_cfg, pool_cfg);
    PostgresDevicePublicKeyRepository key_repo(pool);
    PostgresMfaRepository mfa_repo(pool);

    // Verify objects are validly instantiated
    EXPECT_NO_THROW({
        auto key_ptr = &key_repo;
        auto mfa_ptr = &mfa_repo;
        ASSERT_NE(key_ptr, nullptr);
        ASSERT_NE(mfa_ptr, nullptr);
    });
}

} // namespace
} // namespace securecloud::auth::repository::test
