#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_public_key_repository.hpp"
#include "auth/repository/exceptions.hpp"

#include <algorithm>
#include <gtest/gtest.h>
#include <map>
#include <mutex>
#include <vector>

namespace securecloud::auth::repository::test {
namespace {

using domain::DevicePublicKeyEntity;
using domain::KeyStatus;
using domain::KeyType;
using domain::PrekeyBundle;
using domain::Uuid;

class InMemoryDevicePublicKeyRepository : public IDevicePublicKeyRepository {
  public:
    void store_public_key(const DevicePublicKeyEntity& key) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (keys_.find(key.key_id) != keys_.end()) {
            throw DuplicateEntityException("Key already exists: " + key.key_id.to_string());
        }
        keys_[key.key_id] = key;
    }

    void store_public_key(const DevicePublicKeyEntity& key, pqxx::transaction_base& /*tx*/) override {
        store_public_key(key);
    }

    [[nodiscard]] std::optional<DevicePublicKeyEntity> find_by_id(const Uuid& key_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = keys_.find(key_id);
        if (it == keys_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    [[nodiscard]] std::optional<DevicePublicKeyEntity> find_by_id(const Uuid& key_id,
                                                                  pqxx::transaction_base& /*tx*/) override {
        return find_by_id(key_id);
    }

    [[nodiscard]] std::vector<DevicePublicKeyEntity> list_active_keys_by_device_id(const Uuid& device_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DevicePublicKeyEntity> result;
        for (const auto& [_, k] : keys_) {
            if (k.device_id == device_id && k.key_status == KeyStatus::Active) {
                result.push_back(k);
            }
        }
        std::sort(result.begin(), result.end(),
                  [](const auto& a, const auto& b) { return a.created_at < b.created_at; });
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
            throw EntityNotFoundException("Key not found: " + old_key_id.to_string());
        }
        if (it->second.key_status != KeyStatus::Active) {
            throw InvalidEntityStateException("Cannot replace inactive key");
        }
        keys_[new_key.key_id] = new_key;
        it->second.key_status = KeyStatus::Replaced;
        it->second.replaced_by_key_id = new_key.key_id;
    }

    void replace_key(const Uuid& old_key_id, const DevicePublicKeyEntity& new_key,
                     pqxx::transaction_base& /*tx*/) override {
        replace_key(old_key_id, new_key);
    }

    void revoke_all_device_keys(const Uuid& device_id, domain::time_point revoked_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [_, k] : keys_) {
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

    [[nodiscard]] std::optional<DevicePublicKeyEntity> claim_one_time_prekey(const Uuid& device_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        DevicePublicKeyEntity* oldest = nullptr;
        for (auto& [_, k] : keys_) {
            if (k.device_id == device_id && k.key_type == KeyType::OneTimePrekey && k.key_status == KeyStatus::Active) {
                if (!oldest || k.created_at < oldest->created_at) {
                    oldest = &k;
                }
            }
        }
        if (!oldest) {
            return std::nullopt;
        }
        oldest->key_status = KeyStatus::Claimed;
        return *oldest;
    }

    [[nodiscard]] std::optional<DevicePublicKeyEntity> claim_one_time_prekey(const Uuid& device_id,
                                                                             pqxx::transaction_base& /*tx*/) override {
        return claim_one_time_prekey(device_id);
    }

    [[nodiscard]] int32_t count_active_one_time_prekeys(const Uuid& device_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        int32_t count = 0;
        for (const auto& [_, k] : keys_) {
            if (k.device_id == device_id && k.key_type == KeyType::OneTimePrekey && k.key_status == KeyStatus::Active) {
                count++;
            }
        }
        return count;
    }

    [[nodiscard]] int32_t count_active_one_time_prekeys(const Uuid& device_id,
                                                        pqxx::transaction_base& /*tx*/) override {
        return count_active_one_time_prekeys(device_id);
    }

    [[nodiscard]] std::optional<DevicePublicKeyEntity> find_active_identity_key(const Uuid& device_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        DevicePublicKeyEntity* newest = nullptr;
        for (auto& [_, k] : keys_) {
            if (k.device_id == device_id && k.key_type == KeyType::IdentitySigning &&
                k.key_status == KeyStatus::Active) {
                if (!newest || k.created_at > newest->created_at) {
                    newest = &k;
                }
            }
        }
        if (!newest) {
            return std::nullopt;
        }
        return *newest;
    }

    [[nodiscard]] std::optional<DevicePublicKeyEntity>
    find_active_identity_key(const Uuid& device_id, pqxx::transaction_base& /*tx*/) override {
        return find_active_identity_key(device_id);
    }

    [[nodiscard]] std::optional<DevicePublicKeyEntity> find_active_signed_prekey(const Uuid& device_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        DevicePublicKeyEntity* newest = nullptr;
        for (auto& [_, k] : keys_) {
            if (k.device_id == device_id && k.key_type == KeyType::SignedPrekey && k.key_status == KeyStatus::Active) {
                if (!newest || k.created_at > newest->created_at) {
                    newest = &k;
                }
            }
        }
        if (!newest) {
            return std::nullopt;
        }
        return *newest;
    }

    [[nodiscard]] std::optional<DevicePublicKeyEntity>
    find_active_signed_prekey(const Uuid& device_id, pqxx::transaction_base& /*tx*/) override {
        return find_active_signed_prekey(device_id);
    }

    void store_one_time_prekeys(const Uuid& device_id, const std::vector<std::vector<uint8_t>>& keys) override {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::system_clock::now();
        for (const auto& key_bytes : keys) {
            DevicePublicKeyEntity otk{
                .key_id = Uuid::generate_v7(),
                .device_id = device_id,
                .key_type = KeyType::OneTimePrekey,
                .public_key = key_bytes,
                .key_status = KeyStatus::Active,
                .created_at = now,
                .revoked_at = std::nullopt,
                .replaced_by_key_id = std::nullopt,
                .signature = std::nullopt,
            };
            keys_[otk.key_id] = otk;
        }
    }

    void store_one_time_prekeys(const Uuid& device_id, const std::vector<std::vector<uint8_t>>& keys,
                                pqxx::transaction_base& /*tx*/) override {
        store_one_time_prekeys(device_id, keys);
    }

  private:
    std::mutex mutex_;
    std::map<Uuid, DevicePublicKeyEntity> keys_;
};

class DevicePublicKeyRepositoryTest : public ::testing::Test {
  protected:
    InMemoryDevicePublicKeyRepository repo_;
    Uuid device_id_ = Uuid::generate_v7();
    const domain::time_point now_ = std::chrono::system_clock::now();
};

TEST_F(DevicePublicKeyRepositoryTest, KeyStatusClaimedEnumConversion) {
    EXPECT_EQ(domain::to_string(KeyStatus::Claimed), "Claimed");
    EXPECT_EQ(domain::parse_enum<KeyStatus>("Claimed"), KeyStatus::Claimed);
    EXPECT_EQ(domain::parse_enum<KeyStatus>("CLAIMED"), KeyStatus::Claimed);
    EXPECT_EQ(domain::parse_enum<KeyStatus>("claimed"), KeyStatus::Claimed);
}

TEST_F(DevicePublicKeyRepositoryTest, StoreAndFindActiveIdentityKey) {
    EXPECT_FALSE(repo_.find_active_identity_key(device_id_).has_value());

    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = std::vector<uint8_t>(32, 0x01),
        .key_status = KeyStatus::Active,
        .created_at = now_,
    };
    repo_.store_public_key(id_key);

    auto found = repo_.find_active_identity_key(device_id_);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->key_id, id_key.key_id);
    EXPECT_EQ(found->key_type, KeyType::IdentitySigning);
    EXPECT_EQ(found->public_key, id_key.public_key);
}

TEST_F(DevicePublicKeyRepositoryTest, StoreAndFindActiveSignedPrekeyWithSignature) {
    EXPECT_FALSE(repo_.find_active_signed_prekey(device_id_).has_value());

    std::vector<uint8_t> sig(64, 0xAA);
    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = std::vector<uint8_t>(32, 0x02),
        .key_status = KeyStatus::Active,
        .created_at = now_,
        .signature = sig,
    };
    repo_.store_public_key(spk);

    auto found = repo_.find_active_signed_prekey(device_id_);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->key_id, spk.key_id);
    EXPECT_EQ(found->key_type, KeyType::SignedPrekey);
    ASSERT_TRUE(found->signature.has_value());
    EXPECT_EQ(*found->signature, sig);
}

TEST_F(DevicePublicKeyRepositoryTest, ClaimOneTimePrekeyLifecycleAndDepletion) {
    EXPECT_EQ(repo_.count_active_one_time_prekeys(device_id_), 0);
    EXPECT_FALSE(repo_.claim_one_time_prekey(device_id_).has_value());

    // 1. Batch insert 3 OTKs
    std::vector<std::vector<uint8_t>> otks = {
        std::vector<uint8_t>(32, 0x11),
        std::vector<uint8_t>(32, 0x22),
        std::vector<uint8_t>(32, 0x33),
    };
    repo_.store_one_time_prekeys(device_id_, otks);
    EXPECT_EQ(repo_.count_active_one_time_prekeys(device_id_), 3);

    // 2. Claim first OTK
    auto claimed1 = repo_.claim_one_time_prekey(device_id_);
    ASSERT_TRUE(claimed1.has_value());
    EXPECT_EQ(claimed1->key_status, KeyStatus::Claimed);
    EXPECT_EQ(repo_.count_active_one_time_prekeys(device_id_), 2);

    // Verify in repo that claimed1 is indeed Claimed
    auto check1 = repo_.find_by_id(claimed1->key_id);
    ASSERT_TRUE(check1.has_value());
    EXPECT_EQ(check1->key_status, KeyStatus::Claimed);

    // 3. Claim second OTK
    auto claimed2 = repo_.claim_one_time_prekey(device_id_);
    ASSERT_TRUE(claimed2.has_value());
    EXPECT_NE(claimed2->key_id, claimed1->key_id);
    EXPECT_EQ(repo_.count_active_one_time_prekeys(device_id_), 1);

    // 4. Claim third OTK
    auto claimed3 = repo_.claim_one_time_prekey(device_id_);
    ASSERT_TRUE(claimed3.has_value());
    EXPECT_NE(claimed3->key_id, claimed2->key_id);
    EXPECT_EQ(repo_.count_active_one_time_prekeys(device_id_), 0);

    // 5. Pool is depleted -> returns nullopt
    auto depleted = repo_.claim_one_time_prekey(device_id_);
    EXPECT_FALSE(depleted.has_value());
    EXPECT_EQ(repo_.count_active_one_time_prekeys(device_id_), 0);

    // 6. Replenish pool with 2 more OTKs
    std::vector<std::vector<uint8_t>> replenishment = {
        std::vector<uint8_t>(32, 0x44),
        std::vector<uint8_t>(32, 0x55),
    };
    repo_.store_one_time_prekeys(device_id_, replenishment);
    EXPECT_EQ(repo_.count_active_one_time_prekeys(device_id_), 2);

    // 7. Claim succeeds again
    auto claimed4 = repo_.claim_one_time_prekey(device_id_);
    ASSERT_TRUE(claimed4.has_value());
    EXPECT_EQ(claimed4->public_key, replenishment[0]);
    EXPECT_EQ(repo_.count_active_one_time_prekeys(device_id_), 1);
}

TEST_F(DevicePublicKeyRepositoryTest, SignedPrekeyRotationMarksOldKeyReplaced) {
    DevicePublicKeyEntity old_spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = std::vector<uint8_t>(32, 0xAA),
        .key_status = KeyStatus::Active,
        .created_at = now_ - std::chrono::hours(24),
    };
    repo_.store_public_key(old_spk);

    DevicePublicKeyEntity new_spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = std::vector<uint8_t>(32, 0xBB),
        .key_status = KeyStatus::Active,
        .created_at = now_,
    };
    repo_.replace_key(old_spk.key_id, new_spk);

    // Verify old key is Replaced with replaced_by_key_id pointing to new key
    auto old_check = repo_.find_by_id(old_spk.key_id);
    ASSERT_TRUE(old_check.has_value());
    EXPECT_EQ(old_check->key_status, KeyStatus::Replaced);
    EXPECT_EQ(old_check->replaced_by_key_id, new_spk.key_id);

    // Active signed prekey is now new_spk
    auto active_spk = repo_.find_active_signed_prekey(device_id_);
    ASSERT_TRUE(active_spk.has_value());
    EXPECT_EQ(active_spk->key_id, new_spk.key_id);
}

TEST_F(DevicePublicKeyRepositoryTest, RevokeAllDeviceKeysRevokesActiveKeys) {
    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = std::vector<uint8_t>(32, 0x01),
        .key_status = KeyStatus::Active,
        .created_at = now_,
    };
    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = std::vector<uint8_t>(32, 0x02),
        .key_status = KeyStatus::Active,
        .created_at = now_,
    };
    repo_.store_public_key(id_key);
    repo_.store_public_key(spk);
    repo_.store_one_time_prekeys(device_id_, {std::vector<uint8_t>(32, 0x03)});

    EXPECT_TRUE(repo_.find_active_identity_key(device_id_).has_value());
    EXPECT_TRUE(repo_.find_active_signed_prekey(device_id_).has_value());
    EXPECT_EQ(repo_.count_active_one_time_prekeys(device_id_), 1);

    repo_.revoke_all_device_keys(device_id_, now_);

    EXPECT_FALSE(repo_.find_active_identity_key(device_id_).has_value());
    EXPECT_FALSE(repo_.find_active_signed_prekey(device_id_).has_value());
    EXPECT_EQ(repo_.count_active_one_time_prekeys(device_id_), 0);
    EXPECT_FALSE(repo_.claim_one_time_prekey(device_id_).has_value());
}

} // namespace
} // namespace securecloud::auth::repository::test
