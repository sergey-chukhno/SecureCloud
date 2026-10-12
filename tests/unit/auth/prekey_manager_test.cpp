#include "auth/crypto/key_fingerprint.hpp"
#include "auth/domain/audit_event.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/repository/device_public_key_repository.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/prekey_manager.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <openssl/evp.h>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

using domain::AuditEvent;
using domain::AuditEventType;
using domain::DeviceEntity;
using domain::DevicePublicKeyEntity;
using domain::DeviceStatus;
using domain::KeyStatus;
using domain::KeyType;
using domain::PrekeyExhaustionState;
using domain::Uuid;

// ============================================================================
// Cryptographic Helpers
// ============================================================================

struct CryptoTestMaterial {
    std::vector<uint8_t> identity_pub;
    std::vector<uint8_t> signed_prekey;
    std::vector<uint8_t> signature;
    std::vector<std::vector<uint8_t>> one_time_prekeys;
};

CryptoTestMaterial generate_test_crypto_material(std::size_t otk_count = 3) {
    CryptoTestMaterial mat;

    // 1. Ed25519 Identity Key
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY* id_pkey = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &id_pkey);
    EVP_PKEY_CTX_free(ctx);

    size_t id_len = 32;
    mat.identity_pub.resize(id_len);
    EVP_PKEY_get_raw_public_key(id_pkey, mat.identity_pub.data(), &id_len);

    // 2. X25519 Signed Prekey
    EVP_PKEY_CTX* spk_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* spk_pkey = nullptr;
    EVP_PKEY_keygen_init(spk_ctx);
    EVP_PKEY_keygen(spk_ctx, &spk_pkey);
    EVP_PKEY_CTX_free(spk_ctx);

    size_t spk_len = 32;
    mat.signed_prekey.resize(spk_len);
    EVP_PKEY_get_raw_public_key(spk_pkey, mat.signed_prekey.data(), &spk_len);
    EVP_PKEY_free(spk_pkey);

    // 3. Ed25519 Signature over Signed Prekey
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, id_pkey);
    size_t sig_len = 64;
    mat.signature.resize(sig_len);
    EVP_DigestSign(md_ctx, mat.signature.data(), &sig_len, mat.signed_prekey.data(), mat.signed_prekey.size());
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(id_pkey);

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
        mat.one_time_prekeys.push_back(std::move(otk));
    }

    return mat;
}

// ============================================================================
// Mocks
// ============================================================================

class MockDeviceRepository : public repository::IDeviceRepository {
  public:
    MOCK_METHOD(void, register_device, (const DeviceEntity& device), (override));
    MOCK_METHOD(void, register_device, (const DeviceEntity& device, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::optional<DeviceEntity>, find_by_id, (const Uuid& device_id), (override));
    MOCK_METHOD(std::optional<DeviceEntity>, find_by_id, (const Uuid& device_id, pqxx::transaction_base& tx),
                (override));

    MOCK_METHOD(std::vector<DeviceEntity>, list_active_by_user_id, (const Uuid& user_id), (override));
    MOCK_METHOD(std::vector<DeviceEntity>, list_active_by_user_id, (const Uuid& user_id, pqxx::transaction_base& tx),
                (override));

    MOCK_METHOD(std::vector<DeviceEntity>, list_all_by_user_id, (const Uuid& user_id, bool include_revoked),
                (override));
    MOCK_METHOD(std::vector<DeviceEntity>, list_all_by_user_id,
                (const Uuid& user_id, bool include_revoked, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(void, authorize_device, (const Uuid& device_id, domain::time_point authorized_at), (override));
    MOCK_METHOD(void, authorize_device,
                (const Uuid& device_id, domain::time_point authorized_at, pqxx::transaction_base& tx), (override));

    void revoke_device(const Uuid& device_id, std::string_view reason, domain::time_point revoked_at) override {
        revoke_device_str(device_id, std::string(reason), revoked_at);
    }
    MOCK_METHOD(void, revoke_device_str,
                (const Uuid& device_id, const std::string& reason, domain::time_point revoked_at));

    void revoke_device(const Uuid& device_id, std::string_view reason, domain::time_point revoked_at,
                       pqxx::transaction_base& tx) override {
        revoke_device_tx_str(device_id, std::string(reason), revoked_at, tx);
    }
    MOCK_METHOD(void, revoke_device_tx_str,
                (const Uuid& device_id, const std::string& reason, domain::time_point revoked_at,
                 pqxx::transaction_base& tx));

    MOCK_METHOD(void, update_last_authenticated, (const Uuid& device_id, domain::time_point auth_time), (override));
    MOCK_METHOD(void, update_last_authenticated,
                (const Uuid& device_id, domain::time_point auth_time, pqxx::transaction_base& tx), (override));
};

class MockDevicePublicKeyRepository : public repository::IDevicePublicKeyRepository {
  public:
    MOCK_METHOD(void, store_public_key, (const DevicePublicKeyEntity& key), (override));
    MOCK_METHOD(void, store_public_key, (const DevicePublicKeyEntity& key, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::optional<DevicePublicKeyEntity>, find_by_id, (const Uuid& key_id), (override));
    MOCK_METHOD(std::optional<DevicePublicKeyEntity>, find_by_id, (const Uuid& key_id, pqxx::transaction_base& tx),
                (override));

    MOCK_METHOD(std::vector<DevicePublicKeyEntity>, list_active_keys_by_device_id, (const Uuid& device_id), (override));
    MOCK_METHOD(std::vector<DevicePublicKeyEntity>, list_active_keys_by_device_id,
                (const Uuid& device_id, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(void, replace_key, (const Uuid& old_key_id, const DevicePublicKeyEntity& new_key), (override));
    MOCK_METHOD(void, replace_key,
                (const Uuid& old_key_id, const DevicePublicKeyEntity& new_key, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(void, revoke_all_device_keys, (const Uuid& device_id, domain::time_point revoked_at), (override));
    MOCK_METHOD(void, revoke_all_device_keys,
                (const Uuid& device_id, domain::time_point revoked_at, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::optional<DevicePublicKeyEntity>, claim_one_time_prekey, (const Uuid& device_id), (override));
    MOCK_METHOD(std::optional<DevicePublicKeyEntity>, claim_one_time_prekey,
                (const Uuid& device_id, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(int32_t, count_active_one_time_prekeys, (const Uuid& device_id), (override));
    MOCK_METHOD(int32_t, count_active_one_time_prekeys, (const Uuid& device_id, pqxx::transaction_base& tx),
                (override));

    MOCK_METHOD(int32_t, count_claimed_one_time_prekeys, (const Uuid& device_id), (override));
    MOCK_METHOD(int32_t, count_claimed_one_time_prekeys, (const Uuid& device_id, pqxx::transaction_base& tx),
                (override));

    bool has_active_key_conflict(const Uuid& device_id, std::span<const uint8_t> key) override {
        return has_active_key_conflict_vec(device_id, std::vector<uint8_t>(key.begin(), key.end()));
    }
    MOCK_METHOD(bool, has_active_key_conflict_vec, (const Uuid& device_id, const std::vector<uint8_t>& key));

    bool has_active_key_conflict(const Uuid& device_id, std::span<const uint8_t> key,
                                 pqxx::transaction_base& tx) override {
        return has_active_key_conflict_tx_vec(device_id, std::vector<uint8_t>(key.begin(), key.end()), tx);
    }
    MOCK_METHOD(bool, has_active_key_conflict_tx_vec,
                (const Uuid& device_id, const std::vector<uint8_t>& key, pqxx::transaction_base& tx));

    MOCK_METHOD(std::optional<DevicePublicKeyEntity>, find_active_identity_key, (const Uuid& device_id), (override));
    MOCK_METHOD(std::optional<DevicePublicKeyEntity>, find_active_identity_key,
                (const Uuid& device_id, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::optional<DevicePublicKeyEntity>, find_active_signed_prekey, (const Uuid& device_id), (override));
    MOCK_METHOD(std::optional<DevicePublicKeyEntity>, find_active_signed_prekey,
                (const Uuid& device_id, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(void, store_one_time_prekeys, (const Uuid& device_id, const std::vector<std::vector<uint8_t>>& keys),
                (override));
    MOCK_METHOD(void, store_one_time_prekeys,
                (const Uuid& device_id, const std::vector<std::vector<uint8_t>>& keys, pqxx::transaction_base& tx),
                (override));
};

class MockAuditEventPublisher : public IAuditEventPublisher {
  public:
    MOCK_METHOD(void, publish, (const domain::AuditEvent& event), (noexcept, override));
};

// ============================================================================
// Test Fixture
// ============================================================================

class PrekeyManagerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        device_repo_ = std::make_shared<NiceMock<MockDeviceRepository>>();
        public_key_repo_ = std::make_shared<NiceMock<MockDevicePublicKeyRepository>>();
        audit_publisher_ = std::make_shared<NiceMock<MockAuditEventPublisher>>();

        user_id_ = Uuid::generate_v7();
        device_id_ = Uuid::generate_v7();

        test_device_ = DeviceEntity{
            .device_id = device_id_,
            .user_id = user_id_,
            .device_status = DeviceStatus::Active,
            .registered_at = std::chrono::system_clock::now(),
            .revoked_at = std::nullopt,
            .revocation_reason = std::nullopt,
            .last_authenticated_at = std::chrono::system_clock::now(),
            .created_at = std::chrono::system_clock::now(),
            .updated_at = std::chrono::system_clock::now(),
        };

        crypto_material_ = generate_test_crypto_material(5);

        manager_ = std::make_unique<PrekeyManager>(device_repo_, public_key_repo_, audit_publisher_,
                                                   20,                               // low inventory threshold
                                                   std::chrono::seconds(7 * 86400)); // 7 days SPK max age
    }

    std::shared_ptr<NiceMock<MockDeviceRepository>> device_repo_;
    std::shared_ptr<NiceMock<MockDevicePublicKeyRepository>> public_key_repo_;
    std::shared_ptr<NiceMock<MockAuditEventPublisher>> audit_publisher_;

    Uuid user_id_;
    Uuid device_id_;
    DeviceEntity test_device_;
    CryptoTestMaterial crypto_material_;

    std::unique_ptr<PrekeyManager> manager_;
};

// ============================================================================
// Inventory Status Tests
// ============================================================================

TEST_F(PrekeyManagerTest, GetInventoryStatus_HealthyInventory_ReturnsHealthyStatus) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_)).WillOnce(Return(50));
    EXPECT_CALL(*public_key_repo_, count_claimed_one_time_prekeys(device_id_)).WillOnce(Return(10));

    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = crypto_material_.signed_prekey,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now() - std::chrono::hours(24), // 1 day old
        .signature = crypto_material_.signature,
    };
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(spk));

    auto result = manager_->get_inventory_status(device_id_);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.inventory_status.device_id, device_id_);
    EXPECT_EQ(result.inventory_status.active_one_time_prekeys, 50);
    EXPECT_EQ(result.inventory_status.claimed_one_time_prekeys, 10);
    EXPECT_EQ(result.inventory_status.low_inventory_threshold, 20);
    EXPECT_FALSE(result.inventory_status.is_low_inventory);
    EXPECT_FALSE(result.inventory_status.is_exhausted);
    EXPECT_FALSE(result.inventory_status.signed_prekey_needs_rotation);
}

TEST_F(PrekeyManagerTest, GetInventoryStatus_LowInventory_ReturnsLowStatus) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_)).WillOnce(Return(15));
    EXPECT_CALL(*public_key_repo_, count_claimed_one_time_prekeys(device_id_)).WillOnce(Return(35));

    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = crypto_material_.signed_prekey,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now() - std::chrono::hours(24),
        .signature = crypto_material_.signature,
    };
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(spk));

    auto result = manager_->get_inventory_status(device_id_);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.inventory_status.active_one_time_prekeys, 15);
    EXPECT_TRUE(result.inventory_status.is_low_inventory);
    EXPECT_FALSE(result.inventory_status.is_exhausted);
}

TEST_F(PrekeyManagerTest, GetInventoryStatus_ExhaustedInventory_ReturnsExhaustedStatus) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_)).WillOnce(Return(0));
    EXPECT_CALL(*public_key_repo_, count_claimed_one_time_prekeys(device_id_)).WillOnce(Return(50));

    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = crypto_material_.signed_prekey,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now() - std::chrono::hours(48),
        .signature = crypto_material_.signature,
    };
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(spk));

    auto result = manager_->get_inventory_status(device_id_);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.inventory_status.active_one_time_prekeys, 0);
    EXPECT_TRUE(result.inventory_status.is_low_inventory);
    EXPECT_TRUE(result.inventory_status.is_exhausted);
}

TEST_F(PrekeyManagerTest, GetInventoryStatus_OldSignedPrekey_FlagsNeedsRotation) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_)).WillOnce(Return(30));
    EXPECT_CALL(*public_key_repo_, count_claimed_one_time_prekeys(device_id_)).WillOnce(Return(10));

    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = crypto_material_.signed_prekey,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now() - std::chrono::hours(24 * 8), // 8 days old
        .signature = crypto_material_.signature,
    };
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(spk));

    auto result = manager_->get_inventory_status(device_id_);
    ASSERT_TRUE(result.is_success());
    EXPECT_TRUE(result.inventory_status.signed_prekey_needs_rotation);
    EXPECT_GT(result.inventory_status.signed_prekey_age_seconds, 7 * 86400);
}

TEST_F(PrekeyManagerTest, GetInventoryStatus_DeviceNotFound_ReturnsNotFound) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(std::nullopt));

    auto result = manager_->get_inventory_status(device_id_);
    EXPECT_TRUE(result.is_not_found());
}

TEST_F(PrekeyManagerTest, GetInventoryStatus_DeviceRevoked_ReturnsDeviceRevoked) {
    test_device_.device_status = DeviceStatus::Revoked;
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));

    auto result = manager_->get_inventory_status(device_id_);
    EXPECT_TRUE(result.is_device_revoked());
}

// ============================================================================
// Single Bundle Claiming Tests
// ============================================================================

TEST_F(PrekeyManagerTest, ClaimDevicePrekeyBundle_HealthyInventory_ReturnsHealthyBundle) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));

    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = crypto_material_.identity_pub,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now(),
        .signature = std::nullopt,
    };
    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = crypto_material_.signed_prekey,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now(),
        .signature = crypto_material_.signature,
    };
    DevicePublicKeyEntity otk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::OneTimePrekey,
        .public_key = crypto_material_.one_time_prekeys[0],
        .key_status = KeyStatus::Claimed,
        .created_at = std::chrono::system_clock::now(),
        .signature = std::nullopt,
    };

    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(id_key));
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(spk));
    EXPECT_CALL(*public_key_repo_, claim_one_time_prekey(device_id_)).WillOnce(Return(otk));
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_)).WillOnce(Return(25)); // > 20

    EXPECT_CALL(*audit_publisher_, publish(_)).Times(0); // No low/exhausted alerts

    auto result = manager_->claim_device_prekey_bundle(device_id_);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.exhaustion_state, PrekeyExhaustionState::InventoryHealthy);
    EXPECT_TRUE(result.one_time_prekey.has_value());
    EXPECT_EQ(*result.one_time_prekey, crypto_material_.one_time_prekeys[0]);
    EXPECT_EQ(result.identity_key, crypto_material_.identity_pub);
    EXPECT_EQ(result.signed_prekey, crypto_material_.signed_prekey);
}

TEST_F(PrekeyManagerTest, ClaimDevicePrekeyBundle_LowInventory_EmitsAuditEventAndReturnsLow) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));

    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = crypto_material_.identity_pub,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now(),
        .signature = std::nullopt,
    };
    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = crypto_material_.signed_prekey,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now(),
        .signature = crypto_material_.signature,
    };
    DevicePublicKeyEntity otk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::OneTimePrekey,
        .public_key = crypto_material_.one_time_prekeys[0],
        .key_status = KeyStatus::Claimed,
        .created_at = std::chrono::system_clock::now(),
        .signature = std::nullopt,
    };

    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(id_key));
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(spk));
    EXPECT_CALL(*public_key_repo_, claim_one_time_prekey(device_id_)).WillOnce(Return(otk));
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_)).WillOnce(Return(18)); // <= 20

    EXPECT_CALL(*audit_publisher_, publish(testing::Field(&AuditEvent::event_type, AuditEventType::PrekeyInventoryLow)))
        .Times(1);

    auto result = manager_->claim_device_prekey_bundle(device_id_);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.exhaustion_state, PrekeyExhaustionState::InventoryLow);
    EXPECT_TRUE(result.one_time_prekey.has_value());
}

TEST_F(PrekeyManagerTest, ClaimDevicePrekeyBundle_ExhaustedInventory_EmitsAuditEventAndReturnsExhausted) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));

    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = crypto_material_.identity_pub,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now(),
        .signature = std::nullopt,
    };
    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = crypto_material_.signed_prekey,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now(),
        .signature = crypto_material_.signature,
    };

    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(id_key));
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(spk));
    EXPECT_CALL(*public_key_repo_, claim_one_time_prekey(device_id_)).WillOnce(Return(std::nullopt)); // Exhausted!
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_)).WillOnce(Return(0));

    EXPECT_CALL(*audit_publisher_,
                publish(testing::Field(&AuditEvent::event_type, AuditEventType::PrekeyInventoryExhausted)))
        .Times(1);

    auto result = manager_->claim_device_prekey_bundle(device_id_);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.exhaustion_state, PrekeyExhaustionState::InventoryExhausted);
    EXPECT_FALSE(result.one_time_prekey.has_value());
}

TEST_F(PrekeyManagerTest, ClaimDevicePrekeyBundle_DeviceRevoked_ReturnsDeviceRevoked) {
    test_device_.device_status = DeviceStatus::Revoked;
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));

    auto result = manager_->claim_device_prekey_bundle(device_id_);
    EXPECT_TRUE(result.is_device_revoked());
}

// ============================================================================
// Replenishment Tests
// ============================================================================

TEST_F(PrekeyManagerTest, ReplenishOneTimePrekeys_ValidBatch_StoresKeysAndEmitsAuditEvent) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));
    EXPECT_CALL(*public_key_repo_, has_active_key_conflict_vec(device_id_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(*public_key_repo_, store_one_time_prekeys(device_id_, crypto_material_.one_time_prekeys)).Times(1);
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_)).WillOnce(Return(35));

    EXPECT_CALL(*audit_publisher_, publish(testing::Field(&AuditEvent::event_type, AuditEventType::PrekeysUpdated)))
        .Times(1);

    auto result = manager_->replenish_one_time_prekeys(user_id_, device_id_, device_id_,
                                                       crypto_material_.one_time_prekeys, "127.0.0.1");
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.active_count, 35);
}

TEST_F(PrekeyManagerTest, ReplenishOneTimePrekeys_CallerNotOwner_ReturnsPermissionDenied) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));
    auto other_user = Uuid::generate_v7();

    auto result = manager_->replenish_one_time_prekeys(other_user, device_id_, device_id_,
                                                       crypto_material_.one_time_prekeys, "127.0.0.1");
    EXPECT_TRUE(result.is_permission_denied());
}

TEST_F(PrekeyManagerTest, ReplenishOneTimePrekeys_CallerNotTargetDevice_ReturnsPermissionDenied) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));
    auto other_device = Uuid::generate_v7();

    auto result = manager_->replenish_one_time_prekeys(user_id_, other_device, device_id_,
                                                       crypto_material_.one_time_prekeys, "127.0.0.1");
    EXPECT_TRUE(result.is_permission_denied());
}

TEST_F(PrekeyManagerTest, ReplenishOneTimePrekeys_RevokedDevice_ReturnsDeviceRevoked) {
    test_device_.device_status = DeviceStatus::Revoked;
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));

    auto result = manager_->replenish_one_time_prekeys(user_id_, device_id_, device_id_,
                                                       crypto_material_.one_time_prekeys, "127.0.0.1");
    EXPECT_TRUE(result.is_device_revoked());
}

TEST_F(PrekeyManagerTest, ReplenishOneTimePrekeys_InvalidBatchEmpty_ReturnsInvalidArgument) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));
    std::vector<std::vector<uint8_t>> empty_batch;

    auto result = manager_->replenish_one_time_prekeys(user_id_, device_id_, device_id_, empty_batch, "127.0.0.1");
    EXPECT_TRUE(result.is_invalid_argument());
}

TEST_F(PrekeyManagerTest, ReplenishOneTimePrekeys_ConflictDetected_ReturnsConflict) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));
    EXPECT_CALL(*public_key_repo_, has_active_key_conflict_vec(device_id_, _)).WillOnce(Return(true));

    auto result = manager_->replenish_one_time_prekeys(user_id_, device_id_, device_id_,
                                                       crypto_material_.one_time_prekeys, "127.0.0.1");
    EXPECT_TRUE(result.is_conflict());
}

// ============================================================================
// Signed Prekey Rotation Tests
// ============================================================================

TEST_F(PrekeyManagerTest, RotateSignedPrekey_ValidSignature_ReplacesKeyAndEmitsAuditEvent) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));

    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = crypto_material_.identity_pub,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now(),
        .signature = std::nullopt,
    };
    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(id_key));

    DevicePublicKeyEntity current_spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = crypto_material_.signed_prekey,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now() - std::chrono::hours(24 * 8),
        .signature = crypto_material_.signature,
    };
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(current_spk));
    EXPECT_CALL(*public_key_repo_, replace_key(current_spk.key_id, _)).Times(1);

    EXPECT_CALL(*audit_publisher_,
                publish(testing::Field(&AuditEvent::event_type, AuditEventType::SignedPrekeyRotated)))
        .Times(1);

    auto result = manager_->rotate_signed_prekey(user_id_, device_id_, device_id_, crypto_material_.signed_prekey,
                                                 crypto_material_.signature, "127.0.0.1");
    EXPECT_TRUE(result.is_success());
}

TEST_F(PrekeyManagerTest, RotateSignedPrekey_InvalidSignature_ReturnsInvalidArgument) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));

    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = crypto_material_.identity_pub,
        .key_status = KeyStatus::Active,
        .created_at = std::chrono::system_clock::now(),
        .signature = std::nullopt,
    };
    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(id_key));

    // Corrupted signature
    auto bad_sig = crypto_material_.signature;
    bad_sig[0] ^= 0xFF;

    auto result = manager_->rotate_signed_prekey(user_id_, device_id_, device_id_, crypto_material_.signed_prekey,
                                                 bad_sig, "127.0.0.1");
    EXPECT_TRUE(result.is_invalid_argument());
}

TEST_F(PrekeyManagerTest, RotateSignedPrekey_RevokedDevice_ReturnsDeviceRevoked) {
    test_device_.device_status = DeviceStatus::Revoked;
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(test_device_));

    auto result = manager_->rotate_signed_prekey(user_id_, device_id_, device_id_, crypto_material_.signed_prekey,
                                                 crypto_material_.signature, "127.0.0.1");
    EXPECT_TRUE(result.is_device_revoked());
}

} // namespace
} // namespace securecloud::auth::service::test
