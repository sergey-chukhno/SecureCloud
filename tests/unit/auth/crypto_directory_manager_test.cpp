#include "auth/crypto/device_key_validator.hpp"
#include "auth/crypto/key_fingerprint.hpp"
#include "auth/domain/audit_event.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/repository/device_public_key_repository.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/crypto_directory_manager.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <openssl/evp.h>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;

using domain::AuditEvent;
using domain::AuditEventType;
using domain::DeviceEntity;
using domain::DevicePublicKeyEntity;
using domain::DeviceStatus;
using domain::KeyStatus;
using domain::KeyType;
using domain::PrekeyBundle;
using domain::Uuid;

// ============================================================================
// Cryptographic Test Helpers
// ============================================================================

struct CryptoBundle {
    std::vector<uint8_t> identity_pub;
    std::vector<uint8_t> signed_prekey;
    std::vector<uint8_t> signature;
    std::vector<std::vector<uint8_t>> one_time_prekeys;
};

CryptoBundle generate_test_crypto_bundle(std::size_t otk_count = 3) {
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

    // 3. Ed25519 Signature over Signed Prekey
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, id_pkey);
    size_t sig_len = 64;
    bundle.signature.resize(sig_len);
    EVP_DigestSign(md_ctx, bundle.signature.data(), &sig_len, bundle.signed_prekey.data(), bundle.signed_prekey.size());
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
        bundle.one_time_prekeys.push_back(std::move(otk));
    }

    return bundle;
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

class CryptoDirectoryManagerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        device_repo_ = std::make_shared<NiceMock<MockDeviceRepository>>();
        public_key_repo_ = std::make_shared<NiceMock<MockDevicePublicKeyRepository>>();
        audit_publisher_ = std::make_shared<NiceMock<MockAuditEventPublisher>>();

        manager_ = std::make_unique<CryptoDirectoryManager>(device_repo_, public_key_repo_, audit_publisher_);

        user_id_ = Uuid::generate_v7();
        device_id_ = Uuid::generate_v7();
        bundle_ = generate_test_crypto_bundle(5);
    }

    std::shared_ptr<NiceMock<MockDeviceRepository>> device_repo_;
    std::shared_ptr<NiceMock<MockDevicePublicKeyRepository>> public_key_repo_;
    std::shared_ptr<NiceMock<MockAuditEventPublisher>> audit_publisher_;
    std::unique_ptr<CryptoDirectoryManager> manager_;

    Uuid user_id_;
    Uuid device_id_;
    CryptoBundle bundle_;
};

// ============================================================================
// Constructor Validation Tests
// ============================================================================

TEST_F(CryptoDirectoryManagerTest, ConstructorThrowsOnNullDeviceRepository) {
    EXPECT_THROW(CryptoDirectoryManager(nullptr, public_key_repo_, audit_publisher_), std::invalid_argument);
}

TEST_F(CryptoDirectoryManagerTest, ConstructorThrowsOnNullPublicKeyRepository) {
    EXPECT_THROW(CryptoDirectoryManager(device_repo_, nullptr, audit_publisher_), std::invalid_argument);
}

TEST_F(CryptoDirectoryManagerTest, ConstructorSucceedsWithNullAuditPublisher) {
    EXPECT_NO_THROW(CryptoDirectoryManager(device_repo_, public_key_repo_, nullptr));
}

// ============================================================================
// get_crypto_identity Tests
// ============================================================================

TEST_F(CryptoDirectoryManagerTest, GetCryptoIdentityReturnsNotFoundWhenDeviceDoesNotExist) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(std::nullopt));

    auto result = manager_->get_crypto_identity(device_id_);
    EXPECT_TRUE(result.is_not_found());
    EXPECT_FALSE(result.is_success());
}

TEST_F(CryptoDirectoryManagerTest, GetCryptoIdentityHandlesRevokedDeviceSafely) {
    DeviceEntity revoked_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Revoked,
    };
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(revoked_dev));

    auto result = manager_->get_crypto_identity(device_id_);
    EXPECT_TRUE(result.is_revoked());
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.device_status, DeviceStatus::Revoked);
    EXPECT_EQ(result.signed_prekey, std::nullopt);
    EXPECT_TRUE(result.identity_key.empty());
}

TEST_F(CryptoDirectoryManagerTest, GetCryptoIdentityHandlesPendingAuthorizationDeviceSafely) {
    DeviceEntity pending_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::PendingAuthorization,
    };
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(pending_dev));

    auto result = manager_->get_crypto_identity(device_id_);
    EXPECT_TRUE(result.is_pending_authorization());
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.device_status, DeviceStatus::PendingAuthorization);
    EXPECT_EQ(result.signed_prekey, std::nullopt);
}

TEST_F(CryptoDirectoryManagerTest, GetCryptoIdentityFailsWhenIdentityKeyMissing) {
    DeviceEntity active_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));
    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(std::nullopt));

    auto result = manager_->get_crypto_identity(device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, CryptoIdentityResult::Status::InternalError);
}

TEST_F(CryptoDirectoryManagerTest, GetCryptoIdentityFailsWhenSignedPrekeyMissing) {
    DeviceEntity active_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = bundle_.identity_pub,
        .key_status = KeyStatus::Active,
    };

    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));
    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(id_key));
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(std::nullopt));

    auto result = manager_->get_crypto_identity(device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, CryptoIdentityResult::Status::InternalError);
}

TEST_F(CryptoDirectoryManagerTest, GetCryptoIdentityReturnsFullActiveIdentityAndFingerprint) {
    DeviceEntity active_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = bundle_.identity_pub,
        .key_status = KeyStatus::Active,
    };
    auto spk_created_at = std::chrono::system_clock::now();
    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = bundle_.signed_prekey,
        .key_status = KeyStatus::Active,
        .created_at = spk_created_at,
        .signature = bundle_.signature,
    };

    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));
    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(id_key));
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(spk));

    auto result = manager_->get_crypto_identity(device_id_);
    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.device_id, device_id_);
    EXPECT_EQ(result.device_status, DeviceStatus::Active);
    EXPECT_EQ(result.identity_key, bundle_.identity_pub);
    EXPECT_EQ(result.identity_key_fingerprint, crypto::KeyFingerprint::compute_sha256(bundle_.identity_pub));
    ASSERT_TRUE(result.signed_prekey.has_value());
    EXPECT_EQ(*result.signed_prekey, bundle_.signed_prekey);
    ASSERT_TRUE(result.signed_prekey_signature.has_value());
    EXPECT_EQ(*result.signed_prekey_signature, bundle_.signature);
    EXPECT_EQ(result.signed_prekey_created_at, spk_created_at);
}

// ============================================================================
// get_device_crypto_directory Tests
// ============================================================================

TEST_F(CryptoDirectoryManagerTest, GetDeviceCryptoDirectoryReturnsEmptyWhenUserHasNoActiveDevices) {
    EXPECT_CALL(*device_repo_, list_active_by_user_id(user_id_)).WillOnce(Return(std::vector<DeviceEntity>{}));

    auto result = manager_->get_device_crypto_directory(user_id_);
    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.user_id, user_id_);
    EXPECT_TRUE(result.bundles.empty());
}

TEST_F(CryptoDirectoryManagerTest, GetDeviceCryptoDirectoryAssemblesBundlesWithClaimedOtk) {
    DeviceEntity dev1{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = bundle_.identity_pub,
        .key_status = KeyStatus::Active,
    };
    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = bundle_.signed_prekey,
        .key_status = KeyStatus::Active,
        .signature = bundle_.signature,
    };
    Uuid otk_id = Uuid::generate_v7();
    DevicePublicKeyEntity otk{
        .key_id = otk_id,
        .device_id = device_id_,
        .key_type = KeyType::OneTimePrekey,
        .public_key = bundle_.one_time_prekeys[0],
        .key_status = KeyStatus::Active,
    };

    EXPECT_CALL(*device_repo_, list_active_by_user_id(user_id_)).WillOnce(Return(std::vector<DeviceEntity>{dev1}));
    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(id_key));
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(spk));
    EXPECT_CALL(*public_key_repo_, claim_one_time_prekey(device_id_)).WillOnce(Return(otk));
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_)).WillOnce(Return(4));

    auto result = manager_->get_device_crypto_directory(user_id_);
    EXPECT_TRUE(result.is_success());
    ASSERT_EQ(result.bundles.size(), 1u);

    const auto& b = result.bundles[0];
    EXPECT_EQ(b.device_id, device_id_);
    EXPECT_EQ(b.identity_key, bundle_.identity_pub);
    EXPECT_EQ(b.identity_key_fingerprint, crypto::KeyFingerprint::compute_sha256(bundle_.identity_pub));
    EXPECT_EQ(b.signed_prekey, bundle_.signed_prekey);
    EXPECT_EQ(b.signed_prekey_signature, bundle_.signature);
    ASSERT_TRUE(b.one_time_prekey.has_value());
    EXPECT_EQ(*b.one_time_prekey, bundle_.one_time_prekeys[0]);
    ASSERT_TRUE(b.one_time_prekey_id.has_value());
    EXPECT_EQ(*b.one_time_prekey_id, otk_id);
    EXPECT_EQ(b.remaining_one_time_prekeys, 4);
}

TEST_F(CryptoDirectoryManagerTest, GetDeviceCryptoDirectoryFallsBackGracefullyWhenOtksExhausted) {
    DeviceEntity dev1{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = bundle_.identity_pub,
    };
    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = bundle_.signed_prekey,
        .signature = bundle_.signature,
    };

    EXPECT_CALL(*device_repo_, list_active_by_user_id(user_id_)).WillOnce(Return(std::vector<DeviceEntity>{dev1}));
    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(id_key));
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(spk));
    // When all OTKs are consumed, claim_one_time_prekey returns nullopt
    EXPECT_CALL(*public_key_repo_, claim_one_time_prekey(device_id_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_)).WillOnce(Return(0));

    auto result = manager_->get_device_crypto_directory(user_id_);
    EXPECT_TRUE(result.is_success());
    ASSERT_EQ(result.bundles.size(), 1u);

    const auto& b = result.bundles[0];
    EXPECT_EQ(b.one_time_prekey, std::nullopt);
    EXPECT_EQ(b.one_time_prekey_id, std::nullopt);
    EXPECT_EQ(b.remaining_one_time_prekeys, 0);
}

TEST_F(CryptoDirectoryManagerTest, GetDeviceCryptoDirectoryFiltersDevicesCorrectly) {
    Uuid dev2_id = Uuid::generate_v7();
    Uuid dev3_id = Uuid::generate_v7();

    DeviceEntity dev1{.device_id = device_id_, .user_id = user_id_, .device_status = DeviceStatus::Active};
    DeviceEntity dev2{.device_id = dev2_id, .user_id = user_id_, .device_status = DeviceStatus::Active};
    DeviceEntity dev3{.device_id = dev3_id, .user_id = user_id_, .device_status = DeviceStatus::Active};

    EXPECT_CALL(*device_repo_, list_active_by_user_id(user_id_))
        .WillOnce(Return(std::vector<DeviceEntity>{dev1, dev2, dev3}));

    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = dev2_id,
        .key_type = KeyType::IdentitySigning,
        .public_key = bundle_.identity_pub,
    };
    DevicePublicKeyEntity spk{
        .key_id = Uuid::generate_v7(),
        .device_id = dev2_id,
        .key_type = KeyType::SignedPrekey,
        .public_key = bundle_.signed_prekey,
        .signature = bundle_.signature,
    };

    // Only dev2 should have its keys queried
    EXPECT_CALL(*public_key_repo_, find_active_identity_key(dev2_id)).WillOnce(Return(id_key));
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(dev2_id)).WillOnce(Return(spk));
    EXPECT_CALL(*public_key_repo_, claim_one_time_prekey(dev2_id)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(dev2_id)).WillOnce(Return(0));

    // Filter specifies only dev2
    auto result = manager_->get_device_crypto_directory(user_id_, {dev2_id});
    EXPECT_TRUE(result.is_success());
    ASSERT_EQ(result.bundles.size(), 1u);
    EXPECT_EQ(result.bundles[0].device_id, dev2_id);
}

// ============================================================================
// update_crypto_prekeys Tests
// ============================================================================

TEST_F(CryptoDirectoryManagerTest, UpdateCryptoPrekeysRejectsEmptyInput) {
    auto result = manager_->update_crypto_prekeys(user_id_, device_id_, device_id_, {}, {}, {});
    EXPECT_TRUE(result.is_invalid_argument());
    EXPECT_FALSE(result.is_success());
}

TEST_F(CryptoDirectoryManagerTest, UpdateCryptoPrekeysRejectsNonExistentTargetDevice) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(std::nullopt));

    auto result =
        manager_->update_crypto_prekeys(user_id_, device_id_, device_id_, bundle_.signed_prekey, bundle_.signature, {});
    EXPECT_TRUE(result.is_not_found());
}

TEST_F(CryptoDirectoryManagerTest, UpdateCryptoPrekeysRejectsCallerWhenNotOwner) {
    Uuid other_user = Uuid::generate_v7();
    DeviceEntity target_dev{
        .device_id = device_id_,
        .user_id = other_user,
        .device_status = DeviceStatus::Active,
    };
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(target_dev));

    auto result =
        manager_->update_crypto_prekeys(user_id_, device_id_, device_id_, bundle_.signed_prekey, bundle_.signature, {});
    EXPECT_TRUE(result.is_permission_denied());
}

TEST_F(CryptoDirectoryManagerTest, UpdateCryptoPrekeysRejectsDifferentCallerDevice) {
    Uuid other_device = Uuid::generate_v7();
    DeviceEntity target_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(target_dev));

    auto result = manager_->update_crypto_prekeys(user_id_, other_device, device_id_, bundle_.signed_prekey,
                                                  bundle_.signature, {});
    EXPECT_TRUE(result.is_permission_denied());
}

TEST_F(CryptoDirectoryManagerTest, UpdateCryptoPrekeysRejectsInactiveDevice) {
    DeviceEntity revoked_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Revoked,
    };
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(revoked_dev));

    auto result =
        manager_->update_crypto_prekeys(user_id_, device_id_, device_id_, bundle_.signed_prekey, bundle_.signature, {});
    EXPECT_TRUE(result.is_permission_denied());
}

TEST_F(CryptoDirectoryManagerTest, UpdateCryptoPrekeysRejectsSignedPrekeyWithoutSignature) {
    DeviceEntity active_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));

    auto result = manager_->update_crypto_prekeys(user_id_, device_id_, device_id_, bundle_.signed_prekey, {}, {});
    EXPECT_TRUE(result.is_invalid_argument());
}

TEST_F(CryptoDirectoryManagerTest, UpdateCryptoPrekeysRejectsInvalidSignedPrekeyFormat) {
    DeviceEntity active_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));

    std::vector<uint8_t> bad_spk = {0x01, 0x02}; // Not 32 bytes
    auto result = manager_->update_crypto_prekeys(user_id_, device_id_, device_id_, bad_spk, bundle_.signature, {});
    EXPECT_TRUE(result.is_invalid_argument());
}

TEST_F(CryptoDirectoryManagerTest, UpdateCryptoPrekeysRejectsInvalidSignature) {
    DeviceEntity active_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = bundle_.identity_pub,
    };
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));
    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(id_key));

    std::vector<uint8_t> corrupt_sig = bundle_.signature;
    corrupt_sig[0] ^= 0xFF; // Corrupt signature

    auto result =
        manager_->update_crypto_prekeys(user_id_, device_id_, device_id_, bundle_.signed_prekey, corrupt_sig, {});
    EXPECT_TRUE(result.is_invalid_argument());
}

TEST_F(CryptoDirectoryManagerTest, UpdateCryptoPrekeysRotatesSignedPrekeyAndEmitsAudit) {
    DeviceEntity active_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = bundle_.identity_pub,
    };
    Uuid old_spk_id = Uuid::generate_v7();
    DevicePublicKeyEntity old_spk{
        .key_id = old_spk_id,
        .device_id = device_id_,
        .key_type = KeyType::SignedPrekey,
        .public_key = bundle_.signed_prekey,
    };

    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));
    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(id_key));
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(old_spk));
    EXPECT_CALL(*public_key_repo_, replace_key(old_spk_id, _)).Times(1);
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_)).WillOnce(Return(10));

    AuditEvent published_event;
    EXPECT_CALL(*audit_publisher_, publish(_)).WillOnce(SaveArg<0>(&published_event));

    auto result = manager_->update_crypto_prekeys(user_id_, device_id_, device_id_, bundle_.signed_prekey,
                                                  bundle_.signature, {}, "192.168.1.100");
    EXPECT_TRUE(result.is_success());
    EXPECT_TRUE(result.signed_prekey_rotated);
    EXPECT_EQ(result.one_time_prekeys_added, 0);
    EXPECT_EQ(result.total_active_one_time_prekeys, 10);

    EXPECT_EQ(published_event.event_type, AuditEventType::SignedPrekeyRotated);
    EXPECT_EQ(published_event.user_id, user_id_);
    EXPECT_EQ(published_event.device_id, device_id_);
    EXPECT_EQ(published_event.client_ip, "192.168.1.100");
}

TEST_F(CryptoDirectoryManagerTest, UpdateCryptoPrekeysReplenishesOneTimePrekeysAndEmitsAudit) {
    DeviceEntity active_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));
    EXPECT_CALL(*public_key_repo_, store_one_time_prekeys(device_id_, bundle_.one_time_prekeys)).Times(1);
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_))
        .WillOnce(Return(5))  // For audit event
        .WillOnce(Return(5)); // For final result

    AuditEvent published_event;
    EXPECT_CALL(*audit_publisher_, publish(_)).WillOnce(SaveArg<0>(&published_event));

    auto result =
        manager_->update_crypto_prekeys(user_id_, device_id_, device_id_, {}, {}, bundle_.one_time_prekeys, "10.0.0.5");
    EXPECT_TRUE(result.is_success());
    EXPECT_FALSE(result.signed_prekey_rotated);
    EXPECT_EQ(result.one_time_prekeys_added, static_cast<int32_t>(bundle_.one_time_prekeys.size()));
    EXPECT_EQ(result.total_active_one_time_prekeys, 5);

    EXPECT_EQ(published_event.event_type, AuditEventType::PrekeysUpdated);
    EXPECT_EQ(published_event.user_id, user_id_);
    EXPECT_EQ(published_event.device_id, device_id_);
    EXPECT_EQ(published_event.failure_reason, "ACTIVE_COUNT=5");
    EXPECT_EQ(published_event.client_ip, "10.0.0.5");
}

TEST_F(CryptoDirectoryManagerTest, UpdateCryptoPrekeysRejectsInvalidOneTimePrekeys) {
    DeviceEntity active_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));

    std::vector<std::vector<uint8_t>> invalid_otks = {{0xAA, 0xBB}}; // Not 32 bytes
    auto result = manager_->update_crypto_prekeys(user_id_, device_id_, device_id_, {}, {}, invalid_otks);
    EXPECT_TRUE(result.is_invalid_argument());
}

TEST_F(CryptoDirectoryManagerTest, UpdateCryptoPrekeysCombinedRotationAndReplenishment) {
    DeviceEntity active_dev{
        .device_id = device_id_,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
    };
    DevicePublicKeyEntity id_key{
        .key_id = Uuid::generate_v7(),
        .device_id = device_id_,
        .key_type = KeyType::IdentitySigning,
        .public_key = bundle_.identity_pub,
    };

    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));
    EXPECT_CALL(*public_key_repo_, find_active_identity_key(device_id_)).WillOnce(Return(id_key));
    EXPECT_CALL(*public_key_repo_, find_active_signed_prekey(device_id_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(*public_key_repo_, store_public_key(_)).Times(1);
    EXPECT_CALL(*public_key_repo_, store_one_time_prekeys(device_id_, bundle_.one_time_prekeys)).Times(1);
    EXPECT_CALL(*public_key_repo_, count_active_one_time_prekeys(device_id_)).WillOnce(Return(8)).WillOnce(Return(8));

    // Both signed_prekey_rotated and prekeys_updated should be emitted
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(2);

    auto result = manager_->update_crypto_prekeys(user_id_, device_id_, device_id_, bundle_.signed_prekey,
                                                  bundle_.signature, bundle_.one_time_prekeys, "127.0.0.1");
    EXPECT_TRUE(result.is_success());
    EXPECT_TRUE(result.signed_prekey_rotated);
    EXPECT_EQ(result.one_time_prekeys_added, static_cast<int32_t>(bundle_.one_time_prekeys.size()));
    EXPECT_EQ(result.total_active_one_time_prekeys, 8);
}

} // namespace
} // namespace securecloud::auth::service::test
