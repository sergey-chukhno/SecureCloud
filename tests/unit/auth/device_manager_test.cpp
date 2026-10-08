#include "auth/crypto/device_key_validator.hpp"
#include "auth/domain/audit_event.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/session_result.hpp"
#include "auth/repository/device_public_key_repository.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/device_manager.hpp"
#include "auth/service/session_manager.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <thread>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;

using domain::AuthenticationLevel;
using domain::DeviceEntity;
using domain::DevicePublicKeyEntity;
using domain::DeviceStatus;
using domain::KeyStatus;
using domain::KeyType;
using domain::Uuid;

// ============================================================================
// Cryptographic Fixture Helpers
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
// Mock Repositories & Publishers
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

    MOCK_METHOD(void, revoke_device, (const Uuid& device_id, std::string_view reason, domain::time_point revoked_at),
                (override));
    MOCK_METHOD(void, revoke_device,
                (const Uuid& device_id, std::string_view reason, domain::time_point revoked_at,
                 pqxx::transaction_base& tx),
                (override));

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
};

class MockAuditEventPublisher : public IAuditEventPublisher {
  public:
    MOCK_METHOD(void, publish, (const domain::AuditEvent& event), (noexcept, override));
};

class MockSessionManager : public ISessionManager {
  public:
    MOCK_METHOD(SessionEstablishmentResult, establish_session, (const domain::UserEntity&, const domain::Uuid&),
                (override));
    MOCK_METHOD(domain::SessionValidationResult, validate_session, (const domain::Uuid&, std::optional<domain::Uuid>),
                (override));
    MOCK_METHOD(std::vector<domain::SessionEntity>, list_active_sessions_for_user, (const domain::Uuid&), (override));
    MOCK_METHOD(std::vector<domain::SessionEntity>, list_active_sessions_for_device, (const domain::Uuid&), (override));
    domain::SessionRevocationResult revoke_session(const domain::Uuid& session_id, std::string_view reason) override {
        return revoke_session_str(session_id, std::string(reason));
    }
    MOCK_METHOD(domain::SessionRevocationResult, revoke_session_str, (const domain::Uuid&, const std::string&));

    domain::SessionRevocationResult revoke_all_device_sessions(const domain::Uuid& device_id,
                                                               std::string_view reason) override {
        return revoke_all_device_sessions_str(device_id, std::string(reason));
    }
    MOCK_METHOD(domain::SessionRevocationResult, revoke_all_device_sessions_str,
                (const domain::Uuid&, const std::string&));

    domain::SessionRevocationResult revoke_all_user_sessions(const domain::Uuid& user_id,
                                                             std::string_view reason) override {
        return revoke_all_user_sessions_str(user_id, std::string(reason));
    }
    MOCK_METHOD(domain::SessionRevocationResult, revoke_all_user_sessions_str,
                (const domain::Uuid&, const std::string&));
};

// ============================================================================
// Test Fixture
// ============================================================================

class DeviceManagerTest : public ::testing::Test {
  protected:
    std::shared_ptr<NiceMock<MockDeviceRepository>> device_repo_{std::make_shared<NiceMock<MockDeviceRepository>>()};
    std::shared_ptr<NiceMock<MockDevicePublicKeyRepository>> public_key_repo_{
        std::make_shared<NiceMock<MockDevicePublicKeyRepository>>()};
    std::shared_ptr<NiceMock<MockSessionManager>> session_manager_{std::make_shared<NiceMock<MockSessionManager>>()};
    std::shared_ptr<NiceMock<MockAuditEventPublisher>> audit_publisher_{
        std::make_shared<NiceMock<MockAuditEventPublisher>>()};

    Uuid user_id_{Uuid::generate_v7()};
    CryptoBundle bundle_{generate_valid_crypto_bundle()};
};

// ============================================================================
// Enrollment Tests
// ============================================================================

TEST_F(DeviceManagerTest, EnrollDevice_WithMfaVerified_DirectlyActive) {
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_);

    DeviceEntity saved_device;
    EXPECT_CALL(*device_repo_, register_device(_)).WillOnce(SaveArg<0>(&saved_device));
    // 1 identity key + 1 signed prekey + 3 OTKs = 5 keys stored
    EXPECT_CALL(*public_key_repo_, store_public_key(_)).Times(5);
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(2);

    auto result = manager.enroll_device(user_id_, bundle_.identity_pub, bundle_.signed_prekey, bundle_.signature,
                                        bundle_.one_time_prekeys, AuthenticationLevel::MfaVerified, "127.0.0.1");

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.status, DeviceStatus::Active);
    EXPECT_TRUE(result.pairing_code.empty());
    EXPECT_EQ(saved_device.device_status, DeviceStatus::Active);
    EXPECT_EQ(saved_device.user_id, user_id_);
}

TEST_F(DeviceManagerTest, EnrollDevice_WithPrimaryOnly_PendingAuthorizationAndGeneratesPIN) {
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_);

    DeviceEntity saved_device;
    EXPECT_CALL(*device_repo_, register_device(_)).WillOnce(SaveArg<0>(&saved_device));
    EXPECT_CALL(*public_key_repo_, store_public_key(_)).Times(5);
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(2);

    auto result = manager.enroll_device(user_id_, bundle_.identity_pub, bundle_.signed_prekey, bundle_.signature,
                                        bundle_.one_time_prekeys, AuthenticationLevel::PrimaryOnly, "127.0.0.1");

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.status, DeviceStatus::PendingAuthorization);
    EXPECT_FALSE(result.pairing_code.empty());
    EXPECT_EQ(result.pairing_code.size(), 9); // XXXX-XXXX (8 chars + 1 hyphen)
    EXPECT_EQ(result.pairing_code[4], '-');
    EXPECT_EQ(saved_device.device_status, DeviceStatus::PendingAuthorization);
}

TEST_F(DeviceManagerTest, EnrollDevice_InvalidSignature_RejectsWithoutWriting) {
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_);

    auto corrupted_sig = bundle_.signature;
    corrupted_sig[0] ^= 0xFF;

    EXPECT_CALL(*device_repo_, register_device(_)).Times(0);
    EXPECT_CALL(*public_key_repo_, store_public_key(_)).Times(0);
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(0);

    auto result = manager.enroll_device(user_id_, bundle_.identity_pub, bundle_.signed_prekey, corrupted_sig,
                                        bundle_.one_time_prekeys, AuthenticationLevel::MfaVerified, "127.0.0.1");

    EXPECT_FALSE(result.success);
    EXPECT_NE(result.error_message.find("Cryptographic signature verification failed"), std::string::npos);
}

TEST_F(DeviceManagerTest, EnrollDevice_ZeroPrivateKeyViolation_RejectsImmediately) {
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_);

    std::string bad_marker = "-----BEGIN PRIVATE KEY-----";
    std::vector<uint8_t> bad_id(bad_marker.begin(), bad_marker.end());
    bad_id.resize(32, 0);

    EXPECT_CALL(*device_repo_, register_device(_)).Times(0);
    EXPECT_CALL(*public_key_repo_, store_public_key(_)).Times(0);

    auto result = manager.enroll_device(user_id_, bad_id, bundle_.signed_prekey, bundle_.signature,
                                        bundle_.one_time_prekeys, AuthenticationLevel::MfaVerified);

    EXPECT_FALSE(result.success);
    EXPECT_NE(result.error_message.find("Zero Private Key Invariant"), std::string::npos);
}

// ============================================================================
// Authorization & Pairing Tests
// ============================================================================

TEST_F(DeviceManagerTest, AuthorizeDevice_ValidPairingCode_PromotesToActive) {
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_);

    // 1. Enroll as PrimaryOnly
    auto enroll_res = manager.enroll_device(user_id_, bundle_.identity_pub, bundle_.signed_prekey, bundle_.signature,
                                            bundle_.one_time_prekeys, AuthenticationLevel::PrimaryOnly);
    ASSERT_TRUE(enroll_res.success);
    const auto dev_id = enroll_res.device_id;
    const std::string pin = enroll_res.pairing_code;

    // 2. Setup mock find_by_id
    const auto now = std::chrono::system_clock::now();
    DeviceEntity pending_dev{
        .device_id = dev_id,
        .user_id = user_id_,
        .device_status = DeviceStatus::PendingAuthorization,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    EXPECT_CALL(*device_repo_, find_by_id(dev_id)).WillRepeatedly(Return(pending_dev));
    EXPECT_CALL(*device_repo_, authorize_device(dev_id, _)).Times(1);

    // 3. Authorize with PIN
    auto auth_res = manager.authorize_device(user_id_, dev_id, pin, AuthenticationLevel::PrimaryOnly);
    EXPECT_TRUE(auth_res.success);
    EXPECT_EQ(auth_res.status, DeviceStatus::Active);

    // 4. Second attempt with consumed PIN must fail
    auto auth_res2 = manager.authorize_device(user_id_, dev_id, pin, AuthenticationLevel::PrimaryOnly);
    EXPECT_FALSE(auth_res2.success);
    EXPECT_NE(auth_res2.error_message.find("consumed"), std::string::npos);
}

TEST_F(DeviceManagerTest, AuthorizeDevice_ToleratesHyphenAndSpaceAndLowercase) {
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_);

    auto enroll_res = manager.enroll_device(user_id_, bundle_.identity_pub, bundle_.signed_prekey, bundle_.signature,
                                            bundle_.one_time_prekeys, AuthenticationLevel::PrimaryOnly);
    ASSERT_TRUE(enroll_res.success);
    const auto dev_id = enroll_res.device_id;

    const auto now = std::chrono::system_clock::now();
    DeviceEntity pending_dev{
        .device_id = dev_id,
        .user_id = user_id_,
        .device_status = DeviceStatus::PendingAuthorization,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    EXPECT_CALL(*device_repo_, find_by_id(dev_id)).WillRepeatedly(Return(pending_dev));
    EXPECT_CALL(*device_repo_, authorize_device(dev_id, _)).Times(1);

    // Transform PIN: remove hyphen, convert to lowercase, add space
    std::string messy_pin = enroll_res.pairing_code;
    std::replace(messy_pin.begin(), messy_pin.end(), '-', ' ');
    for (char& c : messy_pin) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    auto auth_res = manager.authorize_device(user_id_, dev_id, messy_pin, AuthenticationLevel::PrimaryOnly);
    EXPECT_TRUE(auth_res.success);
    EXPECT_EQ(auth_res.status, DeviceStatus::Active);
}

TEST_F(DeviceManagerTest, AuthorizeDevice_InvalidCode_LocksOutAfterThreeFailedAttempts) {
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_);

    auto enroll_res = manager.enroll_device(user_id_, bundle_.identity_pub, bundle_.signed_prekey, bundle_.signature,
                                            bundle_.one_time_prekeys, AuthenticationLevel::PrimaryOnly);
    ASSERT_TRUE(enroll_res.success);
    const auto dev_id = enroll_res.device_id;
    const std::string good_pin = enroll_res.pairing_code;

    const auto now = std::chrono::system_clock::now();
    DeviceEntity pending_dev{
        .device_id = dev_id,
        .user_id = user_id_,
        .device_status = DeviceStatus::PendingAuthorization,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    EXPECT_CALL(*device_repo_, find_by_id(dev_id)).WillRepeatedly(Return(pending_dev));
    EXPECT_CALL(*device_repo_, authorize_device(dev_id, _)).Times(0);

    // 1st bad attempt
    auto res1 = manager.authorize_device(user_id_, dev_id, "WRONG001", AuthenticationLevel::PrimaryOnly);
    EXPECT_FALSE(res1.success);
    EXPECT_FALSE(res1.is_locked_out);

    // 2nd bad attempt
    auto res2 = manager.authorize_device(user_id_, dev_id, "WRONG002", AuthenticationLevel::PrimaryOnly);
    EXPECT_FALSE(res2.success);
    EXPECT_FALSE(res2.is_locked_out);

    // 3rd bad attempt triggers lockout
    auto res3 = manager.authorize_device(user_id_, dev_id, "WRONG003", AuthenticationLevel::PrimaryOnly);
    EXPECT_FALSE(res3.success);
    EXPECT_TRUE(res3.is_locked_out);

    // 4th attempt with CORRECT pin is rejected due to lockout
    auto res4 = manager.authorize_device(user_id_, dev_id, good_pin, AuthenticationLevel::PrimaryOnly);
    EXPECT_FALSE(res4.success);
    EXPECT_TRUE(res4.is_locked_out);
    EXPECT_NE(res4.error_message.find("locked out"), std::string::npos);
}

TEST_F(DeviceManagerTest, AuthorizeDevice_ExpiredChallenge_Rejects) {
    // 0-second TTL
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_, std::chrono::seconds(0));

    auto enroll_res = manager.enroll_device(user_id_, bundle_.identity_pub, bundle_.signed_prekey, bundle_.signature,
                                            bundle_.one_time_prekeys, AuthenticationLevel::PrimaryOnly);
    ASSERT_TRUE(enroll_res.success);
    const auto dev_id = enroll_res.device_id;
    const std::string pin = enroll_res.pairing_code;

    const auto now = std::chrono::system_clock::now();
    DeviceEntity pending_dev{
        .device_id = dev_id,
        .user_id = user_id_,
        .device_status = DeviceStatus::PendingAuthorization,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    EXPECT_CALL(*device_repo_, find_by_id(dev_id)).WillRepeatedly(Return(pending_dev));

    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    auto res = manager.authorize_device(user_id_, dev_id, pin, AuthenticationLevel::PrimaryOnly);
    EXPECT_FALSE(res.success);
    EXPECT_NE(res.error_message.find("expired"), std::string::npos);
}

TEST_F(DeviceManagerTest, AuthorizeDevice_MfaVerifiedCaller_BypassesPairingPin) {
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_);

    auto enroll_res = manager.enroll_device(user_id_, bundle_.identity_pub, bundle_.signed_prekey, bundle_.signature,
                                            bundle_.one_time_prekeys, AuthenticationLevel::PrimaryOnly);
    ASSERT_TRUE(enroll_res.success);
    const auto dev_id = enroll_res.device_id;

    const auto now = std::chrono::system_clock::now();
    DeviceEntity pending_dev{
        .device_id = dev_id,
        .user_id = user_id_,
        .device_status = DeviceStatus::PendingAuthorization,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    EXPECT_CALL(*device_repo_, find_by_id(dev_id)).WillRepeatedly(Return(pending_dev));
    EXPECT_CALL(*device_repo_, authorize_device(dev_id, _)).Times(1);

    // Caller with MFA_VERIFIED does not provide pairing PIN (empty string)
    auto res = manager.authorize_device(user_id_, dev_id, "", AuthenticationLevel::MfaVerified);
    EXPECT_TRUE(res.success);
    EXPECT_EQ(res.status, DeviceStatus::Active);
}

TEST_F(DeviceManagerTest, AuthorizeDevice_WrongUser_Rejects) {
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_);

    auto dev_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();
    DeviceEntity pending_dev{
        .device_id = dev_id,
        .user_id = user_id_, // Belongs to user_id_
        .device_status = DeviceStatus::PendingAuthorization,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    EXPECT_CALL(*device_repo_, find_by_id(dev_id)).WillRepeatedly(Return(pending_dev));

    auto other_user = Uuid::generate_v7();
    auto res = manager.authorize_device(other_user, dev_id, "SOMECODE", AuthenticationLevel::MfaVerified);
    EXPECT_FALSE(res.success);
    EXPECT_NE(res.error_message.find("does not belong to user"), std::string::npos);
}

TEST_F(DeviceManagerTest, AuthorizeDevice_AlreadyActiveOrRevoked_Rejects) {
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_);

    auto dev_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();
    DeviceEntity active_dev{
        .device_id = dev_id,
        .user_id = user_id_,
        .device_status = DeviceStatus::Active,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    EXPECT_CALL(*device_repo_, find_by_id(dev_id)).WillRepeatedly(Return(active_dev));

    auto res = manager.authorize_device(user_id_, dev_id, "", AuthenticationLevel::MfaVerified);
    EXPECT_FALSE(res.success);
    EXPECT_NE(res.error_message.find("already active"), std::string::npos);

    DeviceEntity revoked_dev = active_dev;
    revoked_dev.device_status = DeviceStatus::Revoked;
    EXPECT_CALL(*device_repo_, find_by_id(dev_id)).WillRepeatedly(Return(revoked_dev));

    auto res2 = manager.authorize_device(user_id_, dev_id, "", AuthenticationLevel::MfaVerified);
    EXPECT_FALSE(res2.success);
    EXPECT_NE(res2.error_message.find("revoked"), std::string::npos);
}

TEST_F(DeviceManagerTest, InitiateDevicePairing_GeneratesFreshChallengeForPendingDevice) {
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_);

    auto dev_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();
    DeviceEntity pending_dev{
        .device_id = dev_id,
        .user_id = user_id_,
        .device_status = DeviceStatus::PendingAuthorization,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    EXPECT_CALL(*device_repo_, find_by_id(dev_id)).WillRepeatedly(Return(pending_dev));
    EXPECT_CALL(*device_repo_, authorize_device(dev_id, _)).Times(1);

    auto challenge_opt = manager.initiate_device_pairing(user_id_, dev_id, "127.0.0.1");
    ASSERT_TRUE(challenge_opt.has_value());
    EXPECT_EQ(challenge_opt->device_id, dev_id);
    EXPECT_FALSE(challenge_opt->pairing_code.empty());

    // Authorize with this freshly initiated challenge PIN
    auto res =
        manager.authorize_device(user_id_, dev_id, challenge_opt->pairing_code, AuthenticationLevel::PrimaryOnly);
    EXPECT_TRUE(res.success);
    EXPECT_EQ(res.status, DeviceStatus::Active);
}

TEST_F(DeviceManagerTest, ListUserDevices_DelegatesToRepository) {
    DeviceManager manager(device_repo_, public_key_repo_, session_manager_, audit_publisher_);

    std::vector<DeviceEntity> mock_list = {
        DeviceEntity{.device_id = Uuid::generate_v7(), .user_id = user_id_, .device_status = DeviceStatus::Active},
        DeviceEntity{
            .device_id = Uuid::generate_v7(), .user_id = user_id_, .device_status = DeviceStatus::PendingAuthorization},
    };

    EXPECT_CALL(*device_repo_, list_all_by_user_id(user_id_, false)).WillOnce(Return(mock_list));

    auto res = manager.list_user_devices(user_id_, false);
    EXPECT_EQ(res.size(), 2);
}

} // namespace
} // namespace securecloud::auth::service::test
