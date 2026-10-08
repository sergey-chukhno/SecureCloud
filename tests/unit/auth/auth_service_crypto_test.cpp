#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/crypto_directory_manager.hpp"
#include "auth/service/device_manager.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

using domain::AuthenticationLevel;
using domain::DeviceEntity;
using domain::DeviceStatus;
using domain::PrekeyBundle;
using domain::Uuid;

// ============================================================================
// Mocks
// ============================================================================

class MockCryptoDirectoryManager : public ICryptoDirectoryManager {
  public:
    MOCK_METHOD(CryptoIdentityResult, get_crypto_identity, (const Uuid& device_id), (override));

    MOCK_METHOD(DeviceCryptoDirectoryResult, get_device_crypto_directory,
                (const Uuid& user_id, const std::vector<Uuid>& filter_device_ids), (override));

    UpdateCryptoPrekeysResult update_crypto_prekeys(const Uuid& caller_user_id, const Uuid& caller_device_id,
                                                    const Uuid& target_device_id,
                                                    std::span<const uint8_t> new_signed_prekey,
                                                    std::span<const uint8_t> new_signature,
                                                    const std::vector<std::vector<uint8_t>>& new_one_time_prekeys,
                                                    std::string_view client_ip) override {
        return update_crypto_prekeys_impl(caller_user_id, caller_device_id, target_device_id,
                                          std::vector<uint8_t>(new_signed_prekey.begin(), new_signed_prekey.end()),
                                          std::vector<uint8_t>(new_signature.begin(), new_signature.end()),
                                          new_one_time_prekeys, std::string(client_ip));
    }

    MOCK_METHOD(UpdateCryptoPrekeysResult, update_crypto_prekeys_impl,
                (const Uuid&, const Uuid&, const Uuid&, const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                 const std::vector<std::vector<uint8_t>>&, const std::string&));
};

class MockDeviceManager : public IDeviceManager {
  public:
    DeviceEnrollmentResult enroll_device(const Uuid&, std::span<const uint8_t>, std::span<const uint8_t>,
                                         std::span<const uint8_t>, const std::vector<std::vector<uint8_t>>&,
                                         AuthenticationLevel, std::string_view) override {
        return {};
    }

    std::optional<DevicePairingChallenge> initiate_device_pairing(const Uuid&, const Uuid&, std::string_view) override {
        return std::nullopt;
    }

    DeviceAuthorizationResult authorize_device(const Uuid&, const Uuid&, std::string_view, AuthenticationLevel,
                                               std::string_view) override {
        return {};
    }

    DeviceRevocationResult revoke_device(const Uuid&, const Uuid&, std::string_view, AuthenticationLevel,
                                         std::string_view) override {
        return {};
    }

    MOCK_METHOD(std::optional<DeviceEntity>, get_device, (const Uuid& device_id), (override));

    MOCK_METHOD(std::vector<DeviceEntity>, list_user_devices, (const Uuid& user_id, bool include_revoked), (override));
};

// ============================================================================
// Test Fixture
// ============================================================================

class AuthServiceCryptoTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_crypto_mgr_ = std::make_shared<NiceMock<MockCryptoDirectoryManager>>();
        mock_device_mgr_ = std::make_shared<NiceMock<MockDeviceManager>>();

        auth_service_ = std::make_unique<AuthServiceImpl>(nullptr, nullptr, nullptr, nullptr, nullptr, mock_device_mgr_,
                                                          mock_crypto_mgr_);

        user_id_ = Uuid::generate_v7();
        device_id_ = Uuid::generate_v7();
    }

    std::shared_ptr<NiceMock<MockCryptoDirectoryManager>> mock_crypto_mgr_;
    std::shared_ptr<NiceMock<MockDeviceManager>> mock_device_mgr_;
    std::unique_ptr<AuthServiceImpl> auth_service_;

    Uuid user_id_;
    Uuid device_id_;
    grpc::ServerContext context_;
};

// ============================================================================
// GetDeviceCryptoDirectory Tests
// ============================================================================

TEST_F(AuthServiceCryptoTest, GetDeviceCryptoDirectory_UnconfiguredManager_ReturnsUnimplemented) {
    AuthServiceImpl unconfigured_service;
    securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
    req.set_user_id(user_id_.to_string());
    securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

    auto status = unconfigured_service.GetDeviceCryptoDirectory(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
}

TEST_F(AuthServiceCryptoTest, GetDeviceCryptoDirectory_NullRequestOrResponse_ReturnsInvalidArgument) {
    securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
    securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

    auto status1 = auth_service_->GetDeviceCryptoDirectory(&context_, nullptr, &resp);
    EXPECT_EQ(status1.error_code(), grpc::StatusCode::INVALID_ARGUMENT);

    auto status2 = auth_service_->GetDeviceCryptoDirectory(&context_, &req, nullptr);
    EXPECT_EQ(status2.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServiceCryptoTest, GetDeviceCryptoDirectory_MalformedUserId_ReturnsInvalidArgument) {
    securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
    req.set_user_id("invalid-uuid-string");
    securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

    auto status = auth_service_->GetDeviceCryptoDirectory(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServiceCryptoTest, GetDeviceCryptoDirectory_MalformedFilterDeviceId_ReturnsInvalidArgument) {
    securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
    req.set_user_id(user_id_.to_string());
    req.add_device_ids("not-a-valid-uuid");
    securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

    auto status = auth_service_->GetDeviceCryptoDirectory(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServiceCryptoTest, GetDeviceCryptoDirectory_InternalError_PropagatesInternal) {
    securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
    req.set_user_id(user_id_.to_string());
    securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

    EXPECT_CALL(*mock_crypto_mgr_, get_device_crypto_directory(user_id_, _))
        .WillOnce(Return(DeviceCryptoDirectoryResult::internal_error("Database failure")));

    auto status = auth_service_->GetDeviceCryptoDirectory(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INTERNAL);
}

TEST_F(AuthServiceCryptoTest, GetDeviceCryptoDirectory_Success_PopulatesFullBundleRecords) {
    securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
    req.set_user_id(user_id_.to_string());
    req.add_device_ids(device_id_.to_string());
    securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;

    PrekeyBundle bundle{
        .device_id = device_id_,
        .identity_key = {0x01, 0x02, 0x03},
        .identity_key_fingerprint = "SHA256:01:02:03",
        .signed_prekey = {0x04, 0x05},
        .signed_prekey_signature = {0x06, 0x07},
        .one_time_prekey = std::vector<uint8_t>{0x08, 0x09},
        .one_time_prekey_id = Uuid::generate_v7(),
        .device_status = DeviceStatus::Active,
        .signed_prekey_created_at = std::chrono::system_clock::now(),
        .remaining_one_time_prekeys = 42,
    };

    EXPECT_CALL(*mock_crypto_mgr_, get_device_crypto_directory(user_id_, std::vector<Uuid>{device_id_}))
        .WillOnce(Return(DeviceCryptoDirectoryResult::success(user_id_, {bundle})));

    auto status = auth_service_->GetDeviceCryptoDirectory(&context_, &req, &resp);
    EXPECT_TRUE(status.ok());
    ASSERT_EQ(resp.devices_size(), 1);

    const auto& rec = resp.devices(0);
    EXPECT_EQ(rec.device_id(), device_id_.to_string());
    EXPECT_EQ(rec.identity_key(), std::string("\x01\x02\x03", 3));
    EXPECT_EQ(rec.signed_prekey(), std::string("\x04\x05", 2));
    EXPECT_EQ(rec.signed_prekey_signature(), std::string("\x06\x07", 2));
    EXPECT_EQ(rec.one_time_prekey(), std::string("\x08\x09", 2));
    EXPECT_EQ(rec.one_time_prekey_id(), bundle.one_time_prekey_id->to_string());
    EXPECT_EQ(rec.status(), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    EXPECT_EQ(rec.identity_key_fingerprint(), "SHA256:01:02:03");
    EXPECT_EQ(rec.remaining_one_time_prekeys(), 42);
    EXPECT_GT(rec.signed_prekey_created_at_epoch_ms(), 0);
}

// ============================================================================
// GetCryptoIdentity Tests
// ============================================================================

TEST_F(AuthServiceCryptoTest, GetCryptoIdentity_UnconfiguredManager_ReturnsUnimplemented) {
    AuthServiceImpl unconfigured_service;
    securecloud::auth::v1::GetCryptoIdentityRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::GetCryptoIdentityResponse resp;

    auto status = unconfigured_service.GetCryptoIdentity(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
}

TEST_F(AuthServiceCryptoTest, GetCryptoIdentity_MalformedDeviceId_ReturnsInvalidArgument) {
    securecloud::auth::v1::GetCryptoIdentityRequest req;
    req.set_device_id("invalid-uuid");
    securecloud::auth::v1::GetCryptoIdentityResponse resp;

    auto status = auth_service_->GetCryptoIdentity(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServiceCryptoTest, GetCryptoIdentity_NotFound_ReturnsNotFound) {
    securecloud::auth::v1::GetCryptoIdentityRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::GetCryptoIdentityResponse resp;

    EXPECT_CALL(*mock_crypto_mgr_, get_crypto_identity(device_id_)).WillOnce(Return(CryptoIdentityResult::not_found()));

    auto status = auth_service_->GetCryptoIdentity(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
}

TEST_F(AuthServiceCryptoTest, GetCryptoIdentity_RevokedDevice_ReturnsRevokedStatusAndOmitsPrekeys) {
    securecloud::auth::v1::GetCryptoIdentityRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::GetCryptoIdentityResponse resp;

    EXPECT_CALL(*mock_crypto_mgr_, get_crypto_identity(device_id_))
        .WillOnce(Return(CryptoIdentityResult::revoked(device_id_)));

    auto status = auth_service_->GetCryptoIdentity(&context_, &req, &resp);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(resp.device_id(), device_id_.to_string());
    EXPECT_EQ(resp.status(), securecloud::auth::v1::DEVICE_STATUS_REVOKED);
    EXPECT_TRUE(resp.signed_prekey().empty());
    EXPECT_TRUE(resp.signed_prekey_signature().empty());
}

TEST_F(AuthServiceCryptoTest, GetCryptoIdentity_PendingAuthorization_ReturnsPendingStatusAndOmitsPrekeys) {
    securecloud::auth::v1::GetCryptoIdentityRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::GetCryptoIdentityResponse resp;

    EXPECT_CALL(*mock_crypto_mgr_, get_crypto_identity(device_id_))
        .WillOnce(Return(CryptoIdentityResult::pending_authorization(device_id_)));

    auto status = auth_service_->GetCryptoIdentity(&context_, &req, &resp);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(resp.device_id(), device_id_.to_string());
    EXPECT_EQ(resp.status(), securecloud::auth::v1::DEVICE_STATUS_PENDING_AUTHORIZATION);
    EXPECT_TRUE(resp.signed_prekey().empty());
    EXPECT_TRUE(resp.signed_prekey_signature().empty());
}

TEST_F(AuthServiceCryptoTest, GetCryptoIdentity_ActiveDevice_ReturnsFullIdentityAndFingerprint) {
    securecloud::auth::v1::GetCryptoIdentityRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::GetCryptoIdentityResponse resp;

    std::vector<uint8_t> id_key = {0xAA, 0xBB};
    std::vector<uint8_t> spk = {0xCC, 0xDD};
    std::vector<uint8_t> sig = {0xEE, 0xFF};
    auto created_at = std::chrono::system_clock::now();

    EXPECT_CALL(*mock_crypto_mgr_, get_crypto_identity(device_id_))
        .WillOnce(Return(CryptoIdentityResult::success(device_id_, DeviceStatus::Active, id_key, "SHA256:AA:BB", spk,
                                                       sig, created_at)));

    DeviceEntity dev{.device_id = device_id_, .user_id = user_id_, .device_status = DeviceStatus::Active};
    EXPECT_CALL(*mock_device_mgr_, get_device(device_id_)).WillOnce(Return(dev));

    auto status = auth_service_->GetCryptoIdentity(&context_, &req, &resp);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(resp.device_id(), device_id_.to_string());
    EXPECT_EQ(resp.user_id(), user_id_.to_string());
    EXPECT_EQ(resp.status(), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    EXPECT_EQ(resp.identity_key(), std::string("\xAA\xBB", 2));
    EXPECT_EQ(resp.identity_key_fingerprint(), "SHA256:AA:BB");
    EXPECT_EQ(resp.signed_prekey(), std::string("\xCC\xDD", 2));
    EXPECT_EQ(resp.signed_prekey_signature(), std::string("\xEE\xFF", 2));
    EXPECT_GT(resp.signed_prekey_created_at_epoch_ms(), 0);
}

// ============================================================================
// UpdateCryptoPrekeys Tests
// ============================================================================

TEST_F(AuthServiceCryptoTest, UpdateCryptoPrekeys_UnconfiguredManager_ReturnsUnimplemented) {
    AuthServiceImpl unconfigured_service;
    securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

    auto status = unconfigured_service.UpdateCryptoPrekeys(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
}

TEST_F(AuthServiceCryptoTest, UpdateCryptoPrekeys_MissingCallerIdentityMetadata_ReturnsUnauthenticated) {
    securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

    // No metadata or test override set
    auto status = auth_service_->UpdateCryptoPrekeys(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

TEST_F(AuthServiceCryptoTest, UpdateCryptoPrekeys_MalformedTargetDeviceId_ReturnsInvalidArgument) {
    auth_service_->set_caller_identity_for_testing(user_id_, device_id_);

    securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
    req.set_device_id("invalid-target-uuid");
    securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

    auto status = auth_service_->UpdateCryptoPrekeys(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServiceCryptoTest, UpdateCryptoPrekeys_CallerOwnershipMismatch_ReturnsPermissionDenied) {
    auth_service_->set_caller_identity_for_testing(user_id_, device_id_);

    securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
    req.set_device_id(device_id_.to_string());
    req.set_signed_prekey("some-key");
    securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

    EXPECT_CALL(*mock_crypto_mgr_, update_crypto_prekeys_impl(user_id_, device_id_, device_id_, _, _, _, _))
        .WillOnce(Return(UpdateCryptoPrekeysResult::permission_denied("Caller does not own target device")));

    auto status = auth_service_->UpdateCryptoPrekeys(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(AuthServiceCryptoTest, UpdateCryptoPrekeys_TargetNotFound_ReturnsNotFound) {
    auth_service_->set_caller_identity_for_testing(user_id_, device_id_);

    securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

    EXPECT_CALL(*mock_crypto_mgr_, update_crypto_prekeys_impl(user_id_, device_id_, device_id_, _, _, _, _))
        .WillOnce(Return(UpdateCryptoPrekeysResult::not_found()));

    auto status = auth_service_->UpdateCryptoPrekeys(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
}

TEST_F(AuthServiceCryptoTest, UpdateCryptoPrekeys_InvalidSignature_ReturnsInvalidArgument) {
    auth_service_->set_caller_identity_for_testing(user_id_, device_id_);

    securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

    EXPECT_CALL(*mock_crypto_mgr_, update_crypto_prekeys_impl(user_id_, device_id_, device_id_, _, _, _, _))
        .WillOnce(Return(UpdateCryptoPrekeysResult::invalid_argument("Signature verification failed")));

    auto status = auth_service_->UpdateCryptoPrekeys(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServiceCryptoTest, UpdateCryptoPrekeys_Success_PopulatesResponseFields) {
    auth_service_->set_caller_identity_for_testing(user_id_, device_id_);

    securecloud::auth::v1::UpdateCryptoPrekeysRequest req;
    req.set_device_id(device_id_.to_string());
    req.set_signed_prekey("signed-prekey-32-bytes");
    req.set_signed_prekey_signature("signature-64-bytes");
    req.add_one_time_prekeys("otk-1");
    req.add_one_time_prekeys("otk-2");
    securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;

    EXPECT_CALL(*mock_crypto_mgr_, update_crypto_prekeys_impl(user_id_, device_id_, device_id_, _, _, _, _))
        .WillOnce(Return(UpdateCryptoPrekeysResult::success(device_id_, true, 2, 25)));

    auto status = auth_service_->UpdateCryptoPrekeys(&context_, &req, &resp);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(resp.active_one_time_prekey_count(), 25);
    EXPECT_GT(resp.updated_at_epoch_ms(), 0);
}

} // namespace
} // namespace securecloud::auth::service::test
