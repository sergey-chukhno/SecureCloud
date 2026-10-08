#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/device_manager.hpp"
#include "auth/service/session_manager.hpp"
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
using domain::Uuid;

// ============================================================================
// Mock Classes
// ============================================================================

class MockSessionManager : public ISessionManager {
  public:
    MOCK_METHOD(SessionEstablishmentResult, establish_session, (const domain::UserEntity&, const domain::Uuid&),
                (override));
    MOCK_METHOD(domain::SessionValidationResult, validate_session, (const domain::Uuid&, std::optional<domain::Uuid>),
                (override));
    MOCK_METHOD(std::vector<domain::SessionEntity>, list_active_sessions_for_user, (const domain::Uuid&), (override));
    MOCK_METHOD(std::vector<domain::SessionEntity>, list_active_sessions_for_device, (const domain::Uuid&), (override));
    domain::SessionRevocationResult revoke_session(const domain::Uuid& /*session_id*/,
                                                   std::string_view /*reason*/) override {
        return domain::SessionRevocationResult::success(1);
    }
    domain::SessionRevocationResult revoke_all_device_sessions(const domain::Uuid& device_id,
                                                               std::string_view reason) override {
        return revoke_all_device_sessions_impl(device_id, std::string(reason));
    }
    MOCK_METHOD(domain::SessionRevocationResult, revoke_all_device_sessions_impl,
                (const domain::Uuid&, const std::string&));
    domain::SessionRevocationResult revoke_all_user_sessions(const domain::Uuid& /*user_id*/,
                                                             std::string_view /*reason*/) override {
        return domain::SessionRevocationResult::success(1);
    }
};

class MockDeviceManager : public IDeviceManager {
  public:
    DeviceEnrollmentResult enroll_device(const domain::Uuid& user_id, std::span<const uint8_t> identity_key,
                                         std::span<const uint8_t> signed_prekey, std::span<const uint8_t> signature,
                                         const std::vector<std::vector<uint8_t>>& one_time_prekeys,
                                         domain::AuthenticationLevel caller_auth_level,
                                         std::string_view client_ip) override {
        return enroll_device_impl(user_id, std::vector<uint8_t>(identity_key.begin(), identity_key.end()),
                                  std::vector<uint8_t>(signed_prekey.begin(), signed_prekey.end()),
                                  std::vector<uint8_t>(signature.begin(), signature.end()), one_time_prekeys,
                                  caller_auth_level, std::string(client_ip));
    }
    MOCK_METHOD(DeviceEnrollmentResult, enroll_device_impl,
                (const domain::Uuid&, const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                 const std::vector<uint8_t>&, const std::vector<std::vector<uint8_t>>&, domain::AuthenticationLevel,
                 const std::string&));

    std::optional<DevicePairingChallenge> initiate_device_pairing(const domain::Uuid& user_id,
                                                                  const domain::Uuid& pending_device_id,
                                                                  std::string_view client_ip) override {
        return initiate_device_pairing_impl(user_id, pending_device_id, std::string(client_ip));
    }
    MOCK_METHOD(std::optional<DevicePairingChallenge>, initiate_device_pairing_impl,
                (const domain::Uuid&, const domain::Uuid&, const std::string&));

    DeviceAuthorizationResult authorize_device(const domain::Uuid& user_id, const domain::Uuid& device_id,
                                               std::string_view pairing_code,
                                               domain::AuthenticationLevel caller_auth_level,
                                               std::string_view client_ip) override {
        return authorize_device_impl(user_id, device_id, std::string(pairing_code), caller_auth_level,
                                     std::string(client_ip));
    }
    MOCK_METHOD(DeviceAuthorizationResult, authorize_device_impl,
                (const domain::Uuid&, const domain::Uuid&, const std::string&, domain::AuthenticationLevel,
                 const std::string&));

    DeviceRevocationResult revoke_device(const domain::Uuid& user_id, const domain::Uuid& device_id,
                                         std::string_view reason, domain::AuthenticationLevel caller_auth_level,
                                         std::string_view client_ip) override {
        return revoke_device_impl(user_id, device_id, std::string(reason), caller_auth_level, std::string(client_ip));
    }
    MOCK_METHOD(DeviceRevocationResult, revoke_device_impl,
                (const domain::Uuid&, const domain::Uuid&, const std::string&, domain::AuthenticationLevel,
                 const std::string&));

    MOCK_METHOD(std::optional<domain::DeviceEntity>, get_device, (const domain::Uuid&), (override));

    MOCK_METHOD(std::vector<domain::DeviceEntity>, list_user_devices, (const domain::Uuid&, bool), (override));
};

// ============================================================================
// Test Fixture
// ============================================================================

class AuthServiceDeviceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_device_mgr_ = std::make_shared<NiceMock<MockDeviceManager>>();
        mock_session_mgr_ = std::make_shared<NiceMock<MockSessionManager>>();

        auth_service_ =
            std::make_unique<AuthServiceImpl>(nullptr, mock_session_mgr_, nullptr, nullptr, nullptr, mock_device_mgr_);

        user_id_ = Uuid::generate_v7();
        device_id_ = Uuid::generate_v7();
    }

    std::shared_ptr<NiceMock<MockDeviceManager>> mock_device_mgr_;
    std::shared_ptr<NiceMock<MockSessionManager>> mock_session_mgr_;
    std::unique_ptr<AuthServiceImpl> auth_service_;

    Uuid user_id_;
    Uuid device_id_;
};

// ============================================================================
// Unconfigured Service Tests
// ============================================================================

TEST_F(AuthServiceDeviceTest, DeviceRpc_WhenDeviceManagerNull_ReturnsUnimplemented) {
    AuthServiceImpl unconfigured_service(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    ::grpc::ServerContext context;

    {
        securecloud::auth::v1::RegisterDeviceRequest req;
        securecloud::auth::v1::RegisterDeviceResponse resp;
        EXPECT_EQ(unconfigured_service.RegisterDevice(&context, &req, &resp).error_code(),
                  ::grpc::StatusCode::UNIMPLEMENTED);
    }
    {
        securecloud::auth::v1::InitiateDevicePairingRequest req;
        securecloud::auth::v1::InitiateDevicePairingResponse resp;
        EXPECT_EQ(unconfigured_service.InitiateDevicePairing(&context, &req, &resp).error_code(),
                  ::grpc::StatusCode::UNIMPLEMENTED);
    }
    {
        securecloud::auth::v1::AuthorizeDeviceRequest req;
        securecloud::auth::v1::AuthorizeDeviceResponse resp;
        EXPECT_EQ(unconfigured_service.AuthorizeDevice(&context, &req, &resp).error_code(),
                  ::grpc::StatusCode::UNIMPLEMENTED);
    }
    {
        securecloud::auth::v1::GetDeviceRequest req;
        securecloud::auth::v1::GetDeviceResponse resp;
        EXPECT_EQ(unconfigured_service.GetDevice(&context, &req, &resp).error_code(),
                  ::grpc::StatusCode::UNIMPLEMENTED);
    }
    {
        securecloud::auth::v1::ListUserDevicesRequest req;
        securecloud::auth::v1::ListUserDevicesResponse resp;
        EXPECT_EQ(unconfigured_service.ListUserDevices(&context, &req, &resp).error_code(),
                  ::grpc::StatusCode::UNIMPLEMENTED);
    }
    {
        securecloud::auth::v1::RevokeDeviceRequest req;
        securecloud::auth::v1::RevokeDeviceResponse resp;
        EXPECT_EQ(unconfigured_service.RevokeDevice(&context, &req, &resp).error_code(),
                  ::grpc::StatusCode::UNIMPLEMENTED);
    }
}

// ============================================================================
// Null Argument Tests
// ============================================================================

TEST_F(AuthServiceDeviceTest, DeviceRpc_NullArgs_ReturnsInvalidArgument) {
    ::grpc::ServerContext context;

    EXPECT_EQ(auth_service_->RegisterDevice(&context, nullptr, nullptr).error_code(),
              ::grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(auth_service_->InitiateDevicePairing(&context, nullptr, nullptr).error_code(),
              ::grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(auth_service_->AuthorizeDevice(&context, nullptr, nullptr).error_code(),
              ::grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(auth_service_->GetDevice(&context, nullptr, nullptr).error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(auth_service_->ListUserDevices(&context, nullptr, nullptr).error_code(),
              ::grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(auth_service_->RevokeDevice(&context, nullptr, nullptr).error_code(),
              ::grpc::StatusCode::INVALID_ARGUMENT);
}

// ============================================================================
// Invalid UUID Format Tests
// ============================================================================

TEST_F(AuthServiceDeviceTest, DeviceRpc_InvalidUuidFormat_ReturnsInvalidArgument) {
    ::grpc::ServerContext context;
    auth_service_->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    {
        securecloud::auth::v1::RegisterDeviceRequest req;
        req.set_user_id("not-a-valid-uuid");
        securecloud::auth::v1::RegisterDeviceResponse resp;
        EXPECT_EQ(auth_service_->RegisterDevice(&context, &req, &resp).error_code(),
                  ::grpc::StatusCode::INVALID_ARGUMENT);
    }
    {
        securecloud::auth::v1::InitiateDevicePairingRequest req;
        req.set_user_id(user_id_.to_string());
        req.set_device_id("invalid-dev-uuid");
        securecloud::auth::v1::InitiateDevicePairingResponse resp;
        EXPECT_EQ(auth_service_->InitiateDevicePairing(&context, &req, &resp).error_code(),
                  ::grpc::StatusCode::INVALID_ARGUMENT);
    }
    {
        securecloud::auth::v1::AuthorizeDeviceRequest req;
        req.set_user_id("invalid-user-uuid");
        req.set_device_id(device_id_.to_string());
        securecloud::auth::v1::AuthorizeDeviceResponse resp;
        EXPECT_EQ(auth_service_->AuthorizeDevice(&context, &req, &resp).error_code(),
                  ::grpc::StatusCode::INVALID_ARGUMENT);
    }
    {
        securecloud::auth::v1::GetDeviceRequest req;
        req.set_device_id("invalid-uuid");
        securecloud::auth::v1::GetDeviceResponse resp;
        EXPECT_EQ(auth_service_->GetDevice(&context, &req, &resp).error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);
    }
    {
        securecloud::auth::v1::ListUserDevicesRequest req;
        req.set_user_id("invalid-uuid");
        securecloud::auth::v1::ListUserDevicesResponse resp;
        EXPECT_EQ(auth_service_->ListUserDevices(&context, &req, &resp).error_code(),
                  ::grpc::StatusCode::INVALID_ARGUMENT);
    }
    {
        securecloud::auth::v1::RevokeDeviceRequest req;
        req.set_device_id("invalid-uuid");
        securecloud::auth::v1::RevokeDeviceResponse resp;
        EXPECT_EQ(auth_service_->RevokeDevice(&context, &req, &resp).error_code(),
                  ::grpc::StatusCode::INVALID_ARGUMENT);
    }
}

// ============================================================================
// RegisterDevice RPC Tests
// ============================================================================

TEST_F(AuthServiceDeviceTest, RegisterDevice_MfaVerified_EnrollsActiveDevice) {
    ::grpc::ServerContext context;
    auth_service_->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    DeviceEnrollmentResult expected_result;
    expected_result.success = true;
    expected_result.device_id = device_id_;
    expected_result.status = DeviceStatus::Active;

    EXPECT_CALL(*mock_device_mgr_, enroll_device_impl(user_id_, _, _, _, _, AuthenticationLevel::MfaVerified, _))
        .WillOnce(Return(expected_result));

    securecloud::auth::v1::RegisterDeviceRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_identity_key(std::string(32, '\x01'));
    req.set_signed_prekey(std::string(32, '\x02'));
    req.set_signed_prekey_signature(std::string(64, '\x03'));

    securecloud::auth::v1::RegisterDeviceResponse resp;
    auto status = auth_service_->RegisterDevice(&context, &req, &resp);

    ASSERT_TRUE(status.ok());
    EXPECT_EQ(resp.device_id(), device_id_.to_string());
    EXPECT_EQ(resp.status(), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    EXPECT_TRUE(resp.pairing_code().empty());
    EXPECT_GT(resp.registered_at_epoch_ms(), 0);
}

TEST_F(AuthServiceDeviceTest, RegisterDevice_PrimaryOnly_EnrollsPendingDeviceWithPairingCode) {
    ::grpc::ServerContext context;
    auth_service_->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    DeviceEnrollmentResult expected_result;
    expected_result.success = true;
    expected_result.device_id = device_id_;
    expected_result.status = DeviceStatus::PendingAuthorization;
    expected_result.pairing_code = "PAIR1234";
    expected_result.pairing_code_expires_at = std::chrono::system_clock::now() + std::chrono::minutes(10);

    EXPECT_CALL(*mock_device_mgr_, enroll_device_impl(user_id_, _, _, _, _, AuthenticationLevel::PrimaryOnly, _))
        .WillOnce(Return(expected_result));

    securecloud::auth::v1::RegisterDeviceRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_identity_key(std::string(32, '\x01'));
    req.set_signed_prekey(std::string(32, '\x02'));
    req.set_signed_prekey_signature(std::string(64, '\x03'));

    securecloud::auth::v1::RegisterDeviceResponse resp;
    auto status = auth_service_->RegisterDevice(&context, &req, &resp);

    ASSERT_TRUE(status.ok());
    EXPECT_EQ(resp.device_id(), device_id_.to_string());
    EXPECT_EQ(resp.status(), securecloud::auth::v1::DEVICE_STATUS_PENDING_AUTHORIZATION);
    EXPECT_EQ(resp.pairing_code(), "PAIR1234");
    EXPECT_GT(resp.pairing_code_expires_at_epoch_ms(), 0);
}

TEST_F(AuthServiceDeviceTest, RegisterDevice_EnrollmentFailed_ReturnsInvalidArgument) {
    ::grpc::ServerContext context;
    auth_service_->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    DeviceEnrollmentResult failure;
    failure.success = false;
    failure.error_message = "Invalid cryptographic public key length";

    EXPECT_CALL(*mock_device_mgr_, enroll_device_impl(_, _, _, _, _, _, _)).WillOnce(Return(failure));

    securecloud::auth::v1::RegisterDeviceRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_identity_key("invalid-length");

    securecloud::auth::v1::RegisterDeviceResponse resp;
    auto status = auth_service_->RegisterDevice(&context, &req, &resp);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_NE(status.error_message().find("Invalid cryptographic public key length"), std::string::npos);
}

// ============================================================================
// InitiateDevicePairing RPC Tests
// ============================================================================

TEST_F(AuthServiceDeviceTest, InitiateDevicePairing_PendingDevice_ReturnsPairingCode) {
    ::grpc::ServerContext context;

    DevicePairingChallenge challenge;
    challenge.pairing_code = "ABCDEFGH";
    challenge.expires_at = std::chrono::system_clock::now() + std::chrono::minutes(10);

    EXPECT_CALL(*mock_device_mgr_, initiate_device_pairing_impl(user_id_, device_id_, _)).WillOnce(Return(challenge));

    securecloud::auth::v1::InitiateDevicePairingRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_device_id(device_id_.to_string());

    securecloud::auth::v1::InitiateDevicePairingResponse resp;
    auto status = auth_service_->InitiateDevicePairing(&context, &req, &resp);

    ASSERT_TRUE(status.ok());
    EXPECT_EQ(resp.pairing_code(), "ABCDEFGH");
    EXPECT_GT(resp.expires_at_epoch_ms(), 0);
}

TEST_F(AuthServiceDeviceTest, InitiateDevicePairing_DeviceNotFound_ReturnsNotFound) {
    ::grpc::ServerContext context;

    EXPECT_CALL(*mock_device_mgr_, initiate_device_pairing_impl(user_id_, device_id_, _))
        .WillOnce(Return(std::nullopt));

    securecloud::auth::v1::InitiateDevicePairingRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_device_id(device_id_.to_string());

    securecloud::auth::v1::InitiateDevicePairingResponse resp;
    auto status = auth_service_->InitiateDevicePairing(&context, &req, &resp);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::NOT_FOUND);
}

// ============================================================================
// AuthorizeDevice RPC Tests
// ============================================================================

TEST_F(AuthServiceDeviceTest, AuthorizeDevice_ValidCode_PromotesToActive) {
    ::grpc::ServerContext context;
    auth_service_->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    DeviceAuthorizationResult expected_result;
    expected_result.success = true;
    expected_result.device_id = device_id_;
    expected_result.status = DeviceStatus::Active;

    EXPECT_CALL(*mock_device_mgr_,
                authorize_device_impl(user_id_, device_id_, "12345678", AuthenticationLevel::MfaVerified, _))
        .WillOnce(Return(expected_result));

    securecloud::auth::v1::AuthorizeDeviceRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_device_id(device_id_.to_string());
    req.set_pairing_code("12345678");

    securecloud::auth::v1::AuthorizeDeviceResponse resp;
    auto status = auth_service_->AuthorizeDevice(&context, &req, &resp);

    ASSERT_TRUE(status.ok());
    EXPECT_TRUE(resp.authorized());
    EXPECT_EQ(resp.status(), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    EXPECT_GT(resp.authorized_at_epoch_ms(), 0);
}

TEST_F(AuthServiceDeviceTest, AuthorizeDevice_InvalidCode_ReturnsUnauthenticated) {
    ::grpc::ServerContext context;
    auth_service_->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    DeviceAuthorizationResult failure;
    failure.success = false;
    failure.is_locked_out = false;
    failure.error_message = "Invalid pairing code";

    EXPECT_CALL(*mock_device_mgr_, authorize_device_impl(user_id_, device_id_, "WRONGPIN", _, _))
        .WillOnce(Return(failure));

    securecloud::auth::v1::AuthorizeDeviceRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_device_id(device_id_.to_string());
    req.set_pairing_code("WRONGPIN");

    securecloud::auth::v1::AuthorizeDeviceResponse resp;
    auto status = auth_service_->AuthorizeDevice(&context, &req, &resp);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_NE(status.error_message().find("Invalid pairing code"), std::string::npos);
}

TEST_F(AuthServiceDeviceTest, AuthorizeDevice_LockedOut_ReturnsPermissionDenied) {
    ::grpc::ServerContext context;

    DeviceAuthorizationResult lockout;
    lockout.success = false;
    lockout.is_locked_out = true;
    lockout.error_message = "Too many failed attempts. Pairing challenge locked out.";

    EXPECT_CALL(*mock_device_mgr_, authorize_device_impl(user_id_, device_id_, "WRONGPIN", _, _))
        .WillOnce(Return(lockout));

    securecloud::auth::v1::AuthorizeDeviceRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_device_id(device_id_.to_string());
    req.set_pairing_code("WRONGPIN");

    securecloud::auth::v1::AuthorizeDeviceResponse resp;
    auto status = auth_service_->AuthorizeDevice(&context, &req, &resp);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_NE(status.error_message().find("locked out"), std::string::npos);
}

// ============================================================================
// GetDevice RPC Tests
// ============================================================================

TEST_F(AuthServiceDeviceTest, GetDevice_ExistingDevice_ReturnsDeviceDetails) {
    ::grpc::ServerContext context;

    DeviceEntity entity;
    entity.device_id = device_id_;
    entity.user_id = user_id_;
    entity.device_status = DeviceStatus::Active;
    entity.registered_at = std::chrono::system_clock::now();
    entity.last_authenticated_at = std::chrono::system_clock::now();

    EXPECT_CALL(*mock_device_mgr_, get_device(device_id_)).WillOnce(Return(entity));

    securecloud::auth::v1::GetDeviceRequest req;
    req.set_device_id(device_id_.to_string());

    securecloud::auth::v1::GetDeviceResponse resp;
    auto status = auth_service_->GetDevice(&context, &req, &resp);

    ASSERT_TRUE(status.ok());
    EXPECT_EQ(resp.device().device_id(), device_id_.to_string());
    EXPECT_EQ(resp.device().user_id(), user_id_.to_string());
    EXPECT_EQ(resp.device().device_status(), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
}

TEST_F(AuthServiceDeviceTest, GetDevice_NotFound_ReturnsNotFound) {
    ::grpc::ServerContext context;

    EXPECT_CALL(*mock_device_mgr_, get_device(device_id_)).WillOnce(Return(std::nullopt));

    securecloud::auth::v1::GetDeviceRequest req;
    req.set_device_id(device_id_.to_string());

    securecloud::auth::v1::GetDeviceResponse resp;
    auto status = auth_service_->GetDevice(&context, &req, &resp);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::NOT_FOUND);
}

// ============================================================================
// ListUserDevices RPC Tests
// ============================================================================

TEST_F(AuthServiceDeviceTest, ListUserDevices_ReturnsUserDeviceList) {
    ::grpc::ServerContext context;

    DeviceEntity d1;
    d1.device_id = device_id_;
    d1.user_id = user_id_;
    d1.device_status = DeviceStatus::Active;
    d1.registered_at = std::chrono::system_clock::now();
    d1.last_authenticated_at = std::chrono::system_clock::now();

    DeviceEntity d2;
    d2.device_id = Uuid::generate_v7();
    d2.user_id = user_id_;
    d2.device_status = DeviceStatus::Revoked;
    d2.registered_at = std::chrono::system_clock::now();
    d2.revoked_at = std::chrono::system_clock::now();
    d2.revocation_reason = "Lost hardware";
    d2.last_authenticated_at = std::chrono::system_clock::now();

    EXPECT_CALL(*mock_device_mgr_, list_user_devices(user_id_, true))
        .WillOnce(Return(std::vector<DeviceEntity>{d1, d2}));

    securecloud::auth::v1::ListUserDevicesRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_include_revoked(true);

    securecloud::auth::v1::ListUserDevicesResponse resp;
    auto status = auth_service_->ListUserDevices(&context, &req, &resp);

    ASSERT_TRUE(status.ok());
    ASSERT_EQ(resp.devices_size(), 2);
    EXPECT_EQ(resp.devices(0).device_id(), d1.device_id.to_string());
    EXPECT_EQ(resp.devices(0).device_status(), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    EXPECT_EQ(resp.devices(1).device_id(), d2.device_id.to_string());
    EXPECT_EQ(resp.devices(1).device_status(), securecloud::auth::v1::DEVICE_STATUS_REVOKED);
    EXPECT_EQ(resp.devices(1).revocation_reason(), "Lost hardware");
}

// ============================================================================
// RevokeDevice RPC Tests
// ============================================================================

TEST_F(AuthServiceDeviceTest, RevokeDevice_WithoutMfa_ReturnsPermissionDenied) {
    ::grpc::ServerContext context;
    // Default or PrimaryOnly auth level
    auth_service_->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    securecloud::auth::v1::RevokeDeviceRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_device_id(device_id_.to_string());
    req.set_reason("Compromised token");

    securecloud::auth::v1::RevokeDeviceResponse resp;
    auto status = auth_service_->RevokeDevice(&context, &req, &resp);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_NE(status.error_message().find("requires multi-factor authentication"), std::string::npos);
}

TEST_F(AuthServiceDeviceTest, RevokeDevice_WithMfa_DeviceNotFound_ReturnsNotFound) {
    ::grpc::ServerContext context;
    auth_service_->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    DeviceRevocationResult not_found_res;
    not_found_res.success = false;
    not_found_res.is_not_found = true;
    not_found_res.error_message = "Device not found";

    EXPECT_CALL(*mock_device_mgr_, revoke_device_impl(user_id_, device_id_, "Lost phone", _, _))
        .WillOnce(Return(not_found_res));

    securecloud::auth::v1::RevokeDeviceRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_device_id(device_id_.to_string());
    req.set_reason("Lost phone");

    securecloud::auth::v1::RevokeDeviceResponse resp;
    auto status = auth_service_->RevokeDevice(&context, &req, &resp);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::NOT_FOUND);
}

TEST_F(AuthServiceDeviceTest, RevokeDevice_WithMfa_Success_ReturnsRevokedResponse) {
    ::grpc::ServerContext context;
    auth_service_->set_caller_auth_level_for_testing(
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    DeviceRevocationResult success_res;
    success_res.success = true;
    success_res.device_id = device_id_;

    EXPECT_CALL(*mock_device_mgr_, revoke_device_impl(user_id_, device_id_, "Revoking old laptop", _, _))
        .WillOnce(Return(success_res));

    securecloud::auth::v1::RevokeDeviceRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_device_id(device_id_.to_string());
    req.set_reason("Revoking old laptop");

    securecloud::auth::v1::RevokeDeviceResponse resp;
    auto status = auth_service_->RevokeDevice(&context, &req, &resp);

    ASSERT_TRUE(status.ok());
    EXPECT_TRUE(resp.revoked());
    EXPECT_GT(resp.revoked_at_epoch_ms(), 0);
}

} // namespace
} // namespace securecloud::auth::service::test
