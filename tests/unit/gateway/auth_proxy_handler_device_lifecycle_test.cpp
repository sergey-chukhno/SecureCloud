#include "grpc/auth_client_interface.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/routing/router.hpp"
#include "securecloud/auth/v1/auth.pb.h"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace securecloud::gateway::http::test {
namespace {

using ::testing::_;
using ::testing::Return;

class MockAuthClient : public securecloud::gateway::grpc::IAuthClient {
  public:
    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>, authenticate,
                (const securecloud::auth::v1::AuthenticateRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::ValidateSessionResponse>, validate_session,
                (const securecloud::auth::v1::ValidateSessionRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::RefreshSessionResponse>, refresh_session,
                (const securecloud::auth::v1::RefreshSessionRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::RevokeSessionResponse>, revoke_session,
                (const securecloud::auth::v1::RevokeSessionRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetUserResponse>, get_user,
                (const securecloud::auth::v1::GetUserRequest& req, securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::RegisterDeviceResponse>, register_device,
                (const securecloud::auth::v1::RegisterDeviceRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetCryptoIdentityResponse>,
                get_crypto_identity,
                (const securecloud::auth::v1::GetCryptoIdentityRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetDeviceCryptoDirectoryResponse>,
                get_device_crypto_directory,
                (const securecloud::auth::v1::GetDeviceCryptoDirectoryRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::UpdateCryptoPrekeysResponse>,
                update_crypto_prekeys,
                (const securecloud::auth::v1::UpdateCryptoPrekeysRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetPrekeyInventoryStatusResponse>,
                get_prekey_inventory_status,
                (const securecloud::auth::v1::GetPrekeyInventoryStatusRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::ClaimPrekeyBundleResponse>,
                claim_prekey_bundle,
                (const securecloud::auth::v1::ClaimPrekeyBundleRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetPublicSigningKeyResponse>,
                get_public_signing_key,
                (const securecloud::auth::v1::GetPublicSigningKeyRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::InitiateMfaEnrollmentResponse>,
                initiate_mfa_enrollment,
                (const securecloud::auth::v1::InitiateMfaEnrollmentRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::ConfirmMfaEnrollmentResponse>,
                confirm_mfa_enrollment,
                (const securecloud::auth::v1::ConfirmMfaEnrollmentRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::VerifyMfaChallengeResponse>,
                verify_mfa_challenge,
                (const securecloud::auth::v1::VerifyMfaChallengeRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::DisableMfaResponse>, disable_mfa,
                (const securecloud::auth::v1::DisableMfaRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetDeviceResponse>, get_device,
                (const securecloud::auth::v1::GetDeviceRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::ListUserDevicesResponse>, list_user_devices,
                (const securecloud::auth::v1::ListUserDevicesRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::InitiateDevicePairingResponse>,
                initiate_device_pairing,
                (const securecloud::auth::v1::InitiateDevicePairingRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthorizeDeviceResponse>, authorize_device,
                (const securecloud::auth::v1::AuthorizeDeviceRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::RevokeDeviceResponse>, revoke_device,
                (const securecloud::auth::v1::RevokeDeviceRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));
};

AuthenticatedContext make_context(std::string user_id = "user-alice-123", std::string device_id = "dev-main-001",
                                  securecloud::auth::v1::AuthenticationLevel level =
                                      securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                  std::vector<std::string> scopes = {"access"}) {
    return AuthenticatedContext(std::move(user_id), std::move(device_id), "sess-123", level, std::move(scopes),
                                2000000000000LL);
}

class AuthProxyHandlerDeviceLifecycleTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_client_ = std::make_shared<MockAuthClient>();
        handler_ = std::make_unique<AuthProxyHandler>(mock_client_);
    }

    std::shared_ptr<MockAuthClient> mock_client_;
    std::unique_ptr<AuthProxyHandler> handler_;
};

// ============================================================================
// 1. List Devices Tests (GET /api/v1/devices)
// ============================================================================

TEST_F(AuthProxyHandlerDeviceLifecycleTest, ListDevicesSuccess) {
    securecloud::auth::v1::ListUserDevicesResponse grpc_resp;
    auto* dev1 = grpc_resp.add_devices();
    dev1->set_device_id("dev-phone-1");
    dev1->set_user_id("user-alice-123");
    dev1->set_device_status(securecloud::auth::v1::DeviceStatus::DEVICE_STATUS_ACTIVE);
    dev1->set_registered_at_epoch_ms(1670000000000LL);
    dev1->set_revoked_at_epoch_ms(0);
    dev1->set_last_authenticated_at_epoch_ms(1670001000000LL);

    auto* dev2 = grpc_resp.add_devices();
    dev2->set_device_id("dev-laptop-2");
    dev2->set_user_id("user-alice-123");
    dev2->set_device_status(securecloud::auth::v1::DeviceStatus::DEVICE_STATUS_REVOKED);
    dev2->set_registered_at_epoch_ms(1660000000000LL);
    dev2->set_revoked_at_epoch_ms(1665000000000LL);
    dev2->set_revocation_reason("Lost device");
    dev2->set_last_authenticated_at_epoch_ms(1664000000000LL);

    EXPECT_CALL(*mock_client_, list_user_devices(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::ListUserDevicesRequest& req,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(req.user_id(), "user-alice-123");
            EXPECT_FALSE(req.include_revoked());
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::ListUserDevicesResponse>(grpc_resp);
        });

    httplib::Request req;
    httplib::Response res;
    auto ctx = make_context("user-alice-123");

    handler_->handle_list_devices(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    ASSERT_TRUE(body.contains("devices"));
    ASSERT_EQ(body["devices"].size(), 2u);

    EXPECT_EQ(body["devices"][0]["device_id"], "dev-phone-1");
    EXPECT_EQ(body["devices"][0]["device_status"], "DEVICE_STATUS_ACTIVE");
    EXPECT_EQ(body["devices"][0]["registered_at_epoch_ms"], 1670000000000LL);

    EXPECT_EQ(body["devices"][1]["device_id"], "dev-laptop-2");
    EXPECT_EQ(body["devices"][1]["device_status"], "DEVICE_STATUS_REVOKED");
    EXPECT_EQ(body["devices"][1]["revocation_reason"], "Lost device");
}

TEST_F(AuthProxyHandlerDeviceLifecycleTest, ListDevicesIncludeRevokedQueryParam) {
    securecloud::auth::v1::ListUserDevicesResponse grpc_resp;

    EXPECT_CALL(*mock_client_, list_user_devices(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::ListUserDevicesRequest& req,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_TRUE(req.include_revoked());
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::ListUserDevicesResponse>(grpc_resp);
        });

    httplib::Request req;
    req.params.emplace("include_revoked", "true");
    httplib::Response res;
    auto ctx = make_context("user-alice-123");

    handler_->handle_list_devices(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_TRUE(body["devices"].is_array());
    EXPECT_EQ(body["devices"].size(), 0u);
}

TEST_F(AuthProxyHandlerDeviceLifecycleTest, ListDevicesDownstreamFailure) {
    EXPECT_CALL(*mock_client_, list_user_devices(_, _))
        .WillRepeatedly(Return(securecloud::gateway::grpc::DependencyError{
            .kind = securecloud::gateway::grpc::DependencyErrorKind::ServiceUnavailable,
            .message = "Downstream database unavailable",
            .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
        }));

    httplib::Request req;
    httplib::Response res;
    auto ctx = make_context("user-alice-123");

    handler_->handle_list_devices(req, res, ctx);

    EXPECT_EQ(res.status, 503);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "SERVICE_UNAVAILABLE");
}

// ============================================================================
// 2. Get Device Details Tests (GET /api/v1/devices/:device_id)
// ============================================================================

TEST_F(AuthProxyHandlerDeviceLifecycleTest, GetDeviceSuccess) {
    securecloud::auth::v1::GetDeviceResponse grpc_resp;
    auto* dev = grpc_resp.mutable_device();
    dev->set_device_id("dev-456");
    dev->set_user_id("user-alice-123");
    dev->set_device_status(securecloud::auth::v1::DeviceStatus::DEVICE_STATUS_ACTIVE);
    dev->set_registered_at_epoch_ms(1670000000000LL);

    EXPECT_CALL(*mock_client_, get_device(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::GetDeviceRequest& req,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(req.device_id(), "dev-456");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::GetDeviceResponse>(grpc_resp);
        });

    httplib::Request req;
    req.path_params["device_id"] = "dev-456";
    httplib::Response res;
    auto ctx = make_context("user-alice-123");

    handler_->handle_get_device(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    ASSERT_TRUE(body.contains("device"));
    EXPECT_EQ(body["device"]["device_id"], "dev-456");
    EXPECT_EQ(body["device"]["user_id"], "user-alice-123");
    EXPECT_EQ(body["device"]["device_status"], "DEVICE_STATUS_ACTIVE");
}

TEST_F(AuthProxyHandlerDeviceLifecycleTest, GetDeviceCrossTenantAccessBlocked) {
    securecloud::auth::v1::GetDeviceResponse grpc_resp;
    auto* dev = grpc_resp.mutable_device();
    dev->set_device_id("dev-victim-999");
    dev->set_user_id("user-bob-456"); // Belongs to Bob!
    dev->set_device_status(securecloud::auth::v1::DeviceStatus::DEVICE_STATUS_ACTIVE);

    EXPECT_CALL(*mock_client_, get_device(_, _)).WillOnce(Return(grpc_resp));

    httplib::Request req;
    req.path_params["device_id"] = "dev-victim-999";
    httplib::Response res;
    auto ctx = make_context("user-attacker-123"); // Attacker is Alice!

    handler_->handle_get_device(req, res, ctx);

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "PERMISSION_DENIED");
}

TEST_F(AuthProxyHandlerDeviceLifecycleTest, GetDeviceMissingPathParameter) {
    httplib::Request req; // No device_id in path_params
    httplib::Response res;
    auto ctx = make_context("user-alice-123");

    handler_->handle_get_device(req, res, ctx);

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "BAD_REQUEST");
}

TEST_F(AuthProxyHandlerDeviceLifecycleTest, GetDeviceNotFoundDownstream) {
    EXPECT_CALL(*mock_client_, get_device(_, _))
        .WillOnce(Return(securecloud::gateway::grpc::DependencyError{
            .kind = securecloud::gateway::grpc::DependencyErrorKind::NotFound,
            .message = "Device not found",
            .grpc_code = ::grpc::StatusCode::NOT_FOUND,
        }));

    httplib::Request req;
    req.path_params["device_id"] = "dev-nonexistent";
    httplib::Response res;
    auto ctx = make_context("user-alice-123");

    handler_->handle_get_device(req, res, ctx);

    EXPECT_EQ(res.status, 404);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "NOT_FOUND");
}

// ============================================================================
// 3. Initiate Device Pairing Tests (POST /api/v1/devices/pairing)
// ============================================================================

TEST_F(AuthProxyHandlerDeviceLifecycleTest, InitiateDevicePairingSuccess) {
    securecloud::auth::v1::InitiateDevicePairingResponse grpc_resp;
    grpc_resp.set_pairing_code("PAIR-7788");
    grpc_resp.set_expires_at_epoch_ms(1670000300000LL);

    EXPECT_CALL(*mock_client_, initiate_device_pairing(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::InitiateDevicePairingRequest& req,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(req.user_id(), "user-alice-123");
            EXPECT_EQ(req.device_id(), "dev-tablet-3");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::InitiateDevicePairingResponse>(grpc_resp);
        });

    httplib::Request req;
    req.body = nlohmann::json{{"device_id", "dev-tablet-3"}}.dump();
    httplib::Response res;
    auto ctx = make_context("user-alice-123");

    handler_->handle_initiate_device_pairing(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["pairing_code"], "PAIR-7788");
    EXPECT_EQ(body["expires_at_epoch_ms"], 1670000300000LL);
}

TEST_F(AuthProxyHandlerDeviceLifecycleTest, InitiateDevicePairingFallbackToCallerDevice) {
    securecloud::auth::v1::InitiateDevicePairingResponse grpc_resp;
    grpc_resp.set_pairing_code("PAIR-1122");
    grpc_resp.set_expires_at_epoch_ms(1670000300000LL);

    EXPECT_CALL(*mock_client_, initiate_device_pairing(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::InitiateDevicePairingRequest& req,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(req.user_id(), "user-alice-123");
            EXPECT_EQ(req.device_id(), "dev-caller-default");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::InitiateDevicePairingResponse>(grpc_resp);
        });

    httplib::Request req; // Empty body
    httplib::Response res;
    auto ctx = make_context("user-alice-123", "dev-caller-default");

    handler_->handle_initiate_device_pairing(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["pairing_code"], "PAIR-1122");
}

TEST_F(AuthProxyHandlerDeviceLifecycleTest, InitiateDevicePairingMissingDevice) {
    httplib::Request req; // Empty body and empty ctx device_id
    httplib::Response res;
    auto ctx = make_context("user-alice-123", "");

    handler_->handle_initiate_device_pairing(req, res, ctx);

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "BAD_REQUEST");
}

// ============================================================================
// 4. Authorize Device Tests (POST /api/v1/devices/:device_id/authorize)
// ============================================================================

TEST_F(AuthProxyHandlerDeviceLifecycleTest, AuthorizeDeviceRejectsPrimarySessionWithMfaRequired) {
    httplib::Request req;
    req.path_params["device_id"] = "dev-new";
    req.body = nlohmann::json{{"pairing_code", "PAIR-7788"}}.dump();
    httplib::Response res;
    // Primary authentication level -> should trigger MFA_REQUIRED 403
    auto ctx = make_context("user-alice-123", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    handler_->handle_authorize_device(req, res, ctx);

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "MFA_REQUIRED");
}

TEST_F(AuthProxyHandlerDeviceLifecycleTest, AuthorizeDeviceSuccessWithMfaVerifiedSession) {
    securecloud::auth::v1::AuthorizeDeviceResponse grpc_resp;
    grpc_resp.set_authorized(true);
    grpc_resp.set_status(securecloud::auth::v1::DeviceStatus::DEVICE_STATUS_ACTIVE);
    grpc_resp.set_authorized_at_epoch_ms(1670000000000LL);

    EXPECT_CALL(*mock_client_, authorize_device(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::AuthorizeDeviceRequest& req,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(req.user_id(), "user-alice-123");
            EXPECT_EQ(req.device_id(), "dev-new");
            EXPECT_EQ(req.pairing_code(), "PAIR-7788");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthorizeDeviceResponse>(grpc_resp);
        });

    httplib::Request req;
    req.path_params["device_id"] = "dev-new";
    req.body = nlohmann::json{{"pairing_code", "PAIR-7788"}}.dump();
    httplib::Response res;
    auto ctx = make_context("user-alice-123", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    handler_->handle_authorize_device(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_TRUE(body["authorized"].get<bool>());
    EXPECT_EQ(body["status"], "DEVICE_STATUS_ACTIVE");
    EXPECT_EQ(body["authorized_at_epoch_ms"], 1670000000000LL);
}

TEST_F(AuthProxyHandlerDeviceLifecycleTest, AuthorizeDeviceMissingPairingCode) {
    httplib::Request req;
    req.path_params["device_id"] = "dev-new";
    req.body = "{}"; // No pairing_code
    httplib::Response res;
    auto ctx = make_context("user-alice-123", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    handler_->handle_authorize_device(req, res, ctx);

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "BAD_REQUEST");
}

// ============================================================================
// 5. Revoke Device Tests (DELETE /api/v1/devices/:device_id)
// ============================================================================

TEST_F(AuthProxyHandlerDeviceLifecycleTest, RevokeDeviceRejectsPrimarySessionWithMfaRequired) {
    httplib::Request req;
    req.path_params["device_id"] = "dev-to-revoke";
    httplib::Response res;
    auto ctx = make_context("user-alice-123", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    handler_->handle_revoke_device(req, res, ctx);

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "MFA_REQUIRED");
}

TEST_F(AuthProxyHandlerDeviceLifecycleTest, RevokeDeviceSuccessWithMfaVerifiedSession) {
    securecloud::auth::v1::RevokeDeviceResponse grpc_resp;
    grpc_resp.set_revoked(true);
    grpc_resp.set_revoked_at_epoch_ms(1670000500000LL);

    EXPECT_CALL(*mock_client_, revoke_device(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::RevokeDeviceRequest& req,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(req.device_id(), "dev-compromised");
            EXPECT_EQ(req.user_id(), "user-alice-123");
            EXPECT_EQ(req.reason(), "Compromised credential reported");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::RevokeDeviceResponse>(grpc_resp);
        });

    httplib::Request req;
    req.path_params["device_id"] = "dev-compromised";
    req.body = nlohmann::json{{"reason", "Compromised credential reported"}}.dump();
    httplib::Response res;
    auto ctx = make_context("user-alice-123", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    handler_->handle_revoke_device(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_TRUE(body["revoked"].get<bool>());
    EXPECT_EQ(body["revoked_at_epoch_ms"], 1670000500000LL);
}

TEST_F(AuthProxyHandlerDeviceLifecycleTest, RevokeDeviceMissingDeviceId) {
    httplib::Request req; // No device_id
    httplib::Response res;
    auto ctx = make_context("user-alice-123", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    handler_->handle_revoke_device(req, res, ctx);

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "BAD_REQUEST");
}

// ============================================================================
// 6. Router Binding Test
// ============================================================================

TEST_F(AuthProxyHandlerDeviceLifecycleTest, RegisterRoutesBindsAllDeviceEndpoints) {
    Router router;
    EXPECT_EQ(router.route_count(), 0);
    handler_->register_routes(router);

    // Total 22 routes registered by AuthProxyHandler
    EXPECT_EQ(router.route_count(), 22);

    // Verify router dispatches to device listing endpoint
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices";
    httplib::Response res;
    router.handle(req, res);
    EXPECT_NE(res.status, 404);
}

} // namespace
} // namespace securecloud::gateway::http::test
