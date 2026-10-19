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

AuthenticatedContext make_context(std::string user_id = "user-123", std::string device_id = "dev-456",
                                  securecloud::auth::v1::AuthenticationLevel level =
                                      securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                  std::vector<std::string> scopes = {"access"}) {
    int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    return AuthenticatedContext(std::move(user_id), std::move(device_id), "sess-test-789", level, std::move(scopes),
                                now_ms + 3600000);
}

class AuthProxyHandlerMfaTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_client_ = std::make_shared<MockAuthClient>();
        handler_ = std::make_unique<AuthProxyHandler>(mock_client_);
    }

    std::shared_ptr<MockAuthClient> mock_client_;
    std::unique_ptr<AuthProxyHandler> handler_;
};

// ============================================================================
// 1. MFA Enrollment Initiation
// ============================================================================

TEST_F(AuthProxyHandlerMfaTest, InitiateEnrollmentSuccess) {
    httplib::Request req;
    req.body = nlohmann::json{{"issuer", "AcmeCorp"}, {"account_name", "alice@acme.com"}}.dump();
    httplib::Response res;
    auto ctx = make_context("user-alice-123");

    securecloud::auth::v1::InitiateMfaEnrollmentResponse grpc_resp;
    grpc_resp.set_mfa_configuration_id("cfg-mfa-456");
    grpc_resp.set_secret("JBSWY3DPEHPK3PXP");
    grpc_resp.set_otpauth_uri("otpauth://totp/AcmeCorp:alice@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=AcmeCorp");

    EXPECT_CALL(*mock_client_, initiate_mfa_enrollment(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::InitiateMfaEnrollmentRequest& r,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(r.user_id(), "user-alice-123");
            EXPECT_EQ(r.issuer(), "AcmeCorp");
            EXPECT_EQ(r.account_name(), "alice@acme.com");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::InitiateMfaEnrollmentResponse>(grpc_resp);
        });

    handler_->handle_initiate_mfa_enrollment(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["mfa_configuration_id"], "cfg-mfa-456");
    EXPECT_EQ(body["secret"], "JBSWY3DPEHPK3PXP");
    EXPECT_EQ(body["otpauth_uri"], "otpauth://totp/AcmeCorp:alice@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=AcmeCorp");
}

TEST_F(AuthProxyHandlerMfaTest, InitiateEnrollmentEmptyBodyUsesDefaults) {
    httplib::Request req;
    req.body = "";
    httplib::Response res;
    auto ctx = make_context("user-bob-999");

    securecloud::auth::v1::InitiateMfaEnrollmentResponse grpc_resp;
    grpc_resp.set_mfa_configuration_id("cfg-mfa-789");
    grpc_resp.set_secret("KZXW6YTBON2XEZJO");
    grpc_resp.set_otpauth_uri("otpauth://totp/SecureCloud?secret=KZXW6YTBON2XEZJO");

    EXPECT_CALL(*mock_client_, initiate_mfa_enrollment(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::InitiateMfaEnrollmentRequest& r,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(r.user_id(), "user-bob-999");
            EXPECT_EQ(r.issuer(), "SecureCloud");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::InitiateMfaEnrollmentResponse>(grpc_resp);
        });

    handler_->handle_initiate_mfa_enrollment(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["mfa_configuration_id"], "cfg-mfa-789");
    EXPECT_EQ(body["secret"], "KZXW6YTBON2XEZJO");
}

TEST_F(AuthProxyHandlerMfaTest, InitiateEnrollmentDownstreamFailure) {
    httplib::Request req;
    httplib::Response res;
    auto ctx = make_context("user-fail-123");

    EXPECT_CALL(*mock_client_, initiate_mfa_enrollment(_, _))
        .WillOnce(Return(securecloud::gateway::grpc::DependencyError{
            .kind = securecloud::gateway::grpc::DependencyErrorKind::ServiceUnavailable,
            .message = "AuthService temporarily unavailable",
            .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
        }));

    handler_->handle_initiate_mfa_enrollment(req, res, ctx);

    EXPECT_EQ(res.status, 503);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "SERVICE_UNAVAILABLE");
}

// ============================================================================
// 2. MFA Enrollment Confirmation
// ============================================================================

TEST_F(AuthProxyHandlerMfaTest, ConfirmEnrollmentSuccess) {
    httplib::Request req;
    req.body = nlohmann::json{{"code", "123456"}}.dump();
    httplib::Response res;
    auto ctx = make_context("user-alice-123");

    securecloud::auth::v1::ConfirmMfaEnrollmentResponse grpc_resp;
    grpc_resp.set_success(true);
    grpc_resp.add_recovery_codes("REC-AAAA-BBBB");
    grpc_resp.add_recovery_codes("REC-CCCC-DDDD");

    EXPECT_CALL(*mock_client_, confirm_mfa_enrollment(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::ConfirmMfaEnrollmentRequest& r,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(r.user_id(), "user-alice-123");
            EXPECT_EQ(r.code(), "123456");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::ConfirmMfaEnrollmentResponse>(grpc_resp);
        });

    handler_->handle_confirm_mfa_enrollment(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_TRUE(body["success"].get<bool>());
    ASSERT_TRUE(body.contains("recovery_codes"));
    EXPECT_EQ(body["recovery_codes"].size(), 2u);
    EXPECT_EQ(body["recovery_codes"][0], "REC-AAAA-BBBB");
    EXPECT_EQ(body["recovery_codes"][1], "REC-CCCC-DDDD");
}

TEST_F(AuthProxyHandlerMfaTest, ConfirmEnrollmentRejectsMissingOrEmptyCode) {
    auto ctx = make_context("user-alice-123");

    // Missing code
    {
        httplib::Request req;
        req.body = nlohmann::json{{"wrong_field", "value"}}.dump();
        httplib::Response res;
        handler_->handle_confirm_mfa_enrollment(req, res, ctx);
        EXPECT_EQ(res.status, 400);
    }

    // Empty code
    {
        httplib::Request req;
        req.body = nlohmann::json{{"code", ""}}.dump();
        httplib::Response res;
        handler_->handle_confirm_mfa_enrollment(req, res, ctx);
        EXPECT_EQ(res.status, 400);
    }

    // Malformed JSON
    {
        httplib::Request req;
        req.body = "{invalid_json";
        httplib::Response res;
        handler_->handle_confirm_mfa_enrollment(req, res, ctx);
        EXPECT_EQ(res.status, 400);
    }
}

TEST_F(AuthProxyHandlerMfaTest, ConfirmEnrollmentDownstreamFailure) {
    httplib::Request req;
    req.body = nlohmann::json{{"code", "999999"}}.dump();
    httplib::Response res;
    auto ctx = make_context("user-alice-123");

    EXPECT_CALL(*mock_client_, confirm_mfa_enrollment(_, _))
        .WillOnce(Return(securecloud::gateway::grpc::DependencyError{
            .kind = securecloud::gateway::grpc::DependencyErrorKind::Unauthenticated,
            .message = "Invalid TOTP verification code",
            .grpc_code = ::grpc::StatusCode::UNAUTHENTICATED,
        }));

    handler_->handle_confirm_mfa_enrollment(req, res, ctx);

    EXPECT_EQ(res.status, 401);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "UNAUTHENTICATED");
}

// ============================================================================
// 3. MFA Challenge Verification & Stepped-Up Token Issuance
// ============================================================================

TEST_F(AuthProxyHandlerMfaTest, VerifyChallengeSuccess_ReturnsSteppedUpToken) {
    httplib::Request req;
    req.body = nlohmann::json{{"challenge_id", "chal-session-789"}, {"code", "555666"}}.dump();
    httplib::Response res;
    auto ctx = make_context("user-alice-123");

    securecloud::auth::v1::VerifyMfaChallengeResponse grpc_resp;
    grpc_resp.set_session_id("sess-stepped-up-1");
    grpc_resp.set_access_token("jwt.stepped_up.mfa_verified");
    grpc_resp.set_refresh_token("refresh.stepped_up");
    grpc_resp.set_authentication_level(securecloud::auth::v1::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    grpc_resp.set_expires_at_epoch_ms(1800000000000LL);

    EXPECT_CALL(*mock_client_, verify_mfa_challenge(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::VerifyMfaChallengeRequest& r,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(r.challenge_id(), "chal-session-789");
            EXPECT_EQ(r.code(), "555666");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::VerifyMfaChallengeResponse>(grpc_resp);
        });

    handler_->handle_verify_mfa_challenge(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["session_id"], "sess-stepped-up-1");
    EXPECT_EQ(body["access_token"], "jwt.stepped_up.mfa_verified");
    EXPECT_EQ(body["refresh_token"], "refresh.stepped_up");
    EXPECT_EQ(body["authentication_level"], "MFA_VERIFIED");
    EXPECT_EQ(body["expires_at_epoch_ms"], 1800000000000LL);
}

TEST_F(AuthProxyHandlerMfaTest, VerifyChallengeFallsBackToSessionIdWhenChallengeIdOmitted) {
    httplib::Request req;
    req.body = nlohmann::json{{"code", "777888"}}.dump();
    httplib::Response res;
    auto ctx = make_context("user-alice-123"); // session_id is "sess-test-789"

    securecloud::auth::v1::VerifyMfaChallengeResponse grpc_resp;
    grpc_resp.set_session_id("sess-test-789");
    grpc_resp.set_access_token("jwt.elevated");
    grpc_resp.set_refresh_token("refresh.elevated");
    grpc_resp.set_authentication_level(securecloud::auth::v1::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    grpc_resp.set_expires_at_epoch_ms(1800000000000LL);

    EXPECT_CALL(*mock_client_, verify_mfa_challenge(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::VerifyMfaChallengeRequest& r,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(r.challenge_id(), "sess-test-789");
            EXPECT_EQ(r.code(), "777888");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::VerifyMfaChallengeResponse>(grpc_resp);
        });

    handler_->handle_verify_mfa_challenge(req, res, ctx);

    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthProxyHandlerMfaTest, VerifyChallengeRejectsMissingCode) {
    httplib::Request req;
    req.body = nlohmann::json{{"challenge_id", "chal-1"}}.dump();
    httplib::Response res;
    auto ctx = make_context("user-1");

    handler_->handle_verify_mfa_challenge(req, res, ctx);
    EXPECT_EQ(res.status, 400);
}

TEST_F(AuthProxyHandlerMfaTest, VerifyChallengeDownstreamFailure) {
    httplib::Request req;
    req.body = nlohmann::json{{"code", "000000"}}.dump();
    httplib::Response res;
    auto ctx = make_context("user-1");

    EXPECT_CALL(*mock_client_, verify_mfa_challenge(_, _))
        .WillOnce(Return(securecloud::gateway::grpc::DependencyError{
            .kind = securecloud::gateway::grpc::DependencyErrorKind::Unauthenticated,
            .message = "Invalid challenge or expired OTP",
            .grpc_code = ::grpc::StatusCode::UNAUTHENTICATED,
        }));

    handler_->handle_verify_mfa_challenge(req, res, ctx);

    EXPECT_EQ(res.status, 401);
}

// ============================================================================
// 4. Disabling MFA & Stepped-Up Enforcement
// ============================================================================

TEST_F(AuthProxyHandlerMfaTest, DisableMfaRejectsPrimarySessionWithMfaRequired) {
    httplib::Request req;
    req.body = nlohmann::json{{"code", "123456"}}.dump();
    httplib::Response res;
    // Primary-only context (not MFA verified)
    auto ctx = make_context("user-alice-123", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    // Should reject directly without invoking downstream gRPC
    EXPECT_CALL(*mock_client_, disable_mfa(_, _)).Times(0);

    handler_->handle_disable_mfa(req, res, ctx);

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "MFA_REQUIRED");
}

TEST_F(AuthProxyHandlerMfaTest, DisableMfaSuccessWithMfaVerifiedSession) {
    httplib::Request req;
    req.body = nlohmann::json{{"code", "123456"}}.dump();
    httplib::Response res;
    // MFA-verified context
    auto ctx = make_context("user-alice-123", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    securecloud::auth::v1::DisableMfaResponse grpc_resp;
    grpc_resp.set_success(true);

    EXPECT_CALL(*mock_client_, disable_mfa(_, _))
        .WillOnce([&grpc_resp](const securecloud::auth::v1::DisableMfaRequest& r,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(r.user_id(), "user-alice-123");
            EXPECT_EQ(r.code(), "123456");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::DisableMfaResponse>(grpc_resp);
        });

    handler_->handle_disable_mfa(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_TRUE(body["success"].get<bool>());
}

TEST_F(AuthProxyHandlerMfaTest, DisableMfaRejectsMissingCode) {
    httplib::Request req;
    req.body = "{}";
    httplib::Response res;
    auto ctx = make_context("user-alice-123", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    handler_->handle_disable_mfa(req, res, ctx);
    EXPECT_EQ(res.status, 400);
}

// ============================================================================
// 5. Router Registration
// ============================================================================

TEST_F(AuthProxyHandlerMfaTest, RegisterRoutesBindsAllMfaEndpoints) {
    Router router;
    EXPECT_EQ(router.route_count(), 0);
    handler_->register_routes(router);

    // Previously 15 routes, now 22 with the 7 device lifecycle routes
    EXPECT_EQ(router.route_count(), 22);

    // Verify router dispatches to the MFA endpoint (e.g., empty JSON results in 400 rather than 404)
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/mfa/enroll";
    req.body = "{}";
    httplib::Response res;
    router.handle(req, res);
    EXPECT_NE(res.status, 404);
}

} // namespace
} // namespace securecloud::gateway::http::test
