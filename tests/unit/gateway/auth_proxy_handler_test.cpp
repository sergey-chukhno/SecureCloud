#include "grpc/auth_client_interface.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/auth/request_context.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/routing/router.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

namespace securecloud::gateway::http {
namespace {

using ::testing::_;
using ::testing::DoAll;
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
};

class AuthProxyHandlerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_client_ = std::make_shared<MockAuthClient>();
        handler_ = std::make_unique<AuthProxyHandler>(mock_client_);
    }

    std::shared_ptr<MockAuthClient> mock_client_;
    std::unique_ptr<AuthProxyHandler> handler_;
};

TEST_F(AuthProxyHandlerTest, ConstructorThrowsOnNullClient) {
    EXPECT_THROW(AuthProxyHandler(nullptr), std::invalid_argument);
}

TEST_F(AuthProxyHandlerTest, LoginSuccess) {
    httplib::Request req;
    req.body = nlohmann::json{{"identifier", "alice@securecloud.org"},
                              {"credential", "CorrectPassword123!"},
                              {"device_id", "device-alpha-1"}}
                   .dump();

    securecloud::auth::v1::AuthenticateResponse auth_resp;
    auth_resp.set_session_id("sess-xyz-789");
    auth_resp.set_access_token("access-jwt-token");
    auth_resp.set_refresh_token("refresh-token-opaque");
    auth_resp.set_authentication_level(securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    auth_resp.set_expires_at_epoch_ms(1750000000000LL);
    auth_resp.set_user_id("user-alice-uuid");
    auth_resp.set_mfa_required(false);

    EXPECT_CALL(*mock_client_, authenticate(_, _))
        .WillOnce([&auth_resp](const securecloud::auth::v1::AuthenticateRequest& grpc_req,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(grpc_req.credential_identifier(), "alice@securecloud.org");
            EXPECT_EQ(grpc_req.password(), "CorrectPassword123!");
            EXPECT_EQ(grpc_req.device_id(), "device-alpha-1");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(auth_resp);
        });

    httplib::Response res;
    handler_->handle_login(req, res);

    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(res.get_header_value("Content-Type"), "application/json");

    auto json_res = nlohmann::json::parse(res.body);
    EXPECT_EQ(json_res["session_id"], "sess-xyz-789");
    EXPECT_EQ(json_res["access_token"], "access-jwt-token");
    EXPECT_EQ(json_res["refresh_token"], "refresh-token-opaque");
    EXPECT_EQ(json_res["user_id"], "user-alice-uuid");
    EXPECT_FALSE(json_res["mfa_required"].get<bool>());
}

TEST_F(AuthProxyHandlerTest, LoginAlternativeFieldNames) {
    httplib::Request req;
    req.body =
        nlohmann::json{{"credential_identifier", "bob@securecloud.org"}, {"password", "SecretPassword456!"}}.dump();

    securecloud::auth::v1::AuthenticateResponse auth_resp;
    auth_resp.set_session_id("sess-bob-123");
    auth_resp.set_access_token("access-jwt-bob");
    auth_resp.set_refresh_token("refresh-token-bob");
    auth_resp.set_expires_at_epoch_ms(1750000000000LL);
    auth_resp.set_user_id("user-bob-uuid");

    EXPECT_CALL(*mock_client_, authenticate(_, _))
        .WillOnce([&auth_resp](const securecloud::auth::v1::AuthenticateRequest& grpc_req,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(grpc_req.credential_identifier(), "bob@securecloud.org");
            EXPECT_EQ(grpc_req.password(), "SecretPassword456!");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(auth_resp);
        });

    httplib::Response res;
    handler_->handle_login(req, res);

    EXPECT_EQ(res.status, 200);
    auto json_res = nlohmann::json::parse(res.body);
    EXPECT_EQ(json_res["session_id"], "sess-bob-123");
}

TEST_F(AuthProxyHandlerTest, LoginMalformedJsonReturns400) {
    httplib::Request req;
    req.body = "not a valid json string {";

    httplib::Response res;
    handler_->handle_login(req, res);

    EXPECT_EQ(res.status, 400);
    auto json_res = nlohmann::json::parse(res.body);
    EXPECT_EQ(json_res["error"]["code"], "BAD_REQUEST");
}

TEST_F(AuthProxyHandlerTest, LoginMissingFieldsReturns400) {
    httplib::Request req;
    req.body = nlohmann::json{{"identifier", "only-identifier"}}.dump();

    httplib::Response res;
    handler_->handle_login(req, res);

    EXPECT_EQ(res.status, 400);
    auto json_res = nlohmann::json::parse(res.body);
    EXPECT_EQ(json_res["error"]["code"], "BAD_REQUEST");
}

TEST_F(AuthProxyHandlerTest, LoginUpstreamInvalidCredentialsReturns401) {
    httplib::Request req;
    req.body = nlohmann::json{{"identifier", "alice@securecloud.org"}, {"credential", "WrongPassword"}}.dump();

    securecloud::gateway::grpc::DependencyError dep_err{
        .kind = securecloud::gateway::grpc::DependencyErrorKind::Unauthenticated,
        .message = "Invalid credential identifier or password",
        .grpc_code = ::grpc::StatusCode::UNAUTHENTICATED};

    EXPECT_CALL(*mock_client_, authenticate(_, _))
        .WillOnce(Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(dep_err)));

    httplib::Response res;
    handler_->handle_login(req, res);

    EXPECT_EQ(res.status, 401);
    auto json_res = nlohmann::json::parse(res.body);
    EXPECT_EQ(json_res["error"]["code"], "UNAUTHENTICATED");
}

TEST_F(AuthProxyHandlerTest, LoginUpstreamUnavailableReturns503) {
    httplib::Request req;
    req.body = nlohmann::json{{"identifier", "alice@securecloud.org"}, {"credential", "Secret123"}}.dump();

    securecloud::gateway::grpc::DependencyError dep_err{
        .kind = securecloud::gateway::grpc::DependencyErrorKind::ServiceUnavailable,
        .message = "Auth service unreachable",
        .grpc_code = ::grpc::StatusCode::UNAVAILABLE};

    EXPECT_CALL(*mock_client_, authenticate(_, _))
        .WillOnce(Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(dep_err)));

    httplib::Response res;
    handler_->handle_login(req, res);

    EXPECT_EQ(res.status, 503);
    auto json_res = nlohmann::json::parse(res.body);
    EXPECT_EQ(json_res["error"]["code"], "SERVICE_UNAVAILABLE");
}

TEST_F(AuthProxyHandlerTest, RefreshSuccess) {
    httplib::Request req;
    req.body = nlohmann::json{{"refresh_token", "valid-refresh-token-123"}, {"device_id", "dev-01"}}.dump();

    securecloud::auth::v1::RefreshSessionResponse refresh_resp;
    refresh_resp.set_session_id("sess-refreshed");
    refresh_resp.set_access_token("new-access-jwt");
    refresh_resp.set_new_refresh_token("brand-new-refresh-token");
    refresh_resp.set_expires_at_epoch_ms(1760000000000LL);

    EXPECT_CALL(*mock_client_, refresh_session(_, _))
        .WillOnce([&refresh_resp](const securecloud::auth::v1::RefreshSessionRequest& grpc_req,
                                  securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(grpc_req.refresh_token(), "valid-refresh-token-123");
            EXPECT_EQ(grpc_req.device_id(), "dev-01");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::RefreshSessionResponse>(refresh_resp);
        });

    httplib::Response res;
    handler_->handle_refresh(req, res);

    EXPECT_EQ(res.status, 200);
    auto json_res = nlohmann::json::parse(res.body);
    EXPECT_EQ(json_res["session_id"], "sess-refreshed");
    EXPECT_EQ(json_res["access_token"], "new-access-jwt");
    EXPECT_EQ(json_res["refresh_token"], "brand-new-refresh-token");
}

TEST_F(AuthProxyHandlerTest, RefreshMissingTokenReturns400) {
    httplib::Request req;
    req.body = nlohmann::json{{"device_id", "dev-01"}}.dump();

    httplib::Response res;
    handler_->handle_refresh(req, res);

    EXPECT_EQ(res.status, 400);
    auto json_res = nlohmann::json::parse(res.body);
    EXPECT_EQ(json_res["error"]["code"], "BAD_REQUEST");
}

TEST_F(AuthProxyHandlerTest, RevokeSessionSuccess) {
    httplib::Request req;
    AuthenticatedContext ctx("user-1", "dev-1", "sess-to-revoke",
                             securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {},
                             2000000000000LL);

    securecloud::auth::v1::RevokeSessionResponse revoke_resp;
    revoke_resp.set_revoked(true);

    EXPECT_CALL(*mock_client_, revoke_session(_, _))
        .WillOnce([&revoke_resp](const securecloud::auth::v1::RevokeSessionRequest& grpc_req,
                                 securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(grpc_req.session_id(), "sess-to-revoke");
            EXPECT_EQ(grpc_req.reason(), "User logout");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::RevokeSessionResponse>(revoke_resp);
        });

    httplib::Response res;
    handler_->handle_revoke(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto json_res = nlohmann::json::parse(res.body);
    EXPECT_TRUE(json_res["revoked"].get<bool>());
}

TEST_F(AuthProxyHandlerTest, RevokeSessionExplicitBodyOverride) {
    httplib::Request req;
    req.body = nlohmann::json{{"session_id", "sess-target-device"}, {"reason", "Lost device"}}.dump();

    AuthenticatedContext ctx("user-1", "dev-1", "sess-primary",
                             securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {},
                             2000000000000LL);

    securecloud::auth::v1::RevokeSessionResponse revoke_resp;
    revoke_resp.set_revoked(true);

    EXPECT_CALL(*mock_client_, revoke_session(_, _))
        .WillOnce([&revoke_resp](const securecloud::auth::v1::RevokeSessionRequest& grpc_req,
                                 securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(grpc_req.session_id(), "sess-target-device");
            EXPECT_EQ(grpc_req.reason(), "Lost device");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::RevokeSessionResponse>(revoke_resp);
        });

    httplib::Response res;
    handler_->handle_revoke(req, res, ctx);

    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthProxyHandlerTest, GetUserMeSuccess) {
    httplib::Request req;
    AuthenticatedContext ctx("user-uuid-charlie", "dev-c", "sess-c",
                             securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {},
                             2000000000000LL);

    securecloud::auth::v1::GetUserResponse user_resp;
    auto* user = user_resp.mutable_user();
    user->set_user_id("user-uuid-charlie");
    user->set_credential_identifier("charlie@securecloud.org");
    user->set_account_status(securecloud::auth::v1::AccountStatus::ACCOUNT_STATUS_ACTIVE);
    user->set_created_at_epoch_ms(1700000000000LL);
    user->set_updated_at_epoch_ms(1705000000000LL);

    EXPECT_CALL(*mock_client_, get_user(_, _))
        .WillOnce([&user_resp](const securecloud::auth::v1::GetUserRequest& grpc_req,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(grpc_req.user_id(), "user-uuid-charlie");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::GetUserResponse>(user_resp);
        });

    httplib::Response res;
    handler_->handle_get_me(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto json_res = nlohmann::json::parse(res.body);
    EXPECT_EQ(json_res["user"]["user_id"], "user-uuid-charlie");
    EXPECT_EQ(json_res["user"]["credential_identifier"], "charlie@securecloud.org");
}

TEST_F(AuthProxyHandlerTest, GetUserMeUnauthenticatedContextReturns401) {
    httplib::Request req;
    AuthenticatedContext empty_ctx; // empty user_id

    httplib::Response res;
    handler_->handle_get_me(req, res, empty_ctx);

    EXPECT_EQ(res.status, 401);
}

TEST_F(AuthProxyHandlerTest, RegisterDeviceSuccess) {
    httplib::Request req;
    req.body = nlohmann::json{{"identity_key", "raw-identity-key-data"},
                              {"signed_prekey", "raw-signed-prekey-data"},
                              {"signed_prekey_signature", "raw-sig"},
                              {"one_time_prekeys", {"opk-1", "opk-2"}}}
                   .dump();

    AuthenticatedContext ctx("user-uuid-dave", "dev-placeholder", "sess-dave",
                             securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {},
                             2000000000000LL);

    securecloud::auth::v1::RegisterDeviceResponse reg_resp;
    reg_resp.set_device_id("dev-newly-enrolled-1");
    reg_resp.set_status(securecloud::auth::v1::DeviceStatus::DEVICE_STATUS_ACTIVE);
    reg_resp.set_registered_at_epoch_ms(1720000000000LL);

    EXPECT_CALL(*mock_client_, register_device(_, _))
        .WillOnce([&reg_resp](const securecloud::auth::v1::RegisterDeviceRequest& grpc_req,
                              securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(grpc_req.user_id(), "user-uuid-dave");
            EXPECT_EQ(grpc_req.identity_key(), "raw-identity-key-data");
            EXPECT_EQ(grpc_req.signed_prekey(), "raw-signed-prekey-data");
            EXPECT_EQ(grpc_req.signed_prekey_signature(), "raw-sig");
            EXPECT_EQ(grpc_req.one_time_prekeys_size(), 2);
            EXPECT_EQ(grpc_req.one_time_prekeys(0), "opk-1");
            EXPECT_EQ(grpc_req.one_time_prekeys(1), "opk-2");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::RegisterDeviceResponse>(reg_resp);
        });

    httplib::Response res;
    handler_->handle_register_device(req, res, ctx);

    EXPECT_EQ(res.status, 201);
    auto json_res = nlohmann::json::parse(res.body);
    EXPECT_EQ(json_res["device_id"], "dev-newly-enrolled-1");
}

TEST_F(AuthProxyHandlerTest, RegisterDeviceMalformedJsonReturns400) {
    httplib::Request req;
    req.body = "not json";

    AuthenticatedContext ctx("user-uuid-dave", "dev-placeholder", "sess-dave",
                             securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {},
                             2000000000000LL);

    httplib::Response res;
    handler_->handle_register_device(req, res, ctx);

    EXPECT_EQ(res.status, 400);
}

TEST_F(AuthProxyHandlerTest, RequestIdPropagationToClientCallContext) {
    httplib::Request req;
    req.headers.emplace("X-Request-ID", "req-correlation-id-999");
    req.body = nlohmann::json{{"identifier", "alice@securecloud.org"}, {"credential", "pw"}}.dump();

    securecloud::auth::v1::AuthenticateResponse auth_resp;
    auth_resp.set_session_id("sess-1");

    EXPECT_CALL(*mock_client_, authenticate(_, _))
        .WillOnce([](const securecloud::auth::v1::AuthenticateRequest& /*req*/,
                     securecloud::gateway::grpc::ClientCallContext& ctx) {
            EXPECT_EQ(ctx.request_id(), "req-correlation-id-999");
            securecloud::auth::v1::AuthenticateResponse resp;
            resp.set_session_id("sess-1");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(resp);
        });

    httplib::Response res;
    handler_->handle_login(req, res);

    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthProxyHandlerTest, ClientTimeoutPropagatedToClientCallContext) {
    httplib::Request req;
    req.headers.emplace("X-Request-Timeout", "600ms");
    req.body = nlohmann::json{{"identifier", "alice@securecloud.org"}, {"credential", "pw"}}.dump();

    EXPECT_CALL(*mock_client_, authenticate(_, _))
        .WillOnce([](const securecloud::auth::v1::AuthenticateRequest& /*req*/,
                     securecloud::gateway::grpc::ClientCallContext& ctx) {
            EXPECT_LE(ctx.deadline_remaining().count(), 600);
            EXPECT_GE(ctx.deadline_remaining().count(), 500);
            securecloud::auth::v1::AuthenticateResponse resp;
            resp.set_session_id("sess-deadline");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(resp);
        });

    httplib::Response res;
    handler_->handle_login(req, res);

    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthProxyHandlerTest, ClientTimeoutClampedToMinimumFloor) {
    httplib::Request req;
    // 10ms is below the 50ms floor
    req.headers.emplace("X-Request-Timeout", "10ms");
    req.body = nlohmann::json{{"identifier", "alice@securecloud.org"}, {"credential", "pw"}}.dump();

    EXPECT_CALL(*mock_client_, authenticate(_, _))
        .WillOnce([](const securecloud::auth::v1::AuthenticateRequest& /*req*/,
                     securecloud::gateway::grpc::ClientCallContext& ctx) {
            // Clamped to minimum floor (50ms)
            EXPECT_LE(ctx.deadline_remaining().count(), 50);
            EXPECT_GE(ctx.deadline_remaining().count(), 40);
            securecloud::auth::v1::AuthenticateResponse resp;
            resp.set_session_id("sess-floor");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(resp);
        });

    httplib::Response res;
    handler_->handle_login(req, res);

    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthProxyHandlerTest, FastFailOnExpiredBudgetReturns504WithoutRpcCall) {
    GatewayServiceDeadlinesConfig deadlines_cfg;
    deadlines_cfg.min_request_deadline_ms = 50;
    deadlines_cfg.max_request_deadline_ms = 5000;
    deadlines_cfg.auth_timeout_ms = 200;

    auto t0 = std::chrono::steady_clock::now();
    // Simulate time jumping by 300ms on the second call to now()
    int call_count = 0;
    auto clock_fn = [t0, call_count]() mutable -> std::chrono::steady_clock::time_point {
        if (++call_count == 1) {
            return t0;
        }
        return t0 + std::chrono::milliseconds(500); // 500ms > 200ms deadline
    };

    auto deadline_mgr = std::make_shared<DeadlineManager>(deadlines_cfg, clock_fn);
    AuthProxyHandler handler(mock_client_, deadline_mgr);

    httplib::Request req;
    req.headers.emplace("X-Request-ID", "req-expired-1");
    req.body = nlohmann::json{{"identifier", "alice@securecloud.org"}, {"credential", "pw"}}.dump();

    // Invariant: mock_client_ MUST NOT be called!
    EXPECT_CALL(*mock_client_, authenticate(_, _)).Times(0);

    httplib::Response res;
    handler.handle_login(req, res);

    EXPECT_EQ(res.status, 504);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["status"], 504);
    EXPECT_EQ(body["error"]["code"], "GATEWAY_TIMEOUT");
    EXPECT_EQ(body["type"], "https://securecloud.internal/errors/gateway-timeout");
    EXPECT_EQ(body["request_id"], "req-expired-1");
}

TEST_F(AuthProxyHandlerTest, GetMeRetriesOnTransientUnavailableAndSucceeds) {
    auto retry_policy = std::make_shared<RetryPolicy>(
        RetryPolicyConfig{}, [](std::chrono::milliseconds /*delay*/) {}, [] { return 0.0; });
    AuthProxyHandler handler(mock_client_, nullptr, retry_policy);

    AuthenticatedContext ctx("user-uuid-1", "dev-1", "sess-1",
                             securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {},
                             2000000000000LL);

    int call_count = 0;
    EXPECT_CALL(*mock_client_, get_user(_, _))
        .Times(2)
        .WillRepeatedly([&call_count](const securecloud::auth::v1::GetUserRequest& /*req*/,
                                      securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            ++call_count;
            if (call_count == 1) {
                return securecloud::gateway::grpc::Result<securecloud::auth::v1::GetUserResponse>(
                    securecloud::gateway::grpc::DependencyError{
                        .kind = securecloud::gateway::grpc::DependencyErrorKind::ServiceUnavailable,
                        .message = "Transient down",
                        .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
                    });
            }
            securecloud::auth::v1::GetUserResponse resp;
            auto* user = resp.mutable_user();
            user->set_user_id("user-uuid-1");
            user->set_credential_identifier("alice@securecloud.org");
            user->set_account_status(securecloud::auth::v1::AccountStatus::ACCOUNT_STATUS_ACTIVE);
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::GetUserResponse>(resp);
        });

    httplib::Request req;
    httplib::Response res;
    handler.handle_get_me(req, res, ctx);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["user"]["user_id"], "user-uuid-1");
    EXPECT_EQ(call_count, 2);
}

TEST_F(AuthProxyHandlerTest, LoginDoesNotRetryOnUnavailableDueToNonIdempotency) {
    auto retry_policy = std::make_shared<RetryPolicy>(
        RetryPolicyConfig{}, [](std::chrono::milliseconds /*delay*/) {}, [] { return 0.0; });
    AuthProxyHandler handler(mock_client_, nullptr, retry_policy);

    httplib::Request req;
    req.body = nlohmann::json{{"identifier", "alice@securecloud.org"}, {"credential", "pw"}}.dump();

    // Invariant: Non-idempotent operation MUST be invoked exactly once even on UNAVAILABLE!
    EXPECT_CALL(*mock_client_, authenticate(_, _))
        .Times(1)
        .WillOnce([](const securecloud::auth::v1::AuthenticateRequest& /*req*/,
                     securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(
                securecloud::gateway::grpc::DependencyError{
                    .kind = securecloud::gateway::grpc::DependencyErrorKind::ServiceUnavailable,
                    .message = "Service unavailable",
                    .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
                });
        });

    httplib::Response res;
    handler.handle_login(req, res);

    EXPECT_EQ(res.status, 503);
}

TEST_F(AuthProxyHandlerTest, RegisterRoutesRegistersAllAuthRoutes) {
    Router router;
    EXPECT_EQ(router.route_count(), 0);

    handler_->register_routes(router);

    // Routes registered:
    // POST /api/v1/auth/login
    // POST /api/v1/auth/refresh
    // POST /api/v1/auth/revoke
    // GET /api/v1/users/me
    // POST /api/v1/devices
    EXPECT_EQ(router.route_count(), 5);
}

} // namespace
} // namespace securecloud::gateway::http
