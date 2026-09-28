#include "http/auth/authentication_middleware.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/auth/token_validator_interface.hpp"
#include "http/router.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

namespace securecloud::gateway::http {
namespace {

using ::testing::_;
using ::testing::Return;

class MockTokenValidator : public ITokenValidator {
  public:
    MOCK_METHOD(AuthenticatedResult, validate,
                (const std::string& token, const std::string& session_id, const std::string& request_id), (override));
};

AuthenticatedContext
make_test_context(const std::string& user_id = "usr-test-1", const std::string& device_id = "dev-test-1",
                  securecloud::auth::v1::AuthenticationLevel level =
                      securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                  std::vector<std::string> scopes = {"messages:write", "files:read", "access"},
                  int64_t expires_in_sec = 3600) {
    auto now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    return AuthenticatedContext(user_id, device_id, "sess-test-1", level, std::move(scopes),
                                now_ms + (expires_in_sec * 1000));
}

class AuthenticationMiddlewareTest : public ::testing::Test {
  protected:
    void SetUp() override {
        policy_ = std::make_shared<GatewaySecurityPolicy>(GatewaySecurityPolicy::create_default());
        mock_validator_ = std::make_shared<MockTokenValidator>();
        middleware_ = std::make_shared<AuthenticationMiddleware>(policy_, mock_validator_);

        router_ = std::make_unique<Router>();
        router_->use(middleware_);

        // Register sample routes
        router_->get("/health/live", [](const httplib::Request&, httplib::Response& res) {
            res.status = 200;
            res.set_content("OK", "text/plain");
        });

        router_->add_authenticated_route(
            "POST", "/api/v1/messages/send",
            [](const httplib::Request&, httplib::Response& res, const AuthenticatedContext& ctx) {
                nlohmann::json j;
                j["user_id"] = ctx.user_id();
                j["device_id"] = ctx.device_id();
                j["mfa"] = ctx.is_mfa_verified();
                res.status = 200;
                res.set_content(j.dump(), "application/json");
            });

        router_->add_authenticated_route(
            "POST", "/api/v1/auth/device/register",
            [](const httplib::Request&, httplib::Response& res, const AuthenticatedContext& ctx) {
                res.status = 200;
                res.set_content("Device registered: " + ctx.device_id(), "text/plain");
            });
    }

    std::shared_ptr<GatewaySecurityPolicy> policy_;
    std::shared_ptr<MockTokenValidator> mock_validator_;
    std::shared_ptr<AuthenticationMiddleware> middleware_;
    std::unique_ptr<Router> router_;
};

TEST_F(AuthenticationMiddlewareTest, PublicRouteBypassesTokenRequirement) {
    EXPECT_CALL(*mock_validator_, validate(_, _, _)).Times(0);

    httplib::Request req;
    req.method = "GET";
    req.path = "/health/live";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(res.body, "OK");
}

TEST_F(AuthenticationMiddlewareTest, ProtectedRouteMissingAuthorizationHeaderRejectsWith401) {
    EXPECT_CALL(*mock_validator_, validate(_, _, _)).Times(0);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("x-request-id", "req-test-missing-hdr");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 401);
    EXPECT_TRUE(res.has_header("WWW-Authenticate"));
    EXPECT_EQ(res.get_header_value("x-request-id"), "req-test-missing-hdr");

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "UNAUTHENTICATED");
    EXPECT_EQ(json["error"]["request_id"], "req-test-missing-hdr");
}

TEST_F(AuthenticationMiddlewareTest, ProtectedRouteMalformedHeaderRejectsWith401) {
    EXPECT_CALL(*mock_validator_, validate(_, _, _)).Times(0);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("Authorization", "Basic dXNlcjpwYXNz");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 401);
    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "UNAUTHENTICATED");
}

TEST_F(AuthenticationMiddlewareTest, ProtectedRouteInvalidTokenRejectsWith401) {
    EXPECT_CALL(*mock_validator_, validate("invalid-tok", _, _))
        .WillOnce(Return(TokenValidationError{TokenValidationErrorKind::InvalidSignature, "Signature mismatch"}));

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("Authorization", "Bearer invalid-tok");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 401);
    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "INVALID_TOKEN");
}

TEST_F(AuthenticationMiddlewareTest, ProtectedRouteExpiredTokenRejectsWith401) {
    EXPECT_CALL(*mock_validator_, validate("expired-tok", _, _))
        .WillOnce(Return(TokenValidationError{TokenValidationErrorKind::TokenExpired, "Token expired"}));

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("Authorization", "Bearer expired-tok");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 401);
    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "TOKEN_EXPIRED");
}

TEST_F(AuthenticationMiddlewareTest, ProtectedRouteRevokedSessionRejectsWith401) {
    EXPECT_CALL(*mock_validator_, validate("revoked-tok", _, _))
        .WillOnce(Return(TokenValidationError{TokenValidationErrorKind::SessionRevoked, "Session revoked"}));

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("Authorization", "Bearer revoked-tok");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 401);
    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "SESSION_REVOKED");
}

TEST_F(AuthenticationMiddlewareTest, UpstreamAuthOutageRejectsWith503) {
    EXPECT_CALL(*mock_validator_, validate("good-tok", _, _))
        .WillOnce(Return(TokenValidationError{TokenValidationErrorKind::ServiceUnavailable, "gRPC timeout"}));

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("Authorization", "Bearer good-tok");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 503);
    EXPECT_TRUE(res.has_header("Retry-After"));
    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "SERVICE_UNAVAILABLE");
}

TEST_F(AuthenticationMiddlewareTest, SensitiveRouteWithoutMfaRejectsWith403) {
    auto primary_ctx = make_test_context("usr-alice", "dev-1",
                                         securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                         {"auth:device:register"});

    EXPECT_CALL(*mock_validator_, validate("primary-only-tok", _, _)).WillOnce(Return(primary_ctx));

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/device/register";
    req.set_header("Authorization", "Bearer primary-only-tok");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 403);
    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "MFA_REQUIRED");
}

TEST_F(AuthenticationMiddlewareTest, ProtectedRouteMissingRequiredScopeRejectsWith403) {
    // /api/v1/messages/send requires "messages:write"
    auto insufficient_scope_ctx = make_test_context(
        "usr-alice", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
        {"files:read"});

    EXPECT_CALL(*mock_validator_, validate("readonly-tok", _, _)).WillOnce(Return(insufficient_scope_ctx));

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("Authorization", "Bearer readonly-tok");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 403);
    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "INSUFFICIENT_SCOPE");
}

TEST_F(AuthenticationMiddlewareTest, ProtectedRouteValidTokenEnrichesContext) {
    auto valid_ctx = make_test_context("usr-superman", "dev-macbook",
                                       securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                                       {"messages:write", "access"});

    EXPECT_CALL(*mock_validator_, validate("valid-token-xyz", _, _)).WillOnce(Return(valid_ctx));

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("Authorization", "Bearer valid-token-xyz");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 200);
    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["user_id"], "usr-superman");
    EXPECT_EQ(json["device_id"], "dev-macbook");
    EXPECT_TRUE(json["mfa"].get<bool>());
}

TEST_F(AuthenticationMiddlewareTest, FailClosedProtectsUnmappedRoutes) {
    EXPECT_CALL(*mock_validator_, validate(_, _, _)).Times(0);

    httplib::Request req;
    req.method = "GET";
    req.path = "/unmapped/secret/admin";

    httplib::Response res;
    router_->handle(req, res);

    // Unmapped route must fail closed with 401 instead of reaching 404 handler anonymously
    EXPECT_EQ(res.status, 401);
    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "UNAUTHENTICATED");
}

TEST_F(AuthenticationMiddlewareTest, NullDependenciesThrowInvalidArgument) {
    EXPECT_THROW(AuthenticationMiddleware(nullptr, mock_validator_), std::invalid_argument);
    EXPECT_THROW(AuthenticationMiddleware(policy_, nullptr), std::invalid_argument);
}

TEST_F(AuthenticationMiddlewareTest, SpoofedIdentityHeadersAreSanitizedOnPublicRoute) {
    policy_->add_rule("GET", "/health/public-status", RouteAccess::Public);
    EXPECT_CALL(*mock_validator_, validate(_, _, _)).Times(0);

    bool handler_executed = false;
    router_->get("/health/public-status", [&](const httplib::Request& req, httplib::Response& res) {
        handler_executed = true;
        // Verify all spoofed identity headers have been scrubbed by perimeter sanitizer
        EXPECT_FALSE(req.has_header("x-user-id"));
        EXPECT_FALSE(req.has_header("X-User-Id"));
        EXPECT_FALSE(req.has_header("x-device-id"));
        EXPECT_FALSE(req.has_header("X-Auth-Level"));
        EXPECT_FALSE(req.has_header("x-scopes"));
        EXPECT_FALSE(req.has_header("x-authenticated-role"));
        EXPECT_FALSE(req.has_header("x-securecloud-identity-hash"));

        // Legitimate correlation headers preserved
        EXPECT_TRUE(req.has_header("x-request-id"));
        EXPECT_EQ(req.get_header_value("x-request-id"), "req-public-test");

        // Public route receives no AuthenticatedContext
        auto ctx_opt = AuthenticationMiddleware::get_context(req);
        EXPECT_FALSE(ctx_opt.has_value());

        res.status = 200;
        res.set_content("PUBLIC_OK", "text/plain");
    });

    httplib::Request req;
    req.method = "GET";
    req.path = "/health/public-status";
    req.set_header("x-request-id", "req-public-test");
    req.set_header("X-User-Id", "spoofed-admin");
    req.set_header("x-device-id", "fake-device-777");
    req.set_header("X-Auth-Level", "AUTHENTICATION_LEVEL_MFA_VERIFIED");
    req.set_header("x-scopes", "admin,superuser");
    req.set_header("x-authenticated-role", "root");
    req.set_header("x-securecloud-identity-hash", "fake-hash");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_executed);
    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthenticationMiddlewareTest, SpoofedIdentityHeadersAreSanitizedOnProtectedRoute) {
    auto valid_ctx = make_test_context("usr-alice", "dev-alice-laptop",
                                       securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                                       {"messages:write", "messages:read", "access"});

    EXPECT_CALL(*mock_validator_, validate("valid-token-alice", _, _)).WillOnce(Return(valid_ctx));

    bool handler_executed = false;
    router_->add_authenticated_route(
        "POST", "/api/v1/messages/verify-headers",
        [&](const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx) {
            handler_executed = true;
            // Spoofed headers must be absent from req.headers
            EXPECT_FALSE(req.has_header("x-user-id"));
            EXPECT_FALSE(req.has_header("X-User-Id"));
            EXPECT_FALSE(req.has_header("x-device-id"));
            EXPECT_FALSE(req.has_header("X-Auth-Level"));
            EXPECT_FALSE(req.has_header("x-authenticated-permissions"));

            // Authenticated context must strictly reflect the authoritative validator token payload
            EXPECT_EQ(ctx.user_id(), "usr-alice");
            EXPECT_EQ(ctx.device_id(), "dev-alice-laptop");

            res.status = 200;
        });

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/verify-headers";
    req.set_header("Authorization", "Bearer valid-token-alice");
    req.set_header("X-User-Id", "spoofed-bob");
    req.set_header("x-device-id", "spoofed-device-bob");
    req.set_header("X-Auth-Level", "AUTHENTICATION_LEVEL_PRIMARY");
    req.set_header("x-authenticated-permissions", "all");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_executed);
    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthenticationMiddlewareTest, UnauthenticatedRequestCannotFabricateContext) {
    EXPECT_CALL(*mock_validator_, validate(_, _, _)).Times(0);

    httplib::Request req;
    req.method = "GET";
    req.path = "/health/live";
    req.set_header("x-user-id", "attacker");
    req.set_header("x-authenticated-scopes", "all");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 200);
    // Unauthenticated request cannot fabricate context
    EXPECT_FALSE(AuthenticationMiddleware::get_context(req).has_value());
    EXPECT_FALSE(Router::get_authenticated_context(req).has_value());
}

} // namespace
} // namespace securecloud::gateway::http
