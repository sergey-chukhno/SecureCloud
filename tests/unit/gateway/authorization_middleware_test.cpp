#include "http/auth/authorization_middleware.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/auth/request_context.hpp"
#include "http/routing/router.hpp"

#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <vector>

namespace securecloud::gateway::http {
namespace {

AuthenticatedContext make_context(std::string user_id = "usr-123", std::string device_id = "dev-456",
                                  securecloud::auth::v1::AuthenticationLevel level =
                                      securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                  std::vector<std::string> scopes = {"messages:send"}, int64_t expires_in_sec = 3600) {
    auto now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    return AuthenticatedContext(std::move(user_id), std::move(device_id), "sess-789", level, std::move(scopes),
                                now_ms + (expires_in_sec * 1000));
}

class AuthorizationMiddlewareTest : public ::testing::Test {
  protected:
    void SetUp() override {
        policy_ = std::make_shared<GatewaySecurityPolicy>(GatewaySecurityPolicy::create_default());
        authz_middleware_ = std::make_shared<AuthorizationMiddleware>(policy_);

        router_ = std::make_unique<Router>();
        router_->use(authz_middleware_);

        // Register dummy handlers to verify if downstream execution is reached
        router_->get("/health/live", [this](const httplib::Request&, httplib::Response& res) {
            handler_invoked_ = true;
            res.status = 200;
            res.set_content(R"({"status":"OK"})", "application/json");
        });

        router_->post("/api/v1/messages/send", [this](const httplib::Request&, httplib::Response& res) {
            handler_invoked_ = true;
            res.status = 200;
            res.set_content(R"({"status":"SENT"})", "application/json");
        });

        router_->get("/api/v1/audit/logs", [this](const httplib::Request&, httplib::Response& res) {
            handler_invoked_ = true;
            res.status = 200;
            res.set_content(R"({"status":"AUDIT_LOGS"})", "application/json");
        });

        router_->post("/api/v1/auth/device/register", [this](const httplib::Request&, httplib::Response& res) {
            handler_invoked_ = true;
            res.status = 200;
            res.set_content(R"({"status":"DEVICE_REGISTERED"})", "application/json");
        });
    }

    std::shared_ptr<GatewaySecurityPolicy> policy_;
    std::shared_ptr<AuthorizationMiddleware> authz_middleware_;
    std::unique_ptr<Router> router_;
    bool handler_invoked_{false};
};

TEST_F(AuthorizationMiddlewareTest, ConstructorThrowsOnNullPolicy) {
    EXPECT_THROW(AuthorizationMiddleware(nullptr), std::invalid_argument);
}

TEST_F(AuthorizationMiddlewareTest, PublicRouteBypassesAuthorization) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/health/live";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthorizationMiddlewareTest, MissingContextOnProtectedRouteFailsClosedWith401) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 401);
    EXPECT_TRUE(res.has_header("WWW-Authenticate"));

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "UNAUTHENTICATED");
    EXPECT_EQ(json["status"], 401);
}

TEST_F(AuthorizationMiddlewareTest, ExactScopeAllowsAccess) {
    auto ctx = make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                            {"messages:send"});

    RequestContext req_ctx("req-1", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthorizationMiddlewareTest, DomainWildcardAllowsAccess) {
    auto ctx = make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                            {"messages:*"});

    RequestContext req_ctx("req-1", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthorizationMiddlewareTest, GlobalWildcardAllowsAccess) {
    auto ctx =
        make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {"*"});

    RequestContext req_ctx("req-1", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthorizationMiddlewareTest, AlternativeScopeAllowsAccess) {
    // Default policy configures alternative_scopes = {"messages:write"} on /api/v1/messages/send
    auto ctx = make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                            {"messages:write"});

    RequestContext req_ctx("req-1", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthorizationMiddlewareTest, InsufficientScopeRejectsWith403AndProblemDetails) {
    auto ctx = make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                            {"files:read"});

    RequestContext req_ctx("req-test-403", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("x-request-id", "req-test-403");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 403);

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "INSUFFICIENT_SCOPE");
    EXPECT_EQ(json["status"], 403);
    EXPECT_EQ(json["type"], "https://securecloud.internal/errors/insufficient-scope");
    EXPECT_EQ(json["request_id"], "req-test-403");
    ASSERT_TRUE(json.contains("missing_scopes"));
    ASSERT_FALSE(json["missing_scopes"].empty());
    EXPECT_EQ(json["missing_scopes"][0], "messages:send");
}

TEST_F(AuthorizationMiddlewareTest, SensitiveRouteWithoutMfaRejectsWith403) {
    // Accessing /api/v1/audit/logs requires MFA_VERIFIED
    auto ctx = make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                            {"audit:read"});

    RequestContext req_ctx("req-mfa-err", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/audit/logs";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 403);

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "MFA_REQUIRED");
    EXPECT_EQ(json["type"], "https://securecloud.internal/errors/mfa-required");
}

TEST_F(AuthorizationMiddlewareTest, SensitiveRouteWithMfaAllowsAccess) {
    auto ctx =
        make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                     {"audit:read"});

    RequestContext req_ctx("req-mfa-ok", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/audit/logs";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

TEST_F(AuthorizationMiddlewareTest, DeviceBindingRequiredRejectsEmptyDevice) {
    // /api/v1/auth/device/register requires MFA and a non-empty device_id
    auto ctx = make_context("usr-1", "", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                            {"device:manage"});

    RequestContext req_ctx("req-dev-err", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/device/register";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 403);

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "DEVICE_BINDING_REQUIRED");
    EXPECT_EQ(json["type"], "https://securecloud.internal/errors/device-binding-required");
}

TEST_F(AuthorizationMiddlewareTest, DeviceBindingSatisfiedAllowsAccess) {
    auto ctx =
        make_context("usr-1", "dev-valid-123",
                     securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED, {"device:manage"});

    RequestContext req_ctx("req-dev-ok", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/device/register";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

} // namespace
} // namespace securecloud::gateway::http
