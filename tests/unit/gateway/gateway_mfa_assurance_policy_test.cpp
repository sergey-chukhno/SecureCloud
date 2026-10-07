#include "http/auth/authorization_middleware.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/auth/request_context.hpp"
#include "http/routing/router.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace securecloud::gateway::http::test {
namespace {

AuthenticatedContext make_context(std::string user_id, std::string device_id,
                                  securecloud::auth::v1::AuthenticationLevel level,
                                  std::vector<std::string> scopes = {"access"}) {
    auto now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    return AuthenticatedContext(std::move(user_id), std::move(device_id), "sess-test", level, std::move(scopes),
                                now_ms + 3600000);
}

class GatewayMfaAssurancePolicyTest : public ::testing::Test {
  protected:
    void SetUp() override {
        policy_ = std::make_shared<GatewaySecurityPolicy>(GatewaySecurityPolicy::create_default());
        authz_middleware_ = std::make_shared<AuthorizationMiddleware>(policy_);

        router_ = std::make_unique<Router>();
        router_->use(authz_middleware_);

        // Register dummy downstream handlers for tested endpoints
        router_->get("/api/v1/auth/me", [this](const httplib::Request&, httplib::Response& res) {
            handler_invoked_ = true;
            res.status = 200;
            res.set_content(R"({"status":"USER_PROFILE"})", "application/json");
        });

        router_->post("/api/v1/auth/mfa/disable", [this](const httplib::Request&, httplib::Response& res) {
            handler_invoked_ = true;
            res.status = 200;
            res.set_content(R"({"status":"MFA_DISABLED"})", "application/json");
        });

        router_->post("/api/v1/auth/devices/revoke", [this](const httplib::Request&, httplib::Response& res) {
            handler_invoked_ = true;
            res.status = 200;
            res.set_content(R"({"status":"DEVICE_REVOKED"})", "application/json");
        });

        router_->del("/api/v1/user/delete", [this](const httplib::Request&, httplib::Response& res) {
            handler_invoked_ = true;
            res.status = 200;
            res.set_content(R"({"status":"USER_DELETED"})", "application/json");
        });

        router_->post("/api/v1/admin/settings", [this](const httplib::Request&, httplib::Response& res) {
            handler_invoked_ = true;
            res.status = 200;
            res.set_content(R"({"status":"ADMIN_OK"})", "application/json");
        });
    }

    std::shared_ptr<GatewaySecurityPolicy> policy_;
    std::shared_ptr<AuthorizationMiddleware> authz_middleware_;
    std::unique_ptr<Router> router_;
    bool handler_invoked_{false};
};

// ============================================================================
// 1. Unauthenticated Requests Rejected with 401
// ============================================================================

TEST_F(GatewayMfaAssurancePolicyTest, StandardRoute_Unauthenticated_RejectsWith401) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/auth/me";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 401);
    EXPECT_TRUE(res.has_header("WWW-Authenticate"));

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "UNAUTHENTICATED");
}

TEST_F(GatewayMfaAssurancePolicyTest, SensitiveRoute_Unauthenticated_RejectsWith401) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/mfa/disable";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 401);
    EXPECT_TRUE(res.has_header("WWW-Authenticate"));

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "UNAUTHENTICATED");
}

// ============================================================================
// 2. Standard Protected Route Allows PrimaryOnly Tokens
// ============================================================================

TEST_F(GatewayMfaAssurancePolicyTest, StandardRoute_PrimaryOnlyToken_AllowsAccess) {
    auto ctx = make_context("usr-1", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                            {"user:profile"});

    RequestContext req_ctx("req-std-1", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/auth/me";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

// ============================================================================
// 3. Sensitive Operations Reject PrimaryOnly Tokens with 403 Forbidden
// ============================================================================

TEST_F(GatewayMfaAssurancePolicyTest, SensitiveRoute_MfaDisable_PrimaryOnlyToken_RejectsWith403) {
    auto ctx = make_context("usr-1", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    RequestContext req_ctx("req-mfa-dis", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/mfa/disable";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 403);

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "MFA_REQUIRED");
    EXPECT_EQ(json["error"]["assurance_error"], "INSUFFICIENT_AUTHENTICATION_ASSURANCE");
    EXPECT_EQ(json["error"]["message"], "Operation requires multi-factor authentication");
}

TEST_F(GatewayMfaAssurancePolicyTest, SensitiveRoute_DevicesRevoke_PrimaryOnlyToken_RejectsWith403) {
    auto ctx = make_context("usr-1", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    RequestContext req_ctx("req-dev-rev", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/devices/revoke";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 403);

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "MFA_REQUIRED");
}

TEST_F(GatewayMfaAssurancePolicyTest, SensitiveRoute_UserDelete_PrimaryOnlyToken_RejectsWith403) {
    auto ctx = make_context("usr-1", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    RequestContext req_ctx("req-usr-del", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "DELETE";
    req.path = "/api/v1/user/delete";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 403);

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "MFA_REQUIRED");
}

TEST_F(GatewayMfaAssurancePolicyTest, SensitiveRoute_AdminEndpoint_PrimaryOnlyToken_RejectsWith403) {
    auto ctx = make_context("usr-1", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    RequestContext req_ctx("req-admin", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/admin/settings";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 403);

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "MFA_REQUIRED");
}

// ============================================================================
// 4. Sensitive Operations Allow MfaVerified Tokens with 200 OK
// ============================================================================

TEST_F(GatewayMfaAssurancePolicyTest, SensitiveRoute_MfaDisable_MfaVerifiedToken_AllowsAccess) {
    auto ctx = make_context("usr-1", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    RequestContext req_ctx("req-mfa-ok", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/mfa/disable";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

TEST_F(GatewayMfaAssurancePolicyTest, SensitiveRoute_DevicesRevoke_MfaVerifiedToken_AllowsAccess) {
    auto ctx = make_context("usr-1", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    RequestContext req_ctx("req-rev-ok", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/devices/revoke";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

TEST_F(GatewayMfaAssurancePolicyTest, SensitiveRoute_UserDelete_MfaVerifiedToken_AllowsAccess) {
    auto ctx = make_context("usr-1", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    RequestContext req_ctx("req-del-ok", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "DELETE";
    req.path = "/api/v1/user/delete";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

TEST_F(GatewayMfaAssurancePolicyTest, SensitiveRoute_AdminEndpoint_MfaVerifiedToken_AllowsAccess) {
    auto ctx = make_context("usr-1", "dev-1",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    RequestContext req_ctx("req-adm-ok", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/admin/settings";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

} // namespace
} // namespace securecloud::gateway::http::test
