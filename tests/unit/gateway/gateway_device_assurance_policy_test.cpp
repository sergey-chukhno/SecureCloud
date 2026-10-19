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

class GatewayDeviceAssurancePolicyTest : public ::testing::Test {
  protected:
    void SetUp() override {
        policy_ = std::make_shared<GatewaySecurityPolicy>(GatewaySecurityPolicy::create_default());
        authz_middleware_ = std::make_shared<AuthorizationMiddleware>(policy_);

        router_ = std::make_unique<Router>();
        router_->use(authz_middleware_);

        // Register dummy downstream handlers for tested endpoints
        router_->post("/api/v1/devices/register", [this](const httplib::Request& req, httplib::Response& res) {
            handler_invoked_ = true;
            last_received_headers_ = req.headers;
            res.status = 200;
            res.set_content(R"({"status":"REGISTERED"})", "application/json");
        });

        router_->post("/api/v1/devices/authorize", [this](const httplib::Request& req, httplib::Response& res) {
            handler_invoked_ = true;
            last_received_headers_ = req.headers;
            res.status = 200;
            res.set_content(R"({"status":"AUTHORIZED"})", "application/json");
        });

        router_->post("/api/v1/devices/revoke", [this](const httplib::Request& req, httplib::Response& res) {
            handler_invoked_ = true;
            last_received_headers_ = req.headers;
            res.status = 200;
            res.set_content(R"({"status":"REVOKED"})", "application/json");
        });

        router_->get("/api/v1/devices", [this](const httplib::Request& req, httplib::Response& res) {
            handler_invoked_ = true;
            last_received_headers_ = req.headers;
            res.status = 200;
            res.set_content(R"({"status":"DEVICES_LIST"})", "application/json");
        });

        router_->get("/api/v1/devices/dev-123", [this](const httplib::Request& req, httplib::Response& res) {
            handler_invoked_ = true;
            last_received_headers_ = req.headers;
            res.status = 200;
            res.set_content(R"({"status":"DEVICE_DETAIL"})", "application/json");
        });

        // Aliases under /api/v1/auth/devices/...
        router_->post("/api/v1/auth/devices/register", [this](const httplib::Request& req, httplib::Response& res) {
            handler_invoked_ = true;
            last_received_headers_ = req.headers;
            res.status = 200;
            res.set_content(R"({"status":"AUTH_REGISTERED"})", "application/json");
        });

        router_->post("/api/v1/auth/devices/authorize", [this](const httplib::Request& req, httplib::Response& res) {
            handler_invoked_ = true;
            last_received_headers_ = req.headers;
            res.status = 200;
            res.set_content(R"({"status":"AUTH_AUTHORIZED"})", "application/json");
        });

        router_->get("/api/v1/auth/devices", [this](const httplib::Request& req, httplib::Response& res) {
            handler_invoked_ = true;
            last_received_headers_ = req.headers;
            res.status = 200;
            res.set_content(R"({"status":"AUTH_DEVICES_LIST"})", "application/json");
        });
    }

    std::shared_ptr<GatewaySecurityPolicy> policy_;
    std::shared_ptr<AuthorizationMiddleware> authz_middleware_;
    std::unique_ptr<Router> router_;
    bool handler_invoked_{false};
    httplib::Headers last_received_headers_{};
};

// ============================================================================
// 1. Unauthenticated Requests Rejected with 401
// ============================================================================

TEST_F(GatewayDeviceAssurancePolicyTest, RegisterDevice_Unauthenticated_RejectsWith401) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/register";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 401);
    EXPECT_TRUE(res.has_header("WWW-Authenticate"));

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "UNAUTHENTICATED");
}

TEST_F(GatewayDeviceAssurancePolicyTest, AuthorizeDevice_Unauthenticated_RejectsWith401) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/authorize";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 401);
}

TEST_F(GatewayDeviceAssurancePolicyTest, RevokeDevice_Unauthenticated_RejectsWith401) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/revoke";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 401);
}

TEST_F(GatewayDeviceAssurancePolicyTest, ListDevices_Unauthenticated_RejectsWith401) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 401);
}

// ============================================================================
// 2. Primary-Only Tokens on Sensitive Routes Rejected with 403 Forbidden
// ============================================================================

TEST_F(GatewayDeviceAssurancePolicyTest, RegisterDevice_PrimaryOnlyToken_RejectsWith403AndAssuranceError) {
    auto ctx = make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    RequestContext req_ctx("req-dev-reg", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/register";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 403);

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "MFA_REQUIRED");
    EXPECT_EQ(json["assurance_error"], "INSUFFICIENT_AUTHENTICATION_ASSURANCE");
}

TEST_F(GatewayDeviceAssurancePolicyTest, AuthorizeDevice_PrimaryOnlyToken_RejectsWith403AndAssuranceError) {
    auto ctx = make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    RequestContext req_ctx("req-dev-auth", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/authorize";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 403);

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "MFA_REQUIRED");
    EXPECT_EQ(json["assurance_error"], "INSUFFICIENT_AUTHENTICATION_ASSURANCE");
}

TEST_F(GatewayDeviceAssurancePolicyTest, RevokeDevice_PrimaryOnlyToken_RejectsWith403AndAssuranceError) {
    auto ctx = make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    RequestContext req_ctx("req-dev-rev", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/revoke";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 403);

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "MFA_REQUIRED");
    EXPECT_EQ(json["assurance_error"], "INSUFFICIENT_AUTHENTICATION_ASSURANCE");
}

// ============================================================================
// 3. Primary-Only Tokens on Protected Routes Allowed with 200 OK
// ============================================================================

TEST_F(GatewayDeviceAssurancePolicyTest, ListDevices_PrimaryOnlyToken_AllowsAccess) {
    auto ctx = make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    RequestContext req_ctx("req-dev-list", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

TEST_F(GatewayDeviceAssurancePolicyTest, GetDeviceDetail_PrimaryOnlyToken_AllowsAccess) {
    auto ctx = make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    RequestContext req_ctx("req-dev-get", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices/dev-123";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

// ============================================================================
// 4. MfaVerified Tokens on Sensitive Routes Allowed with 200 OK & Header Propagation
// ============================================================================

TEST_F(GatewayDeviceAssurancePolicyTest, RegisterDevice_MfaVerifiedToken_AllowsAccessAndPropagatesMetadata) {
    auto ctx = make_context("usr-alice", "dev-laptop",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    RequestContext req_ctx("req-dev-mfa", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/register";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);

    // Verify metadata propagation
    EXPECT_EQ(last_received_headers_.find("x-user-id")->second, "usr-alice");
    EXPECT_EQ(last_received_headers_.find("x-device-id")->second, "dev-laptop");
    EXPECT_EQ(last_received_headers_.find("x-auth-level")->second, "mfa_verified");
}

TEST_F(GatewayDeviceAssurancePolicyTest, AuthorizeDevice_MfaVerifiedToken_AllowsAccess) {
    auto ctx = make_context("usr-alice", "dev-phone",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    RequestContext req_ctx("req-dev-auth-mfa", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/authorize";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(last_received_headers_.find("x-auth-level")->second, "mfa_verified");
}

TEST_F(GatewayDeviceAssurancePolicyTest, RevokeDevice_MfaVerifiedToken_AllowsAccess) {
    auto ctx = make_context("usr-alice", "dev-phone",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    RequestContext req_ctx("req-dev-rev-mfa", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/revoke";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(last_received_headers_.find("x-auth-level")->second, "mfa_verified");
}

// ============================================================================
// 5. Auth Aliases Behave Identically
// ============================================================================

TEST_F(GatewayDeviceAssurancePolicyTest, AuthAlias_RegisterDevice_PrimaryOnlyToken_RejectsWith403) {
    auto ctx = make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    RequestContext req_ctx("req-alias-reg", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/devices/register";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_invoked_);
    EXPECT_EQ(res.status, 403);
}

TEST_F(GatewayDeviceAssurancePolicyTest, AuthAlias_RegisterDevice_MfaVerifiedToken_AllowsAccess) {
    auto ctx =
        make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    RequestContext req_ctx("req-alias-mfa", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/devices/register";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

TEST_F(GatewayDeviceAssurancePolicyTest, AuthAlias_ListDevices_PrimaryOnlyToken_AllowsAccess) {
    auto ctx = make_context("usr-1", "dev-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    RequestContext req_ctx("req-alias-list", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/auth/devices";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_invoked_);
    EXPECT_EQ(res.status, 200);
}

} // namespace
} // namespace securecloud::gateway::http::test
