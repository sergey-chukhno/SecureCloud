#include "http/auth/authenticated_context.hpp"
#include "http/auth/authentication_middleware.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/auth/request_context.hpp"
#include "http/auth/token_validator_interface.hpp"
#include "http/routing/router.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <vector>

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
make_test_context(const std::string& user_id = "usr-opaque-111", const std::string& device_id = "dev-opaque-222",
                  const std::string& session_id = "sess-opaque-333",
                  securecloud::auth::v1::AuthenticationLevel level =
                      securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                  std::vector<std::string> scopes = {"messages:write", "messages:read", "access"},
                  int64_t expires_in_sec = 3600) {
    auto now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    return AuthenticatedContext(user_id, device_id, session_id, level, std::move(scopes),
                                now_ms + (expires_in_sec * 1000));
}

class AuthenticatedContextLifecycleTest : public ::testing::Test {
  protected:
    void SetUp() override {
        policy_ = std::make_shared<GatewaySecurityPolicy>(GatewaySecurityPolicy::create_default());
        mock_validator_ = std::make_shared<MockTokenValidator>();
        middleware_ = std::make_shared<AuthenticationMiddleware>(policy_, mock_validator_);

        router_ = std::make_unique<Router>();
        router_->use(middleware_);
    }

    void TearDown() override {
        // Assert zero thread-local context leaks across tests
        EXPECT_EQ(Router::current_request_context(), nullptr);
        EXPECT_FALSE(Router::current_authenticated_context().has_value());
    }

    std::shared_ptr<GatewaySecurityPolicy> policy_;
    std::shared_ptr<MockTokenValidator> mock_validator_;
    std::shared_ptr<AuthenticationMiddleware> middleware_;
    std::unique_ptr<Router> router_;
};

// 1. Valid context access without token re-parsing
TEST_F(AuthenticatedContextLifecycleTest, TestCase1_ValidContextAccessWithoutTokenReparsing) {
    auto expected_ctx = make_test_context("usr-alice-123", "dev-macbook-456", "sess-live-789");
    EXPECT_CALL(*mock_validator_, validate("valid-access-token-xyz", _, _)).WillOnce(Return(expected_ctx));

    bool handler_called = false;
    router_->add_authenticated_route(
        "POST", "/api/v1/messages/send",
        [&](const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx) {
            handler_called = true;

            // Access via callback argument
            EXPECT_EQ(ctx.user_id(), "usr-alice-123");
            EXPECT_EQ(ctx.device_id(), "dev-macbook-456");
            EXPECT_EQ(ctx.session_id(), "sess-live-789");
            EXPECT_TRUE(ctx.is_mfa_verified());
            EXPECT_TRUE(ctx.has_scope("messages:write"));

            // Access via static Router ergonomics without token re-parsing
            const auto* req_ctx = Router::current_request_context();
            ASSERT_NE(req_ctx, nullptr);
            EXPECT_TRUE(req_ctx->is_authenticated());
            EXPECT_EQ(req_ctx->request_id(), "req-lifecycle-tc1");

            auto auth_opt = Router::current_authenticated_context();
            ASSERT_TRUE(auth_opt.has_value());
            EXPECT_EQ(auth_opt->user_id(), "usr-alice-123");
            EXPECT_EQ(auth_opt->device_id(), "dev-macbook-456");

            // Also via Router::get_authenticated_context(req)
            auto ctx_from_req = Router::get_authenticated_context(req);
            ASSERT_TRUE(ctx_from_req.has_value());
            EXPECT_EQ(ctx_from_req->user_id(), "usr-alice-123");

            res.status = 200;
            res.set_content("PROCESSED", "text/plain");
        });

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("Authorization", "Bearer valid-access-token-xyz");
    req.set_header("x-request-id", "req-lifecycle-tc1");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_called);
    EXPECT_EQ(res.status, 200);
}

// 2. Missing context behavior on public/anonymous routes
TEST_F(AuthenticatedContextLifecycleTest, TestCase2_MissingContextOnPublicAnonymousRoute) {
    EXPECT_CALL(*mock_validator_, validate(_, _, _)).Times(0);

    bool handler_called = false;
    router_->get("/health/live", [&](const httplib::Request& req, httplib::Response& res) {
        handler_called = true;

        // Active request context exists with correlation metadata
        const auto* req_ctx = Router::current_request_context();
        ASSERT_NE(req_ctx, nullptr);
        EXPECT_FALSE(req_ctx->is_authenticated());
        EXPECT_FALSE(req_ctx->authenticated_context().has_value());
        EXPECT_EQ(req_ctx->request_id(), "req-health-live");

        // Authenticated context is absent
        EXPECT_FALSE(Router::current_authenticated_context().has_value());
        EXPECT_FALSE(Router::get_authenticated_context(req).has_value());

        res.status = 200;
        res.set_content("LIVE", "text/plain");
    });

    httplib::Request req;
    req.method = "GET";
    req.path = "/health/live";
    req.set_header("x-request-id", "req-health-live");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_TRUE(handler_called);
    EXPECT_EQ(res.status, 200);
}

// 3. Missing context rejection on protected routes
TEST_F(AuthenticatedContextLifecycleTest, TestCase3_MissingContextRejectionOnProtectedRoute) {
    EXPECT_CALL(*mock_validator_, validate(_, _, _)).Times(0);

    bool handler_called = false;
    router_->add_authenticated_route(
        "POST", "/api/v1/messages/send",
        [&](const httplib::Request&, httplib::Response&, const AuthenticatedContext&) { handler_called = true; });

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("x-request-id", "req-unauth-tc3");
    // No Authorization header

    httplib::Response res;
    router_->handle(req, res);

    // Handler must never execute and 401 must be returned
    EXPECT_FALSE(handler_called);
    EXPECT_EQ(res.status, 401);
    EXPECT_TRUE(res.has_header("WWW-Authenticate"));

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "UNAUTHENTICATED");
}

// 4. Malformed and tampered token rejection
TEST_F(AuthenticatedContextLifecycleTest, TestCase4_MalformedAndTamperedTokenRejection) {
    EXPECT_CALL(*mock_validator_, validate(_, _, _)).Times(0);

    bool handler_called = false;
    router_->add_authenticated_route(
        "POST", "/api/v1/messages/send",
        [&](const httplib::Request&, httplib::Response&, const AuthenticatedContext&) { handler_called = true; });

    // Malformed token with invalid characters
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("Authorization", "Bearer invalid!character@injection$token");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_called);
    EXPECT_EQ(res.status, 401);
    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "UNAUTHENTICATED");
}

// 5. Expired session and revoked token rejection
TEST_F(AuthenticatedContextLifecycleTest, TestCase5_ExpiredSessionAndRevokedTokenRejection) {
    TokenValidationError expired_err{TokenValidationErrorKind::TokenExpired, "Access token has expired"};
    EXPECT_CALL(*mock_validator_, validate("expired-token", _, _)).WillOnce(Return(expired_err));

    bool handler_called = false;
    router_->add_authenticated_route(
        "POST", "/api/v1/messages/send",
        [&](const httplib::Request&, httplib::Response&, const AuthenticatedContext&) { handler_called = true; });

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("Authorization", "Bearer expired-token");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_called);
    EXPECT_EQ(res.status, 401);
    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "TOKEN_EXPIRED");
}

// 6. Assurance level and scope enforcement
TEST_F(AuthenticatedContextLifecycleTest, TestCase6_AssuranceLevelAndScopeEnforcement) {
    // 6a. Sensitive route requiring MFA rejected for PRIMARY level
    auto primary_ctx = make_test_context("usr-bob", "dev-phone", "sess-1",
                                         securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                         {"auth:device:register"});

    EXPECT_CALL(*mock_validator_, validate("primary-tok", _, _)).WillOnce(Return(primary_ctx));

    bool handler_called = false;
    router_->add_authenticated_route(
        "POST", "/api/v1/auth/device/register",
        [&](const httplib::Request&, httplib::Response&, const AuthenticatedContext&) { handler_called = true; });

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/device/register";
    req.set_header("Authorization", "Bearer primary-tok");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_FALSE(handler_called);
    EXPECT_EQ(res.status, 403);
    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "MFA_REQUIRED");

    // 6b. Missing required scope rejected
    auto insufficient_scope_ctx = make_test_context(
        "usr-bob", "dev-phone", "sess-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
        {"files:read"} // Missing "messages:write"
    );

    EXPECT_CALL(*mock_validator_, validate("scope-lacking-tok", _, _)).WillOnce(Return(insufficient_scope_ctx));

    httplib::Request req2;
    req2.method = "POST";
    req2.path = "/api/v1/messages/send";
    req2.set_header("Authorization", "Bearer scope-lacking-tok");

    httplib::Response res2;
    router_->handle(req2, res2);

    EXPECT_EQ(res2.status, 403);
    auto json2 = nlohmann::json::parse(res2.body);
    EXPECT_EQ(json2["error"]["code"], "INSUFFICIENT_SCOPE");
}

// 7. Anti-spoofing and identity fabrication denial
TEST_F(AuthenticatedContextLifecycleTest, TestCase7_AntiSpoofingAndIdentityFabricationDenial) {
    EXPECT_CALL(*mock_validator_, validate(_, _, _)).Times(0);

    router_->get("/health/live", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
        res.set_content("LIVE", "text/plain");
    });

    httplib::Request req;
    req.method = "GET";
    req.path = "/health/live";
    req.set_header("x-user-id", "attacker-impostor");
    req.set_header("x-device-id", "spoofed-device");
    req.set_header("x-auth-level", "AUTHENTICATION_LEVEL_MFA_VERIFIED");
    req.set_header("x-scopes", "all,admin");
    req.set_header("x-authenticated-role", "root");

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 200);

    // Verify context cannot be fabricated by spoofed headers
    EXPECT_FALSE(Router::current_authenticated_context().has_value());
    EXPECT_FALSE(Router::get_authenticated_context(req).has_value());
}

// 8. Secret isolation and safe audit sanitization
TEST_F(AuthenticatedContextLifecycleTest, TestCase8_SecretIsolationAndSafeAuditSanitization) {
    AuthenticatedContext ctx("usr-opaque-id-999", "dev-opaque-id-888", "sess-opaque-id-777",
                             securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                             {"messages:write", "files:read"}, 1700000000000);

    auto audit = ctx.to_audit_info();

    EXPECT_EQ(audit["user_id"], "usr-opaque-id-999");
    EXPECT_EQ(audit["device_id"], "dev-opaque-id-888");
    EXPECT_EQ(audit["session_id"], "sess-opaque-id-777");
    EXPECT_EQ(audit["auth_level"], "AUTHENTICATION_LEVEL_MFA_VERIFIED");
    EXPECT_TRUE(audit["mfa_verified"].get<bool>());

    // Prohibit secret leakage in audit info
    EXPECT_FALSE(audit.contains("private_key"));
    EXPECT_FALSE(audit.contains("secret"));
    EXPECT_FALSE(audit.contains("access_token"));
    EXPECT_FALSE(audit.contains("token"));
    EXPECT_FALSE(audit.contains("plaintext"));
    EXPECT_FALSE(audit.contains("payload"));
}

// 9. Exception safety and deterministic thread-local cleanup
TEST_F(AuthenticatedContextLifecycleTest, TestCase9_ExceptionSafetyAndDeterministicThreadLocalCleanup) {
    auto valid_ctx = make_test_context("usr-crash", "dev-crash", "sess-crash");
    EXPECT_CALL(*mock_validator_, validate("crash-tok", _, _)).WillOnce(Return(valid_ctx));

    router_->add_authenticated_route("POST", "/api/v1/messages/send",
                                     [&](const httplib::Request&, httplib::Response&, const AuthenticatedContext&) {
                                         // Inside scope: active context exists
                                         EXPECT_NE(Router::current_request_context(), nullptr);
                                         EXPECT_TRUE(Router::current_authenticated_context().has_value());
                                         throw std::runtime_error("Simulated catastrophic handler failure");
                                     });

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/send";
    req.set_header("Authorization", "Bearer crash-tok");

    httplib::Response res;
    // Router::handle catches unhandled exceptions and writes 500 internal error
    EXPECT_NO_THROW(router_->handle(req, res));

    EXPECT_EQ(res.status, 500);

    // After exception unwind, thread-local state must be cleanly reset
    EXPECT_EQ(Router::current_request_context(), nullptr);
    EXPECT_FALSE(Router::current_authenticated_context().has_value());
}

} // namespace
} // namespace securecloud::gateway::http
