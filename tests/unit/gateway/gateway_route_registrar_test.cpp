#include "grpc/auth_client_interface.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/auth/request_context.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/routing/gateway_route_registrar.hpp"
#include "http/routing/router.hpp"
#include "securecloud/health/health_status_manager.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>

namespace securecloud::gateway::http {
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
};

class GatewayRouteRegistrarTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_auth_client_ = std::make_shared<MockAuthClient>();
        auth_proxy_ = std::make_shared<AuthProxyHandler>(mock_auth_client_);
        health_manager_ = std::make_unique<common::health::HealthStatusManager>("gateway-test");
        registrar_ = std::make_unique<GatewayRouteRegistrar>(auth_proxy_, *health_manager_);
    }

    std::shared_ptr<MockAuthClient> mock_auth_client_;
    std::shared_ptr<AuthProxyHandler> auth_proxy_;
    std::unique_ptr<common::health::HealthStatusManager> health_manager_;
    std::unique_ptr<GatewayRouteRegistrar> registrar_;
};

TEST_F(GatewayRouteRegistrarTest, ConstructorThrowsOnNullAuthProxy) {
    EXPECT_THROW(GatewayRouteRegistrar(nullptr, *health_manager_), std::invalid_argument);
    std::shared_ptr<common::health::HealthStatusManager> hm_ptr = std::move(health_manager_);
    EXPECT_THROW(GatewayRouteRegistrar(nullptr, hm_ptr), std::invalid_argument);
    EXPECT_THROW(GatewayRouteRegistrar(auth_proxy_, nullptr), std::invalid_argument);
}

TEST_F(GatewayRouteRegistrarTest, RegisterAllRoutesPopulatesRouterTable) {
    Router router;
    EXPECT_EQ(router.route_count(), 0);

    registrar_->register_all_routes(router);

    // Expected routes:
    // Health: 2 (/health/live, /health/ready)
    // Auth Core: 5 (/api/v1/auth/login, /api/v1/auth/refresh, /api/v1/auth/revoke, /api/v1/users/me, /api/v1/devices)
    // Auth Aliases: 3 (/api/v1/auth/me, /api/v1/auth/device/register, /api/v1/auth/logout)
    // Stubs: 6 (3 messages, 2 files, 1 audit)
    // Total = 16 routes
    EXPECT_EQ(router.route_count(), 16);
}

TEST_F(GatewayRouteRegistrarTest, HealthLiveServing) {
    Router router;
    registrar_->register_health_routes(router);

    health_manager_->set_live(true);

    httplib::Request req;
    req.method = "GET";
    req.path = "/health/live";

    httplib::Response res;
    router.handle(req, res);

    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(res.get_header_value("Content-Type"), "application/json");
    EXPECT_EQ(res.body, R"({"status":"SERVING"})");
}

TEST_F(GatewayRouteRegistrarTest, HealthLiveNotServing) {
    Router router;
    registrar_->register_health_routes(router);

    health_manager_->set_live(false);

    httplib::Request req;
    req.method = "GET";
    req.path = "/health/live";

    httplib::Response res;
    router.handle(req, res);

    EXPECT_EQ(res.status, 503);
    EXPECT_EQ(res.body, R"({"status":"NOT_SERVING"})");
}

TEST_F(GatewayRouteRegistrarTest, HealthReadyServing) {
    Router router;
    registrar_->register_health_routes(router);

    health_manager_->set_live(true);
    health_manager_->set_ready(true);
    health_manager_->set_readiness_evaluator([] { return true; });

    httplib::Request req;
    req.method = "GET";
    req.path = "/health/ready";

    httplib::Response res;
    router.handle(req, res);

    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(res.body, R"({"status":"SERVING"})");
}

TEST_F(GatewayRouteRegistrarTest, HealthReadyNotServing) {
    Router router;
    registrar_->register_health_routes(router);

    health_manager_->set_ready(false);

    httplib::Request req;
    req.method = "GET";
    req.path = "/health/ready";

    httplib::Response res;
    router.handle(req, res);

    EXPECT_EQ(res.status, 503);
    EXPECT_EQ(res.body, R"({"status":"NOT_SERVING"})");
}

TEST_F(GatewayRouteRegistrarTest, AuthLoginDispatchesToAuthProxy) {
    Router router;
    registrar_->register_auth_routes(router);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/login";
    req.body = nlohmann::json{{"identifier", "alice@securecloud.org"}, {"credential", "Secret123!"}}.dump();

    securecloud::auth::v1::AuthenticateResponse auth_resp;
    auth_resp.set_session_id("sess-test-456");
    auth_resp.set_access_token("token-test");
    auth_resp.set_refresh_token("refresh-test");
    auth_resp.set_user_id("user-test");

    EXPECT_CALL(*mock_auth_client_, authenticate(_, _))
        .WillOnce(Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(auth_resp)));

    httplib::Response res;
    router.handle(req, res);

    EXPECT_EQ(res.status, 200);
    auto j = nlohmann::json::parse(res.body);
    EXPECT_EQ(j["session_id"], "sess-test-456");
}

TEST_F(GatewayRouteRegistrarTest, AuthMeAliasDispatchesToAuthProxy) {
    Router router;
    registrar_->register_auth_routes(router);

    AuthenticatedContext auth_ctx("user-alice-uuid", "dev-1", "sess-1",
                                  securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {},
                                  2000000000000LL);
    RequestContext req_ctx("req-corr-1", "127.0.0.1", 1700000000000LL, auth_ctx);
    ScopedRequestContext scope_guard(req_ctx);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/auth/me";

    securecloud::auth::v1::GetUserResponse user_resp;
    user_resp.mutable_user()->set_user_id("user-alice-uuid");
    user_resp.mutable_user()->set_credential_identifier("alice@securecloud.org");

    EXPECT_CALL(*mock_auth_client_, get_user(_, _))
        .WillOnce([&user_resp](const securecloud::auth::v1::GetUserRequest& grpc_req,
                               securecloud::gateway::grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(grpc_req.user_id(), "user-alice-uuid");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::GetUserResponse>(user_resp);
        });

    httplib::Response res;
    router.handle(req, res);

    EXPECT_EQ(res.status, 200);
    auto j = nlohmann::json::parse(res.body);
    EXPECT_EQ(j["user"]["user_id"], "user-alice-uuid");
}

TEST_F(GatewayRouteRegistrarTest, StubRoutesReturn501NotImplemented) {
    Router router;
    registrar_->register_stub_routes(router);

    AuthenticatedContext auth_ctx("user-bob-uuid", "dev-2", "sess-2",
                                  securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {},
                                  2000000000000LL);
    RequestContext req_ctx("req-stub-test", "127.0.0.1", 1700000000000LL, auth_ctx);
    ScopedRequestContext scope_guard(req_ctx);

    // 1. Messaging send stub
    {
        httplib::Request req;
        req.method = "POST";
        req.path = "/api/v1/messages/send";
        httplib::Response res;
        router.handle(req, res);
        EXPECT_EQ(res.status, 501);
        auto j = nlohmann::json::parse(res.body);
        EXPECT_EQ(j["error"]["code"], "NOT_IMPLEMENTED");
        EXPECT_EQ(j["error"]["request_id"], "req-stub-test");
    }

    // 2. Files upload stub
    {
        httplib::Request req;
        req.method = "POST";
        req.path = "/api/v1/files/upload";
        httplib::Response res;
        router.handle(req, res);
        EXPECT_EQ(res.status, 501);
        auto j = nlohmann::json::parse(res.body);
        EXPECT_EQ(j["error"]["code"], "NOT_IMPLEMENTED");
    }

    // 3. Audit events stub
    {
        httplib::Request req;
        req.method = "GET";
        req.path = "/api/v1/audit/events";
        httplib::Response res;
        router.handle(req, res);
        EXPECT_EQ(res.status, 501);
        auto j = nlohmann::json::parse(res.body);
        EXPECT_EQ(j["error"]["code"], "NOT_IMPLEMENTED");
    }
}

TEST_F(GatewayRouteRegistrarTest, SharedPtrConstructorOverload) {
    auto hm_shared = std::make_shared<common::health::HealthStatusManager>("gateway-shared");
    GatewayRouteRegistrar registrar_shared(auth_proxy_, hm_shared);

    Router router;
    registrar_shared.register_all_routes(router);
    EXPECT_EQ(router.route_count(), 16);
}

} // namespace
} // namespace securecloud::gateway::http
