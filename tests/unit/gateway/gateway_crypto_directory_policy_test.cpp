#include "http/auth/authorization_middleware.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/auth/request_context.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/routing/router.hpp"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

using ::testing::_;
using ::testing::Return;

namespace securecloud::gateway::http::test {
namespace {

class MockAuthClientForPolicy : public securecloud::gateway::grpc::IAuthClient {
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
};

AuthenticatedContext make_context(std::string user_id, std::string device_id,
                                  securecloud::auth::v1::AuthenticationLevel level,
                                  std::vector<std::string> scopes = {"access"}) {
    auto now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    return AuthenticatedContext(std::move(user_id), std::move(device_id), "sess-test", level, std::move(scopes),
                                now_ms + 3600000);
}

class GatewayCryptoDirectoryPolicyTest : public ::testing::Test {
  protected:
    void SetUp() override {
        policy_ = std::make_shared<GatewaySecurityPolicy>(GatewaySecurityPolicy::create_default());
        authz_middleware_ = std::make_shared<AuthorizationMiddleware>(policy_);

        router_ = std::make_unique<Router>();
        router_->use(authz_middleware_);

        mock_auth_client_ = std::make_shared<MockAuthClientForPolicy>();
        auth_proxy_ = std::make_shared<AuthProxyHandler>(mock_auth_client_);
        auth_proxy_->register_routes(*router_);
    }

    std::shared_ptr<GatewaySecurityPolicy> policy_;
    std::shared_ptr<AuthorizationMiddleware> authz_middleware_;
    std::unique_ptr<Router> router_;
    std::shared_ptr<MockAuthClientForPolicy> mock_auth_client_;
    std::shared_ptr<AuthProxyHandler> auth_proxy_;
};

TEST_F(GatewayCryptoDirectoryPolicyTest, PolicyEvaluatesCryptoRoutesAsProtectedPrimary) {
    auto rule_dir = policy_->evaluate("GET", "/api/v1/users/user-uuid-1/devices/crypto-directory");
    EXPECT_EQ(rule_dir.access, RouteAccess::Protected);
    EXPECT_EQ(rule_dir.min_auth_level, securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    EXPECT_FALSE(rule_dir.is_public());
    EXPECT_FALSE(rule_dir.requires_mfa());

    auto rule_ident = policy_->evaluate("GET", "/api/v1/devices/dev-uuid-1/crypto-identity");
    EXPECT_EQ(rule_ident.access, RouteAccess::Protected);
    EXPECT_EQ(rule_ident.min_auth_level, securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    EXPECT_FALSE(rule_ident.is_public());
    EXPECT_FALSE(rule_ident.requires_mfa());

    auto rule_prekeys = policy_->evaluate("POST", "/api/v1/devices/dev-uuid-1/prekeys");
    EXPECT_EQ(rule_prekeys.access, RouteAccess::Protected);
    EXPECT_EQ(rule_prekeys.min_auth_level, securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    EXPECT_FALSE(rule_prekeys.is_public());
    EXPECT_FALSE(rule_prekeys.requires_mfa());
}

TEST_F(GatewayCryptoDirectoryPolicyTest, UnauthenticatedGetCryptoDirectoryReturns401) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/users/user-123/devices/crypto-directory";
    httplib::Response res;

    router_->handle(req, res);

    EXPECT_EQ(res.status, 401);
    EXPECT_TRUE(res.has_header("WWW-Authenticate"));
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "UNAUTHENTICATED");
}

TEST_F(GatewayCryptoDirectoryPolicyTest, UnauthenticatedGetCryptoIdentityReturns401) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices/dev-456/crypto-identity";
    httplib::Response res;

    router_->handle(req, res);

    EXPECT_EQ(res.status, 401);
    EXPECT_TRUE(res.has_header("WWW-Authenticate"));
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "UNAUTHENTICATED");
}

TEST_F(GatewayCryptoDirectoryPolicyTest, UnauthenticatedPostPrekeysReturns401) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/dev-456/prekeys";
    req.body = R"({"signed_prekey":"spk","signed_prekey_signature":"sig"})";
    httplib::Response res;

    router_->handle(req, res);

    EXPECT_EQ(res.status, 401);
    EXPECT_TRUE(res.has_header("WWW-Authenticate"));
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "UNAUTHENTICATED");
}

TEST_F(GatewayCryptoDirectoryPolicyTest, AuthenticatedGetCryptoDirectorySuccessAndMetadataInjected) {
    auto ctx = make_context("user-alice", "dev-alice",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    RequestContext req_ctx("req-dir-001", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    securecloud::auth::v1::GetDeviceCryptoDirectoryResponse dir_resp;
    auto* rec = dir_resp.add_devices();
    rec->set_device_id("dev-bob-phone");
    rec->set_identity_key("id-key-data");
    rec->set_signed_prekey("spk-data");
    rec->set_signed_prekey_signature("spk-sig");
    rec->set_status(securecloud::auth::v1::DeviceStatus::DEVICE_STATUS_ACTIVE);
    rec->set_identity_key_fingerprint("fp-sha256-bob");
    rec->set_signed_prekey_created_at_epoch_ms(1700000000000LL);
    rec->set_remaining_one_time_prekeys(45);

    EXPECT_CALL(*mock_auth_client_, get_device_crypto_directory(_, _))
        .WillOnce([&dir_resp](const securecloud::auth::v1::GetDeviceCryptoDirectoryRequest& req,
                              securecloud::gateway::grpc::ClientCallContext& /*call_ctx*/) {
            EXPECT_EQ(req.user_id(), "user-bob");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::GetDeviceCryptoDirectoryResponse>(
                dir_resp);
        });

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/users/user-bob/devices/crypto-directory";
    httplib::Response res;

    router_->handle(req, res);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["user_id"], "user-bob");
    ASSERT_EQ(body["devices"].size(), 1);
    EXPECT_EQ(body["devices"][0]["device_id"], "dev-bob-phone");
    EXPECT_EQ(body["devices"][0]["identity_key"], "id-key-data");
    EXPECT_EQ(body["devices"][0]["identity_key_fingerprint"], "fp-sha256-bob");
    EXPECT_EQ(body["devices"][0]["remaining_one_time_prekeys"], 45);
}

TEST_F(GatewayCryptoDirectoryPolicyTest, AuthenticatedGetCryptoIdentitySuccess) {
    auto ctx = make_context("user-alice", "dev-alice",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    RequestContext req_ctx("req-ident-001", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    securecloud::auth::v1::GetCryptoIdentityResponse ident_resp;
    ident_resp.set_device_id("dev-charlie");
    ident_resp.set_user_id("user-charlie");
    ident_resp.set_identity_key("id-charlie-data");
    ident_resp.set_signed_prekey("spk-charlie");
    ident_resp.set_signed_prekey_signature("sig-charlie");
    ident_resp.set_status(securecloud::auth::v1::DeviceStatus::DEVICE_STATUS_ACTIVE);
    ident_resp.set_identity_key_fingerprint("fp-sha256-charlie");
    ident_resp.set_signed_prekey_created_at_epoch_ms(1710000000000LL);

    EXPECT_CALL(*mock_auth_client_, get_crypto_identity(_, _))
        .WillOnce([&ident_resp](const securecloud::auth::v1::GetCryptoIdentityRequest& req,
                                securecloud::gateway::grpc::ClientCallContext& /*call_ctx*/) {
            EXPECT_EQ(req.device_id(), "dev-charlie");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::GetCryptoIdentityResponse>(ident_resp);
        });

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices/dev-charlie/crypto-identity";
    httplib::Response res;

    router_->handle(req, res);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["device_id"], "dev-charlie");
    EXPECT_EQ(body["user_id"], "user-charlie");
    EXPECT_EQ(body["identity_key"], "id-charlie-data");
    EXPECT_EQ(body["signed_prekey"], "spk-charlie");
    EXPECT_EQ(body["identity_key_fingerprint"], "fp-sha256-charlie");
}

TEST_F(GatewayCryptoDirectoryPolicyTest, PrekeyUpdatePerimeterRejectsDeviceMismatchWith403) {
    auto ctx = make_context("user-alice", "dev-deviceA",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    RequestContext req_ctx("req-prekey-mismatch", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/dev-deviceB/prekeys";
    req.body = R"({"signed_prekey":"new-spk","signed_prekey_signature":"new-sig"})";
    httplib::Response res;

    EXPECT_CALL(*mock_auth_client_, update_crypto_prekeys(_, _)).Times(0);

    router_->handle(req, res);

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "DEVICE_MISMATCH");
}

TEST_F(GatewayCryptoDirectoryPolicyTest, PrekeyUpdateMatchingDeviceDispatchesDownstreamSuccess) {
    auto ctx = make_context("user-alice", "dev-deviceA",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    RequestContext req_ctx("req-prekey-ok", "127.0.0.1", 1000, ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    securecloud::auth::v1::UpdateCryptoPrekeysResponse upd_resp;
    upd_resp.set_active_one_time_prekey_count(50);
    upd_resp.set_updated_at_epoch_ms(1720000000000LL);

    EXPECT_CALL(*mock_auth_client_, update_crypto_prekeys(_, _))
        .WillOnce([&upd_resp](const securecloud::auth::v1::UpdateCryptoPrekeysRequest& req,
                              securecloud::gateway::grpc::ClientCallContext& /*call_ctx*/) {
            EXPECT_EQ(req.device_id(), "dev-deviceA");
            EXPECT_EQ(req.signed_prekey(), "new-spk");
            EXPECT_EQ(req.signed_prekey_signature(), "new-sig");
            EXPECT_EQ(req.one_time_prekeys_size(), 2);
            EXPECT_EQ(req.one_time_prekeys(0), "otk-1");
            EXPECT_EQ(req.one_time_prekeys(1), "otk-2");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::UpdateCryptoPrekeysResponse>(upd_resp);
        });

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/dev-deviceA/prekeys";
    req.body =
        nlohmann::json{
            {"signed_prekey", "new-spk"},
            {"signed_prekey_signature", "new-sig"},
            {"one_time_prekeys", {"otk-1", "otk-2"}},
        }
            .dump();
    httplib::Response res;

    router_->handle(req, res);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["device_id"], "dev-deviceA");
    EXPECT_EQ(body["active_one_time_prekey_count"], 50);
    EXPECT_EQ(body["updated_at_epoch_ms"], 1720000000000LL);
}

} // namespace
} // namespace securecloud::gateway::http::test
