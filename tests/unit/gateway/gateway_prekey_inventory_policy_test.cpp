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

class MockAuthClientForPrekeys : public securecloud::gateway::grpc::IAuthClient {
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

class GatewayPrekeyInventoryPolicyTest : public ::testing::Test {
  protected:
    void SetUp() override {
        policy_ = std::make_shared<GatewaySecurityPolicy>(GatewaySecurityPolicy::create_default());
        authz_middleware_ = std::make_shared<AuthorizationMiddleware>(policy_);

        router_ = std::make_unique<Router>();
        router_->use(authz_middleware_);

        mock_auth_client_ = std::make_shared<MockAuthClientForPrekeys>();
        auth_proxy_ = std::make_shared<AuthProxyHandler>(mock_auth_client_);
        auth_proxy_->register_routes(*router_);
    }

    std::shared_ptr<GatewaySecurityPolicy> policy_;
    std::shared_ptr<AuthorizationMiddleware> authz_middleware_;
    std::unique_ptr<Router> router_;
    std::shared_ptr<MockAuthClientForPrekeys> mock_auth_client_;
    std::shared_ptr<AuthProxyHandler> auth_proxy_;
};

// ============================================================================
// Security Policy Tests
// ============================================================================

TEST_F(GatewayPrekeyInventoryPolicyTest, PolicyEvaluatesInventoryRouteAsProtectedPrimary) {
    auto rule = policy_->evaluate("GET", "/api/v1/devices/dev-uuid-1/prekeys/inventory");
    EXPECT_EQ(rule.access, RouteAccess::Protected);
    EXPECT_EQ(rule.min_auth_level, securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    EXPECT_FALSE(rule.is_public());
    EXPECT_FALSE(rule.requires_mfa());
}

TEST_F(GatewayPrekeyInventoryPolicyTest, PolicyEvaluatesClaimRouteAsProtectedPrimary) {
    auto rule = policy_->evaluate("POST", "/api/v1/devices/dev-uuid-1/prekeys/claim");
    EXPECT_EQ(rule.access, RouteAccess::Protected);
    EXPECT_EQ(rule.min_auth_level, securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    EXPECT_FALSE(rule.is_public());
    EXPECT_FALSE(rule.requires_mfa());
}

// ============================================================================
// Unauthenticated Rejection Tests
// ============================================================================

TEST_F(GatewayPrekeyInventoryPolicyTest, UnauthenticatedRequest_GetInventory_Returns401) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices/dev-uuid-1/prekeys/inventory";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 401);
}

TEST_F(GatewayPrekeyInventoryPolicyTest, UnauthenticatedRequest_ClaimPrekey_Returns401) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/dev-uuid-1/prekeys/claim";

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 401);
}

// ============================================================================
// Device Mismatch Protection Tests
// ============================================================================

TEST_F(GatewayPrekeyInventoryPolicyTest, CallerDeviceMismatch_GetInventory_Returns403DeviceMismatch) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices/target-dev-uuid/prekeys/inventory";

    auto caller_ctx = make_context("user-uuid-1", "foreign-dev-uuid",
                                   securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    RequestContext req_ctx("req-1", "127.0.0.1", 1000, caller_ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "DEVICE_MISMATCH");
}

// ============================================================================
// Get Prekey Inventory Handler Tests
// ============================================================================

TEST_F(GatewayPrekeyInventoryPolicyTest, GetPrekeyInventory_Success_Returns200WithInventoryJson) {
    std::string dev_id = "018f9e1e-2e3d-7123-8abc-0123456789ab";
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices/" + dev_id + "/prekeys/inventory";

    auto caller_ctx =
        make_context("user-uuid-1", dev_id, securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    RequestContext req_ctx("req-2", "127.0.0.1", 1000, caller_ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    securecloud::auth::v1::GetPrekeyInventoryStatusResponse resp;
    resp.set_device_id(dev_id);
    resp.set_active_one_time_prekeys(35);
    resp.set_claimed_one_time_prekeys(15);
    resp.set_low_inventory_threshold(20);
    resp.set_is_low_inventory(false);
    resp.set_is_exhausted(false);
    resp.set_signed_prekey_created_at_epoch_ms(1710000000000LL);
    resp.set_signed_prekey_age_seconds(86400);
    resp.set_signed_prekey_needs_rotation(false);

    EXPECT_CALL(*mock_auth_client_, get_prekey_inventory_status(_, _))
        .WillOnce(
            Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetPrekeyInventoryStatusResponse>(resp)));

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["device_id"], dev_id);
    EXPECT_EQ(body["active_one_time_prekeys"], 35);
    EXPECT_EQ(body["claimed_one_time_prekeys"], 15);
    EXPECT_EQ(body["low_inventory_threshold"], 20);
    EXPECT_FALSE(body["is_low_inventory"]);
    EXPECT_FALSE(body["is_exhausted"]);
    EXPECT_EQ(body["signed_prekey_age_seconds"], 86400);
    EXPECT_FALSE(body["signed_prekey_needs_rotation"]);
}

TEST_F(GatewayPrekeyInventoryPolicyTest, GetPrekeyInventory_DeviceNotFound_Returns404) {
    std::string dev_id = "018f9e1e-2e3d-7123-8abc-0123456789ab";
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices/" + dev_id + "/prekeys/inventory";

    auto caller_ctx =
        make_context("user-uuid-1", dev_id, securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    RequestContext req_ctx("req-3", "127.0.0.1", 1000, caller_ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    auto dep_err = securecloud::gateway::grpc::DependencyError::from_grpc_status(
        ::grpc::Status(::grpc::StatusCode::NOT_FOUND, "Device not found"));

    EXPECT_CALL(*mock_auth_client_, get_prekey_inventory_status(_, _))
        .WillOnce(Return(
            securecloud::gateway::grpc::Result<securecloud::auth::v1::GetPrekeyInventoryStatusResponse>(dep_err)));

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 404);
}

// ============================================================================
// Claim Prekey Bundle Handler Tests
// ============================================================================

TEST_F(GatewayPrekeyInventoryPolicyTest, ClaimPrekey_SuccessHealthy_Returns200WithBundleAndHealthyState) {
    std::string dev_id = "018f9e1e-2e3d-7123-8abc-0123456789ab";
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/" + dev_id + "/prekeys/claim";

    // Caller can be any authenticated user
    auto caller_ctx = make_context("alice-user-uuid", "alice-dev-uuid",
                                   securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    RequestContext req_ctx("req-4", "127.0.0.1", 1000, caller_ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;
    auto* b = resp.mutable_bundle();
    b->set_device_id(dev_id);
    b->set_identity_key("id-key-bytes");
    b->set_identity_key_fingerprint("id-fp");
    b->set_signed_prekey("spk-bytes");
    b->set_signed_prekey_signature("spk-sig");
    b->set_signed_prekey_created_at_epoch_ms(1710000000000LL);
    b->set_one_time_prekey("otk-bytes");
    b->set_one_time_prekey_id("otk-id-123");
    b->set_status(securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    resp.set_exhaustion_state(securecloud::auth::v1::PREKEY_EXHAUSTION_STATE_HEALTHY);

    EXPECT_CALL(*mock_auth_client_, claim_prekey_bundle(_, _))
        .WillOnce(Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::ClaimPrekeyBundleResponse>(resp)));

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["exhaustion_state"], "HEALTHY");
    EXPECT_EQ(body["bundle"]["device_id"], dev_id);
    EXPECT_EQ(body["bundle"]["identity_key_fingerprint"], "id-fp");
    EXPECT_EQ(body["bundle"]["one_time_prekey"], "otk-bytes");
    EXPECT_EQ(body["bundle"]["one_time_prekey_id"], "otk-id-123");
}

TEST_F(GatewayPrekeyInventoryPolicyTest, ClaimPrekey_SuccessExhausted_Returns200WithBundleAndExhaustedState) {
    std::string dev_id = "018f9e1e-2e3d-7123-8abc-0123456789ab";
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/" + dev_id + "/prekeys/claim";

    auto caller_ctx = make_context("alice-user-uuid", "alice-dev-uuid",
                                   securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    RequestContext req_ctx("req-5", "127.0.0.1", 1000, caller_ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;
    auto* b = resp.mutable_bundle();
    b->set_device_id(dev_id);
    b->set_identity_key("id-key-bytes");
    b->set_identity_key_fingerprint("id-fp");
    b->set_signed_prekey("spk-bytes");
    b->set_signed_prekey_signature("spk-sig");
    b->set_signed_prekey_created_at_epoch_ms(1710000000000LL);
    b->set_status(securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    resp.set_exhaustion_state(securecloud::auth::v1::PREKEY_EXHAUSTION_STATE_EXHAUSTED);

    EXPECT_CALL(*mock_auth_client_, claim_prekey_bundle(_, _))
        .WillOnce(Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::ClaimPrekeyBundleResponse>(resp)));

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["exhaustion_state"], "EXHAUSTED");
    EXPECT_FALSE(body["bundle"].contains("one_time_prekey"));
}

TEST_F(GatewayPrekeyInventoryPolicyTest, ClaimPrekey_DeviceRevoked_Returns403Forbidden) {
    std::string dev_id = "018f9e1e-2e3d-7123-8abc-0123456789ab";
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/devices/" + dev_id + "/prekeys/claim";

    auto caller_ctx = make_context("alice-user-uuid", "alice-dev-uuid",
                                   securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    RequestContext req_ctx("req-6", "127.0.0.1", 1000, caller_ctx);
    ScopedRequestContext scoped_ctx(req_ctx);

    auto dep_err = securecloud::gateway::grpc::DependencyError::from_grpc_status(
        ::grpc::Status(::grpc::StatusCode::PERMISSION_DENIED, "Device is revoked"));

    EXPECT_CALL(*mock_auth_client_, claim_prekey_bundle(_, _))
        .WillOnce(
            Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::ClaimPrekeyBundleResponse>(dep_err)));

    httplib::Response res;
    router_->handle(req, res);

    EXPECT_EQ(res.status, 403);
}

} // namespace
} // namespace securecloud::gateway::http::test
