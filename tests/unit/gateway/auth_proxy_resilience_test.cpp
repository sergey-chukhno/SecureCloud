#include "grpc/auth_client_interface.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/errors/error_mapper.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/deadline_manager.hpp"
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

AuthenticatedContext make_context(std::string user_id = "user-alice-123", std::string device_id = "dev-001",
                                  securecloud::auth::v1::AuthenticationLevel level =
                                      securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY) {
    return AuthenticatedContext(std::move(user_id), std::move(device_id), "sess-123", level, {"access"},
                                2000000000000LL);
}

class AuthProxyResilienceTest : public ::testing::Test {
  protected:
    void SetUp() override { mock_client_ = std::make_shared<MockAuthClient>(); }

    std::shared_ptr<MockAuthClient> mock_client_;
};

// ============================================================================
// 1. Bulkhead Saturation & Rejection Tests
// ============================================================================

TEST_F(AuthProxyResilienceTest, BulkheadSaturationRejectionAcrossEndpoints) {
    // Configure Bulkhead with capacity 1 for Auth workload
    GatewayBulkheadConfig bulkhead_cfg;
    bulkhead_cfg.auth_max_concurrent = 1;
    auto bulkhead_manager = std::make_shared<BulkheadManager>(bulkhead_cfg);

    AuthProxyHandler handler(mock_client_, nullptr, nullptr, bulkhead_manager, nullptr);

    // Consume the only available lease
    auto lease = bulkhead_manager->acquire(WorkloadCategory::Auth);
    ASSERT_TRUE(lease);

    // Any request to Auth endpoints should now be rejected immediately with 503
    auto ctx = make_context("user-1");

    // 1. Login endpoint
    {
        httplib::Request req;
        req.body = nlohmann::json{{"identifier", "u"}, {"credential", "p"}}.dump();
        httplib::Response res;
        handler.handle_login(req, res);
        EXPECT_EQ(res.status, 503);
        auto body = nlohmann::json::parse(res.body);
        EXPECT_EQ(body["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");
    }

    // 2. MFA enroll endpoint
    {
        httplib::Request req;
        httplib::Response res;
        handler.handle_initiate_mfa_enrollment(req, res, ctx);
        EXPECT_EQ(res.status, 503);
        auto body = nlohmann::json::parse(res.body);
        EXPECT_EQ(body["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");
    }

    // 3. Device list endpoint
    {
        httplib::Request req;
        httplib::Response res;
        handler.handle_list_devices(req, res, ctx);
        EXPECT_EQ(res.status, 503);
        auto body = nlohmann::json::parse(res.body);
        EXPECT_EQ(body["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");
    }
}

// ============================================================================
// 2. Circuit Breaker Fast-Fail and State Progression Tests
// ============================================================================

TEST_F(AuthProxyResilienceTest, CircuitBreakerFastFailWhenOpen) {
    GatewayCircuitBreakerConfig cb_cfg;
    cb_cfg.failure_threshold = 2;
    cb_cfg.recovery_timeout_ms = 60000;
    auto circuit_breaker = std::make_shared<CircuitBreaker>("auth", cb_cfg);

    // Trip circuit breaker manually
    circuit_breaker->record_failure();
    circuit_breaker->record_failure();
    ASSERT_EQ(circuit_breaker->state(), CircuitState::Open);

    AuthProxyHandler handler(mock_client_, nullptr, nullptr, nullptr, circuit_breaker);

    // Verify mock_client is NEVER called when circuit is open
    EXPECT_CALL(*mock_client_, authenticate(_, _)).Times(0);
    EXPECT_CALL(*mock_client_, list_user_devices(_, _)).Times(0);

    // 1. Login test
    {
        httplib::Request req;
        req.body = nlohmann::json{{"identifier", "u"}, {"credential", "p"}}.dump();
        httplib::Response res;
        handler.handle_login(req, res);

        EXPECT_EQ(res.status, 503);
        EXPECT_TRUE(res.has_header("Retry-After"));
        auto body = nlohmann::json::parse(res.body);
        EXPECT_EQ(body["error"]["code"], "CIRCUIT_BREAKER_OPEN");
    }

    // 2. Device list test
    {
        httplib::Request req;
        httplib::Response res;
        auto ctx = make_context("user-1");
        handler.handle_list_devices(req, res, ctx);

        EXPECT_EQ(res.status, 503);
        auto body = nlohmann::json::parse(res.body);
        EXPECT_EQ(body["error"]["code"], "CIRCUIT_BREAKER_OPEN");
    }
}

TEST_F(AuthProxyResilienceTest, CircuitBreakerRecordsFailuresAndTrips) {
    GatewayCircuitBreakerConfig cb_cfg;
    cb_cfg.failure_threshold = 2;
    cb_cfg.recovery_timeout_ms = 30000;
    auto circuit_breaker = std::make_shared<CircuitBreaker>("auth", cb_cfg);

    AuthProxyHandler handler(mock_client_, nullptr, nullptr, nullptr, circuit_breaker);

    EXPECT_CALL(*mock_client_, authenticate(_, _))
        .Times(2)
        .WillRepeatedly(Return(securecloud::gateway::grpc::DependencyError{
            .kind = securecloud::gateway::grpc::DependencyErrorKind::ServiceUnavailable,
            .message = "Downstream down",
            .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
        }));

    httplib::Request req;
    req.body = nlohmann::json{{"identifier", "user"}, {"credential", "pass"}}.dump();

    // Call 1 -> fails downstream, circuit remains closed
    httplib::Response res1;
    handler.handle_login(req, res1);
    EXPECT_EQ(res1.status, 503);
    EXPECT_EQ(circuit_breaker->state(), CircuitState::Closed);

    // Call 2 -> fails downstream, trips circuit to Open!
    httplib::Response res2;
    handler.handle_login(req, res2);
    EXPECT_EQ(res2.status, 503);
    EXPECT_EQ(circuit_breaker->state(), CircuitState::Open);

    // Call 3 -> fast-fails at Gateway perimeter without downstream call!
    httplib::Response res3;
    handler.handle_login(req, res3);
    EXPECT_EQ(res3.status, 503);
    auto body = nlohmann::json::parse(res3.body);
    EXPECT_EQ(body["error"]["code"], "CIRCUIT_BREAKER_OPEN");
}

// ============================================================================
// 3. Deadline Budget Fast-Fail Tests
// ============================================================================

TEST_F(AuthProxyResilienceTest, ExpiredDeadlineFastFailsWithGatewayTimeout) {
    GatewayServiceDeadlinesConfig deadline_cfg;
    deadline_cfg.min_request_deadline_ms = 50;
    deadline_cfg.max_request_deadline_ms = 10000;
    deadline_cfg.auth_timeout_ms = 5000;

    auto t0 = std::chrono::steady_clock::now();
    int call_count = 0;
    auto clock_fn = [t0, call_count]() mutable -> std::chrono::steady_clock::time_point {
        if (++call_count == 1) {
            return t0;
        }
        // Second call occurs inside has_sufficient_budget; simulate 6000ms elapsed (> 5000ms)
        return t0 + std::chrono::milliseconds(6000);
    };

    auto deadline_manager = std::make_shared<DeadlineManager>(deadline_cfg, clock_fn);
    AuthProxyHandler handler(mock_client_, deadline_manager);

    httplib::Request req;
    req.body = nlohmann::json{{"identifier", "user"}, {"credential", "pass"}}.dump();

    EXPECT_CALL(*mock_client_, authenticate(_, _)).Times(0);

    httplib::Response res;
    handler.handle_login(req, res);

    EXPECT_EQ(res.status, 504);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "GATEWAY_TIMEOUT");
    EXPECT_EQ(body["type"], "https://securecloud.internal/errors/gateway-timeout");
}

// ============================================================================
// 4. RFC 7807 Problem Details Matrix & Harmonization Tests
// ============================================================================

TEST_F(AuthProxyResilienceTest, Rfc7807ProblemDetailsSchemaCompliance) {
    httplib::Response res;
    ErrorMapper::write_error(res, 400, "BAD_REQUEST", "Malformed JSON body", "req-test-123");

    EXPECT_EQ(res.status, 400);
    EXPECT_EQ(res.get_header_value("Content-Type"), "application/json");

    auto body = nlohmann::json::parse(res.body);

    // RFC 7807 standard fields
    EXPECT_EQ(body["type"], "https://securecloud.internal/errors/bad-request");
    EXPECT_EQ(body["title"], "Bad Request");
    EXPECT_EQ(body["status"], 400);
    EXPECT_EQ(body["detail"], "Malformed JSON body");
    EXPECT_EQ(body["request_id"], "req-test-123");

    // Backward-compatible nested error object
    ASSERT_TRUE(body.contains("error"));
    EXPECT_EQ(body["error"]["code"], "BAD_REQUEST");
    EXPECT_EQ(body["error"]["message"], "Malformed JSON body");
    EXPECT_EQ(body["error"]["request_id"], "req-test-123");
}

TEST_F(AuthProxyResilienceTest, GrpcStatusCodeTranslationMatrix) {
    struct TestCase {
        ::grpc::StatusCode grpc_code;
        int expected_http_status;
        std::string expected_error_code;
    };

    const std::vector<TestCase> cases = {
        {::grpc::StatusCode::INVALID_ARGUMENT, 400, "INVALID_ARGUMENT"},
        {::grpc::StatusCode::UNAUTHENTICATED, 401, "UNAUTHENTICATED"},
        {::grpc::StatusCode::PERMISSION_DENIED, 403, "PERMISSION_DENIED"},
        {::grpc::StatusCode::NOT_FOUND, 404, "NOT_FOUND"},
        {::grpc::StatusCode::ALREADY_EXISTS, 409, "ALREADY_EXISTS"},
        {::grpc::StatusCode::FAILED_PRECONDITION, 412, "FAILED_PRECONDITION"},
        {::grpc::StatusCode::RESOURCE_EXHAUSTED, 429, "RESOURCE_EXHAUSTED"},
        {::grpc::StatusCode::INTERNAL, 500, "INTERNAL_ERROR"},
        {::grpc::StatusCode::UNIMPLEMENTED, 501, "NOT_IMPLEMENTED"},
        {::grpc::StatusCode::UNAVAILABLE, 503, "SERVICE_UNAVAILABLE"},
        {::grpc::StatusCode::DEADLINE_EXCEEDED, 504, "GATEWAY_TIMEOUT"},
    };

    for (const auto& tc : cases) {
        EXPECT_EQ(ErrorMapper::grpc_to_http_status(tc.grpc_code), tc.expected_http_status);
        EXPECT_EQ(ErrorMapper::grpc_to_error_code(tc.grpc_code), tc.expected_error_code);

        httplib::Response res;
        ErrorMapper::write_grpc_error(res, tc.grpc_code, "Detailed error explanation", "req-matrix");
        EXPECT_EQ(res.status, tc.expected_http_status);

        auto body = nlohmann::json::parse(res.body);
        EXPECT_EQ(body["status"], tc.expected_http_status);
        EXPECT_EQ(body["error"]["code"].get<std::string>(), tc.expected_error_code);
        EXPECT_EQ(body["detail"], "Detailed error explanation");
        EXPECT_EQ(body["request_id"], "req-matrix");
    }
}

// ============================================================================
// 5. Correlation & Header Propagation Verification
// ============================================================================

TEST_F(AuthProxyResilienceTest, RequestIdCorrelationPropagatedToDownstreamCall) {
    AuthProxyHandler handler(mock_client_);

    std::string captured_request_id;
    EXPECT_CALL(*mock_client_, authenticate(_, _))
        .WillOnce([&captured_request_id](const securecloud::auth::v1::AuthenticateRequest& /*req*/,
                                         securecloud::gateway::grpc::ClientCallContext& ctx) {
            captured_request_id = ctx.request_id();
            securecloud::auth::v1::AuthenticateResponse resp;
            resp.set_session_id("sess-ok");
            resp.set_access_token("token-ok");
            return securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(resp);
        });

    httplib::Request req;
    req.headers.emplace("X-Request-ID", "corr-id-xyz-999");
    req.body = nlohmann::json{{"identifier", "user"}, {"credential", "pass"}}.dump();
    httplib::Response res;

    handler.handle_login(req, res);

    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(captured_request_id, "corr-id-xyz-999");
}

} // namespace
} // namespace securecloud::gateway::http::test
