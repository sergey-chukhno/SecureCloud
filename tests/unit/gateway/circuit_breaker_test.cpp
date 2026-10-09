#include "gateway_config.hpp"
#include "grpc/auth_client_interface.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/retry_policy.hpp"

#include <atomic>
#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

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

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::UpdateCryptoPrekeysResponse>,
                update_crypto_prekeys,
                (const securecloud::auth::v1::UpdateCryptoPrekeysRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));
};

GatewayCircuitBreakerConfig make_test_cb_config(uint32_t failure_threshold = 5, uint32_t recovery_timeout_ms = 1000,
                                                uint32_t half_open_probe_count = 1) {
    GatewayCircuitBreakerConfig cfg;
    cfg.enabled = true;
    cfg.failure_threshold = failure_threshold;
    cfg.recovery_timeout_ms = recovery_timeout_ms;
    cfg.half_open_probe_count = half_open_probe_count;
    return cfg;
}

// ============================================================================
// CircuitBreaker Core FSM Tests (GW-009-T03)
// ============================================================================

TEST(CircuitBreakerTest, InitialStateIsClosed) {
    auto cfg = make_test_cb_config(5, 1000);
    CircuitBreaker cb("auth", cfg);

    EXPECT_EQ(cb.service_name(), "auth");
    EXPECT_EQ(cb.state(), CircuitState::Closed);
    EXPECT_EQ(cb.consecutive_failures(), 0u);
    EXPECT_TRUE(cb.allow_request());
    EXPECT_EQ(to_string(CircuitState::Closed), "CLOSED");
    EXPECT_EQ(to_string(CircuitState::Open), "OPEN");
    EXPECT_EQ(to_string(CircuitState::HalfOpen), "HALF_OPEN");
}

TEST(CircuitBreakerTest, NonTransientFailuresDoNotTripBreaker) {
    auto cfg = make_test_cb_config(3, 1000);
    CircuitBreaker cb("auth", cfg);

    cb.record_status(::grpc::StatusCode::INVALID_ARGUMENT);
    cb.record_status(::grpc::StatusCode::NOT_FOUND);
    cb.record_status(::grpc::StatusCode::UNAUTHENTICATED);
    cb.record_status(::grpc::StatusCode::PERMISSION_DENIED);
    cb.record_status(::grpc::StatusCode::ALREADY_EXISTS);

    EXPECT_EQ(cb.consecutive_failures(), 0u);
    EXPECT_EQ(cb.state(), CircuitState::Closed);
    EXPECT_TRUE(cb.allow_request());
}

TEST(CircuitBreakerTest, TransientFailuresTripBreakerAtThreshold) {
    auto cfg = make_test_cb_config(3, 1000);
    CircuitBreaker cb("auth", cfg);

    cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(cb.consecutive_failures(), 1u);
    EXPECT_EQ(cb.state(), CircuitState::Closed);
    EXPECT_TRUE(cb.allow_request());

    cb.record_status(::grpc::StatusCode::DEADLINE_EXCEEDED);
    EXPECT_EQ(cb.consecutive_failures(), 2u);
    EXPECT_EQ(cb.state(), CircuitState::Closed);
    EXPECT_TRUE(cb.allow_request());

    // 3rd failure reaches threshold -> trips to OPEN
    cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(cb.consecutive_failures(), 3u);
    EXPECT_EQ(cb.state(), CircuitState::Open);
    EXPECT_FALSE(cb.allow_request());
}

TEST(CircuitBreakerTest, IntermittentSuccessResetsFailureCounter) {
    auto cfg = make_test_cb_config(3, 1000);
    CircuitBreaker cb("auth", cfg);

    cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(cb.consecutive_failures(), 2u);

    // Intermittent success resets consecutive counter
    cb.record_status(::grpc::StatusCode::OK);
    EXPECT_EQ(cb.consecutive_failures(), 0u);
    EXPECT_EQ(cb.state(), CircuitState::Closed);

    // Need 3 fresh failures to trip
    cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(cb.state(), CircuitState::Closed);
    EXPECT_TRUE(cb.allow_request());

    cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(cb.state(), CircuitState::Open);
    EXPECT_FALSE(cb.allow_request());
}

TEST(CircuitBreakerTest, SimulatedClockTransitionsToHalfOpenAndRecoversOnSuccess) {
    auto fake_now = std::chrono::steady_clock::time_point{std::chrono::seconds(100)};
    auto clock_fn = [&fake_now]() { return fake_now; };

    auto cfg = make_test_cb_config(2, 5000, 1);
    CircuitBreaker cb("auth", cfg, clock_fn);

    // Trip the breaker
    cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(cb.state(), CircuitState::Open);
    EXPECT_FALSE(cb.allow_request());

    // Advance clock by 4 seconds (under recovery timeout of 5s)
    fake_now += std::chrono::seconds(4);
    EXPECT_EQ(cb.state(), CircuitState::Open);
    EXPECT_FALSE(cb.allow_request());
    EXPECT_GT(cb.remaining_recovery_time_sec(), 0u);

    // Advance clock past 5 seconds -> transitions to HALF_OPEN
    fake_now += std::chrono::seconds(2); // total 6s elapsed
    EXPECT_EQ(cb.state(), CircuitState::HalfOpen);
    EXPECT_EQ(cb.remaining_recovery_time_sec(), 0u);

    // First request is permitted as a probe
    EXPECT_TRUE(cb.allow_request());

    // Subsequent simultaneous requests in HALF_OPEN are rejected (probe budget = 1)
    EXPECT_FALSE(cb.allow_request());

    // Probe succeeds -> breaker resets to CLOSED
    cb.record_success();
    EXPECT_EQ(cb.state(), CircuitState::Closed);
    EXPECT_EQ(cb.consecutive_failures(), 0u);
    EXPECT_TRUE(cb.allow_request());
}

TEST(CircuitBreakerTest, HalfOpenProbeFailureImmediatelyRevertsToOpen) {
    auto fake_now = std::chrono::steady_clock::time_point{std::chrono::seconds(100)};
    auto clock_fn = [&fake_now]() { return fake_now; };

    auto cfg = make_test_cb_config(2, 5000, 1);
    CircuitBreaker cb("auth", cfg, clock_fn);

    // Trip the breaker
    cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(cb.state(), CircuitState::Open);

    // Advance clock past recovery timeout
    fake_now += std::chrono::seconds(6);
    EXPECT_TRUE(cb.allow_request()); // Probe allowed

    // Probe fails with transient error -> reverts to OPEN for another 5s
    cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(cb.state(), CircuitState::Open);
    EXPECT_FALSE(cb.allow_request());

    // 2 seconds later still OPEN
    fake_now += std::chrono::seconds(2);
    EXPECT_EQ(cb.state(), CircuitState::Open);
    EXPECT_FALSE(cb.allow_request());

    // 6 seconds later transitions to HALF_OPEN again
    fake_now += std::chrono::seconds(4);
    EXPECT_EQ(cb.state(), CircuitState::HalfOpen);
    EXPECT_TRUE(cb.allow_request());
}

TEST(CircuitBreakerTest, DisabledBreakerAlwaysAllowsRequests) {
    GatewayCircuitBreakerConfig cfg;
    cfg.enabled = false;
    cfg.failure_threshold = 2;
    cfg.recovery_timeout_ms = 1000;

    CircuitBreaker cb("auth", cfg);
    for (int i = 0; i < 10; ++i) {
        cb.record_status(::grpc::StatusCode::UNAVAILABLE);
    }

    EXPECT_EQ(cb.state(), CircuitState::Closed);
    EXPECT_TRUE(cb.allow_request());
}

TEST(CircuitBreakerTest, WriteRejectionFormatRFC7807) {
    httplib::Response res;
    CircuitBreaker::write_rejection(res, "req-cb-test-corr", 10);

    EXPECT_EQ(res.status, 503);
    EXPECT_EQ(res.get_header_value("Retry-After"), "10");
    EXPECT_EQ(res.get_header_value("Content-Type"), "application/problem+json");

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["type"], "https://securecloud.internal/errors/circuit-breaker-open");
    EXPECT_EQ(json["title"], "Service Unavailable");
    EXPECT_EQ(json["status"], 503);
    EXPECT_EQ(json["error"]["code"], "CIRCUIT_BREAKER_OPEN");
    EXPECT_EQ(json["request_id"], "req-cb-test-corr");
}

TEST(CircuitBreakerTest, ConcurrentAccessThreadSafety) {
    auto cfg = make_test_cb_config(5, 50);
    CircuitBreaker cb("auth", cfg);

    std::atomic<bool> start{false};
    std::vector<std::thread> threads;
    threads.reserve(10);

    for (int t = 0; t < 10; ++t) {
        threads.emplace_back([&cb, &start, t]() {
            while (!start.load(std::memory_order_relaxed)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < 50; ++i) {
                if (cb.allow_request()) {
                    if ((t + i) % 3 == 0) {
                        cb.record_status(::grpc::StatusCode::UNAVAILABLE);
                    } else {
                        cb.record_status(::grpc::StatusCode::OK);
                    }
                }
            }
        });
    }

    start.store(true, std::memory_order_release);
    for (auto& t : threads) {
        t.join();
    }

    // Should maintain consistent state without data races or crash
    SUCCEED();
}

// ============================================================================
// CircuitBreakerRegistry Tests
// ============================================================================

TEST(CircuitBreakerRegistryTest, PrePopulatesServicesAndSupportsCustomCreation) {
    auto cfg = make_test_cb_config(5, 1000);
    CircuitBreakerRegistry registry(cfg);

    auto auth_cb = registry.get("auth");
    ASSERT_NE(auth_cb, nullptr);
    EXPECT_EQ(auth_cb->service_name(), "auth");

    auto msg_cb = registry.get("messaging");
    ASSERT_NE(msg_cb, nullptr);
    EXPECT_EQ(msg_cb->service_name(), "messaging");

    auto files_cb = registry.get("files");
    ASSERT_NE(files_cb, nullptr);
    EXPECT_EQ(files_cb->service_name(), "files");

    EXPECT_NE(auth_cb, msg_cb);
    EXPECT_NE(msg_cb, files_cb);

    EXPECT_EQ(registry.get("nonexistent"), nullptr);

    auto custom_cb = registry.get_or_create("custom_svc");
    ASSERT_NE(custom_cb, nullptr);
    EXPECT_EQ(custom_cb->service_name(), "custom_svc");
    EXPECT_EQ(registry.get("custom_svc"), custom_cb);

    // Trip auth_cb
    for (int i = 0; i < 5; ++i) {
        auth_cb->record_status(::grpc::StatusCode::UNAVAILABLE);
    }
    EXPECT_EQ(auth_cb->state(), CircuitState::Open);

    registry.reset_all();
    EXPECT_EQ(auth_cb->state(), CircuitState::Closed);
}

// ============================================================================
// AuthProxyHandler Circuit Breaker Integration Tests
// ============================================================================

TEST(AuthProxyHandlerCircuitBreakerTest, ClosedBreakerPermitsNormalRpcExecution) {
    auto mock_auth = std::make_shared<MockAuthClient>();
    auto deadline_mgr = std::make_shared<DeadlineManager>();
    auto retry_policy = std::make_shared<RetryPolicy>();
    auto bulkhead_mgr = std::make_shared<BulkheadManager>();
    auto cb = std::make_shared<CircuitBreaker>("auth", make_test_cb_config(3, 1000));

    AuthProxyHandler handler(mock_auth, deadline_mgr, retry_policy, bulkhead_mgr, cb);

    securecloud::auth::v1::AuthenticateResponse auth_proto;
    auth_proto.set_session_id("sess-ok");
    auth_proto.set_access_token("jwt-ok");
    auth_proto.set_refresh_token("rt-ok");
    auth_proto.set_user_id("user-ok");

    EXPECT_CALL(*mock_auth, authenticate(_, _))
        .WillOnce(Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(auth_proto)));

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/login";
    req.body = R"({"identifier": "alice@example.com", "credential": "secretpassword"})";

    httplib::Response res;
    handler.handle_login(req, res);

    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(cb->state(), CircuitState::Closed);
    EXPECT_EQ(cb->consecutive_failures(), 0u);
}

TEST(AuthProxyHandlerCircuitBreakerTest, OpenBreakerFailsFastAtPerimeterWithZeroDownstreamCalls) {
    auto mock_auth = std::make_shared<MockAuthClient>();
    auto deadline_mgr = std::make_shared<DeadlineManager>();
    auto retry_policy = std::make_shared<RetryPolicy>();
    auto bulkhead_mgr = std::make_shared<BulkheadManager>();
    auto cb = std::make_shared<CircuitBreaker>("auth", make_test_cb_config(2, 5000));

    // Manually trip breaker to OPEN
    cb->record_status(::grpc::StatusCode::UNAVAILABLE);
    cb->record_status(::grpc::StatusCode::UNAVAILABLE);
    ASSERT_EQ(cb->state(), CircuitState::Open);

    AuthProxyHandler handler(mock_auth, deadline_mgr, retry_policy, bulkhead_mgr, cb);

    // Crucial check: mock_auth must NOT be called at all!
    EXPECT_CALL(*mock_auth, authenticate(_, _)).Times(0);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/login";
    req.set_header("X-Request-ID", "corr-cb-fast-fail");
    req.body = R"({"identifier": "alice@example.com", "credential": "secretpassword"})";

    httplib::Response res;
    handler.handle_login(req, res);

    EXPECT_EQ(res.status, 503);
    EXPECT_EQ(res.get_header_value("Retry-After"), "5");
    EXPECT_EQ(res.get_header_value("Content-Type"), "application/problem+json");

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["type"], "https://securecloud.internal/errors/circuit-breaker-open");
    EXPECT_EQ(json["error"]["code"], "CIRCUIT_BREAKER_OPEN");
    EXPECT_EQ(json["request_id"], "corr-cb-fast-fail");
}

TEST(AuthProxyHandlerCircuitBreakerTest, ConsecutiveDownstreamFailuresTripBreaker) {
    auto mock_auth = std::make_shared<MockAuthClient>();
    auto deadline_mgr = std::make_shared<DeadlineManager>();
    // Non-retrying policy for fast test execution
    RetryPolicyConfig retry_cfg;
    retry_cfg.max_attempts = 1;
    auto retry_policy = std::make_shared<RetryPolicy>(retry_cfg);
    auto bulkhead_mgr = std::make_shared<BulkheadManager>();
    auto cb = std::make_shared<CircuitBreaker>("auth", make_test_cb_config(2, 5000));

    AuthProxyHandler handler(mock_auth, deadline_mgr, retry_policy, bulkhead_mgr, cb);

    securecloud::gateway::grpc::DependencyError dep_err{
        .kind = securecloud::gateway::grpc::DependencyErrorKind::ServiceUnavailable,
        .message = "Auth microservice unavailable",
        .grpc_code = ::grpc::StatusCode::UNAVAILABLE};

    EXPECT_CALL(*mock_auth, authenticate(_, _))
        .Times(2)
        .WillRepeatedly(
            Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(dep_err)));

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/auth/login";
    req.body = R"({"identifier": "alice@example.com", "credential": "secretpassword"})";

    // Call 1
    httplib::Response res1;
    handler.handle_login(req, res1);
    EXPECT_EQ(res1.status, 503);
    EXPECT_EQ(cb->state(), CircuitState::Closed);
    EXPECT_EQ(cb->consecutive_failures(), 1u);

    // Call 2: Trips breaker
    httplib::Response res2;
    handler.handle_login(req, res2);
    EXPECT_EQ(res2.status, 503);
    EXPECT_EQ(cb->state(), CircuitState::Open);
    EXPECT_EQ(cb->consecutive_failures(), 2u);

    // Call 3: Now fails fast, 0 calls to mock_auth
    httplib::Response res3;
    handler.handle_login(req, res3);
    EXPECT_EQ(res3.status, 503);
    auto json3 = nlohmann::json::parse(res3.body);
    EXPECT_EQ(json3["error"]["code"], "CIRCUIT_BREAKER_OPEN");
}

} // namespace
} // namespace securecloud::gateway::http
