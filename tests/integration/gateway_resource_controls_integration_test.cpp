#include "gateway_config.hpp"
#include "grpc/auth_service_client.hpp"
#include "grpc/channel_manager.hpp"
#include "http/auth/auth_service_token_validator.hpp"
#include "http/auth/authentication_middleware.hpp"
#include "http/auth/authorization_middleware.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/middleware/drain_middleware.hpp"
#include "http/middleware/logging_middleware.hpp"
#include "http/middleware/rate_limiter_middleware.hpp"
#include "http/middleware/request_id_middleware.hpp"
#include "http/middleware/resource_limiter_middleware.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/drain_manager.hpp"
#include "http/resilience/retry_policy.hpp"
#include "http/routing/gateway_route_registrar.hpp"
#include "http/routing/router.hpp"
#include "http/server/https_server.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"
#include "securecloud/auth/v1/auth.pb.h"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <future>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
static void ensure_integration_winsock() {
    static struct WinsockInit {
        WinsockInit() {
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);
        }
        ~WinsockInit() { WSACleanup(); }
    } s_init;
}
#else
static void ensure_integration_winsock() {}
#endif

namespace securecloud::gateway {
namespace {

constexpr auto k_default_client_timeout = std::chrono::milliseconds(5000);
constexpr auto k_shutdown_timeout = std::chrono::milliseconds(3000);
const std::string k_loopback_address = "127.0.0.1";

class ControllableResourceMockAuthService final : public securecloud::auth::v1::AuthService::Service {
  public:
    std::atomic<uint32_t> authenticate_invocations{0};
    std::atomic<uint32_t> authenticate_unavailable_count{0};
    std::atomic<uint32_t> authenticate_delay_ms{0};

    std::atomic<uint32_t> validate_invocations{0};

    void reset_state() {
        authenticate_invocations.store(0);
        authenticate_unavailable_count.store(0);
        authenticate_delay_ms.store(0);
        validate_invocations.store(0);
    }

    ::grpc::Status Authenticate(::grpc::ServerContext* /*context*/,
                                const securecloud::auth::v1::AuthenticateRequest* request,
                                securecloud::auth::v1::AuthenticateResponse* response) override {
        authenticate_invocations.fetch_add(1, std::memory_order_relaxed);

        uint32_t delay = authenticate_delay_ms.load(std::memory_order_relaxed);
        if (delay > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }

        uint32_t unavail = authenticate_unavailable_count.load(std::memory_order_relaxed);
        if (unavail > 0) {
            authenticate_unavailable_count.fetch_sub(1, std::memory_order_relaxed);
            return ::grpc::Status(::grpc::StatusCode::UNAVAILABLE, "Auth microservice temporarily unavailable");
        }

        if (request->credential_identifier() == "bad@securecloud.org") {
            return ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED, "Invalid credentials");
        }

        response->set_session_id("sess-test-resource-123");
        response->set_access_token("valid-resource-token");
        response->set_refresh_token("refresh-resource-token");
        response->set_expires_at_epoch_ms(2000000000000LL);
        response->set_user_id("user-resource-1");
        response->set_authentication_level(
            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
        return ::grpc::Status::OK;
    }

    ::grpc::Status ValidateSession(::grpc::ServerContext* /*context*/,
                                   const securecloud::auth::v1::ValidateSessionRequest* request,
                                   securecloud::auth::v1::ValidateSessionResponse* response) override {
        validate_invocations.fetch_add(1, std::memory_order_relaxed);

        if (request->session_id() == "revoked-session" || request->access_token() == "revoked-token") {
            response->set_is_valid(false);
            return ::grpc::Status::OK;
        }

        response->set_is_valid(true);
        response->set_user_id("user-resource-1");
        response->set_device_id("dev-resource-1");
        response->set_authentication_level(
            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
        response->set_expires_at_epoch_ms(2000000000000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status RevokeSession(::grpc::ServerContext* /*context*/,
                                 const securecloud::auth::v1::RevokeSessionRequest* /*request*/,
                                 securecloud::auth::v1::RevokeSessionResponse* response) override {
        response->set_revoked(true);
        return ::grpc::Status::OK;
    }

    ::grpc::Status RegisterDevice(::grpc::ServerContext* /*context*/,
                                  const securecloud::auth::v1::RegisterDeviceRequest* /*request*/,
                                  securecloud::auth::v1::RegisterDeviceResponse* response) override {
        response->set_device_id("dev-resource-1");
        response->set_status(securecloud::auth::v1::DeviceStatus::DEVICE_STATUS_ACTIVE);
        response->set_registered_at_epoch_ms(1720000000000LL);
        return ::grpc::Status::OK;
    }
};

class GatewayResourceControlsIntegrationTest : public ::testing::Test {
  protected:
    static std::filesystem::path find_pki_dir() {
#ifdef SECURECLOUD_DEV_PKI_DIR
        std::filesystem::path defined_path(SECURECLOUD_DEV_PKI_DIR);
        if (std::filesystem::exists(defined_path / "ca" / "ca.crt")) {
            return defined_path;
        }
#endif
        auto curr = std::filesystem::current_path();
        while (!curr.empty() && curr != curr.root_path()) {
            if (std::filesystem::exists(curr / "deploy" / "dev-pki" / "ca" / "ca.crt")) {
                return curr / "deploy" / "dev-pki";
            }
            curr = curr.parent_path();
        }
        return "deploy/dev-pki";
    }

    void SetUp() override {
        ensure_integration_winsock();
        mock_auth_service_.reset_state();

        pki_root_ = find_pki_dir();
        ca_path_ = pki_root_ / "ca" / "ca.crt";
        auth_cert_path_ = pki_root_ / "services" / "auth" / "auth.crt";
        auth_key_path_ = pki_root_ / "services" / "auth" / "auth.key";
        gateway_cert_path_ = pki_root_ / "services" / "gateway" / "gateway.crt";
        gateway_key_path_ = pki_root_ / "services" / "gateway" / "gateway.key";

        const std::vector<std::filesystem::path> required_paths = {
            ca_path_, auth_cert_path_, auth_key_path_, gateway_cert_path_, gateway_key_path_,
        };
        for (const auto& path : required_paths) {
            ASSERT_TRUE(std::filesystem::exists(path)) << "Required dev PKI credential missing: " << path;
        }

        start_auth_server();
        setup_gateway();
    }

    void TearDown() override {
        stop_gateway();
        stop_auth_server();
    }

    void start_auth_server() {
        common::security::SecurityCredentialsConfig auth_creds{
            .ca_cert_path = ca_path_,
            .service_cert_path = auth_cert_path_,
            .service_key_path = auth_key_path_,
        };
        auto server_creds = common::security::MtlsCredentialLoader::create_server_credentials(auth_creds);
        ASSERT_NE(server_creds, nullptr);

        ::grpc::ServerBuilder builder;
        int port = 0;
        builder.AddListeningPort("127.0.0.1:0", server_creds, &port);
        builder.RegisterService(&mock_auth_service_);

        auth_server_ = builder.BuildAndStart();
        ASSERT_NE(auth_server_, nullptr);
        ASSERT_GT(port, 0);

        auth_port_ = port;
        auth_endpoint_ = "127.0.0.1:" + std::to_string(port);
    }

    void stop_auth_server() {
        if (auth_server_) {
            auth_server_->Shutdown(std::chrono::system_clock::now() + k_shutdown_timeout);
            auth_server_->Wait();
            auth_server_.reset();
        }
    }

    void setup_gateway() {
        common::security::SecurityCredentialsConfig gateway_mTLS_creds{
            .ca_cert_path = ca_path_,
            .service_cert_path = gateway_cert_path_,
            .service_key_path = gateway_key_path_,
        };

        channel_manager_ = std::make_unique<grpc::GrpcChannelManager>(
            gateway_mTLS_creds, auth_endpoint_, "127.0.0.1:50053", "127.0.0.1:50054", "127.0.0.1:50055");
        auto auth_channel = channel_manager_->get_auth_channel();
        ASSERT_NE(auth_channel, nullptr);
        auth_client_ = std::make_shared<grpc::AuthServiceClient>(auth_channel);

        http::TokenValidatorOptions validator_opts{
            .rpc_timeout = std::chrono::milliseconds(2000),
            .cache_ttl = std::chrono::seconds(2),
            .max_cache_entries = 100,
        };
        token_validator_ = std::make_shared<http::AuthServiceTokenValidator>(auth_client_, validator_opts);
        security_policy_ = std::make_shared<http::GatewaySecurityPolicy>(http::GatewaySecurityPolicy::create_default());

        config_.http_listen_address = k_loopback_address;
        config_.http_listen_port = 0;
        config_.server_threads = 4;
        config_.request_timeout_ms = std::chrono::milliseconds(5000);

        // Bulkhead limits
        config_.bulkhead.files_max_concurrent = 2;
        config_.bulkhead.auth_max_concurrent = 5;
        config_.bulkhead.messaging_max_concurrent = 5;
        config_.bulkhead.emergency_reserved_slots = 1;

        // Rate limiter config
        config_.rate_limiting.enabled = true;
        config_.rate_limiting.burst_capacity = 3;
        config_.rate_limiting.refill_rate_per_sec = 1.0;
        config_.rate_limiting.max_tracked_clients = 100;
        config_.rate_limiting.client_ttl = std::chrono::seconds(60);

        // Circuit breaker config
        config_.circuit_breaker.failure_threshold = 5;
        config_.circuit_breaker.recovery_timeout_ms = 300;
        config_.circuit_breaker.half_open_probe_count = 1;

        config_.deadlines.auth_timeout_ms = 1000;
        config_.deadlines.min_request_deadline_ms = 50;
        config_.deadlines.max_request_deadline_ms = 10000;

        config_.tls.enabled = true;
        config_.tls.cert_path = gateway_cert_path_.string();
        config_.tls.key_path = gateway_key_path_.string();
        config_.tls.ca_chain_path = ca_path_.string();
        config_.tls.https_listen_port = 0;
        config_.tls.min_tls_version = "TLSv1.3";
        config_.tls.cipher_suites = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

        health_manager_ = std::make_shared<common::health::HealthStatusManager>("gateway-controls-test");
        health_manager_->set_live(true);
        health_manager_->set_ready(true);

        drain_manager_ = std::make_shared<http::DrainManager>(health_manager_);
        bulkhead_manager_ = std::make_shared<http::BulkheadManager>(config_.bulkhead);
        circuit_breaker_registry_ = std::make_shared<http::CircuitBreakerRegistry>(config_.circuit_breaker);
        auth_circuit_breaker_ = circuit_breaker_registry_->get("auth");
        deadline_manager_ = std::make_shared<http::DeadlineManager>(config_.deadlines);

        http::RetryPolicyConfig retry_cfg;
        retry_cfg.max_attempts = 1; // 1 attempt for strict circuit breaker counting in tests
        retry_cfg.initial_backoff_ms = 10;
        retry_cfg.jitter_ratio = 0.0;
        retry_policy_ = std::make_shared<http::RetryPolicy>(retry_cfg);

        rate_limiter_middleware_ = std::make_shared<http::RateLimiterMiddleware>(config_.rate_limiting);

        router_ = std::make_unique<http::Router>();
        router_->use(std::make_shared<http::RequestIdMiddleware>());
        router_->use(std::make_shared<http::LoggingMiddleware>());
        router_->use(std::make_shared<http::DrainMiddleware>(drain_manager_));
        router_->use(std::make_shared<http::ResourceLimiterMiddleware>(config_));
        router_->use(std::make_shared<http::AuthenticationMiddleware>(security_policy_, token_validator_));
        router_->use(rate_limiter_middleware_);
        router_->use(std::make_shared<http::AuthorizationMiddleware>(security_policy_));

        auth_proxy_ = std::make_shared<http::AuthProxyHandler>(auth_client_, deadline_manager_, retry_policy_,
                                                               bulkhead_manager_, auth_circuit_breaker_);
        route_registrar_ =
            std::make_unique<http::GatewayRouteRegistrar>(auth_proxy_, health_manager_, bulkhead_manager_);
        route_registrar_->register_all_routes(*router_);

        https_server_ = std::make_unique<http::HttpsServer>(config_);
        router_->register_into(*https_server_);

        bool started = https_server_->start(k_loopback_address, 0);
        ASSERT_TRUE(started);
        https_port_ = https_server_->bound_port();
        ASSERT_GT(https_port_, 0);
    }

    void stop_gateway() {
        if (https_server_) {
            https_server_->stop();
            https_server_.reset();
        }
        router_.reset();
        route_registrar_.reset();
        auth_proxy_.reset();
        auth_client_.reset();
        if (channel_manager_) {
            channel_manager_->reset();
            channel_manager_.reset();
        }
    }

    std::unique_ptr<httplib::SSLClient> create_client(std::chrono::milliseconds timeout = k_default_client_timeout) {
        auto client = std::make_unique<httplib::SSLClient>(k_loopback_address, https_port_);
        client->set_ca_cert_path(ca_path_.string());
        client->enable_server_certificate_verification(true);
        client->enable_server_hostname_verification(false);
        client->set_connection_timeout(timeout);
        client->set_read_timeout(timeout);
        client->set_write_timeout(timeout);
        return client;
    }

    ControllableResourceMockAuthService mock_auth_service_;
    std::unique_ptr<::grpc::Server> auth_server_;
    int auth_port_{0};
    std::string auth_endpoint_;

    std::filesystem::path pki_root_;
    std::filesystem::path ca_path_;
    std::filesystem::path auth_cert_path_;
    std::filesystem::path auth_key_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;

    GatewayConfig config_;
    std::unique_ptr<grpc::GrpcChannelManager> channel_manager_;
    std::shared_ptr<grpc::AuthServiceClient> auth_client_;
    std::shared_ptr<http::ITokenValidator> token_validator_;
    std::shared_ptr<http::GatewaySecurityPolicy> security_policy_;
    std::shared_ptr<common::health::HealthStatusManager> health_manager_;
    std::shared_ptr<http::DrainManager> drain_manager_;
    std::shared_ptr<http::BulkheadManager> bulkhead_manager_;
    std::shared_ptr<http::CircuitBreakerRegistry> circuit_breaker_registry_;
    std::shared_ptr<http::CircuitBreaker> auth_circuit_breaker_;
    std::shared_ptr<http::DeadlineManager> deadline_manager_;
    std::shared_ptr<http::RetryPolicy> retry_policy_;
    std::shared_ptr<http::RateLimiterMiddleware> rate_limiter_middleware_;
    std::shared_ptr<http::AuthProxyHandler> auth_proxy_;
    std::unique_ptr<http::GatewayRouteRegistrar> route_registrar_;
    std::unique_ptr<http::Router> router_;
    std::unique_ptr<http::HttpsServer> https_server_;
    int https_port_{0};
};

// ============================================================================
// Test 1: BulkheadIsolationPreventsWorkloadStarvation
// Saturated Files pool does not prevent Auth login from succeeding.
// ============================================================================
TEST_F(GatewayResourceControlsIntegrationTest, BulkheadIsolationPreventsWorkloadStarvation) {
    // Files pool capacity is configured to 2
    auto lease1 = bulkhead_manager_->acquire(http::WorkloadCategory::Files);
    auto lease2 = bulkhead_manager_->acquire(http::WorkloadCategory::Files);
    EXPECT_TRUE(lease1.is_acquired());
    EXPECT_TRUE(lease2.is_acquired());

    // 3rd Files lease must be denied
    auto lease3 = bulkhead_manager_->acquire(http::WorkloadCategory::Files);
    EXPECT_FALSE(lease3.is_acquired());

    // While Files pool is completely saturated, Auth pool must still admit and process login traffic
    auto client = create_client();
    nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "secret"}};
    auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");

    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);

    auto body = nlohmann::json::parse(res->body);
    EXPECT_EQ(body["access_token"], "valid-resource-token");
    EXPECT_EQ(body["user_id"], "user-resource-1");
}

// ============================================================================
// Test 2: BulkheadRejectionEmits503WithRetryAfter
// Saturated pool returns HTTP 503 and RFC 7807 schema.
// ============================================================================
TEST_F(GatewayResourceControlsIntegrationTest, BulkheadRejectionEmits503WithRetryAfter) {
    // Saturate the Files pool (capacity 2)
    auto lease1 = bulkhead_manager_->acquire(http::WorkloadCategory::Files);
    auto lease2 = bulkhead_manager_->acquire(http::WorkloadCategory::Files);
    EXPECT_TRUE(lease1.is_acquired());
    EXPECT_TRUE(lease2.is_acquired());

    // Dispatch request to Files route
    auto client = create_client();
    httplib::Headers headers = {{"Authorization", "Bearer valid-resource-token"}};
    auto res = client->Post("/api/v1/files/upload", headers, "test-data", "application/octet-stream");

    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 503);
    EXPECT_TRUE(res->has_header("Retry-After"));
    EXPECT_EQ(res->get_header_value("Retry-After"), "5");

    auto body = nlohmann::json::parse(res->body);
    EXPECT_EQ(body["status"], 503);
    EXPECT_EQ(body["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");
    EXPECT_EQ(body["type"], "https://securecloud.internal/errors/bulkhead-limit-exceeded");
    EXPECT_FALSE(body["title"].get<std::string>().empty());
    EXPECT_FALSE(body["detail"].get<std::string>().empty());
}

// ============================================================================
// Test 3: RateLimiterRejectsBurstsWith429AndHeaders
// Exceeding token bucket capacity emits HTTP 429 with Retry-After and X-RateLimit-* headers.
// ============================================================================
TEST_F(GatewayResourceControlsIntegrationTest, RateLimiterRejectsBurstsWith429AndHeaders) {
    auto client = create_client();
    nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "secret"}};

    // Burst capacity is 3. Send 3 valid requests sequentially
    for (int i = 0; i < 3; ++i) {
        auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 200);
        EXPECT_TRUE(res->has_header("X-RateLimit-Limit"));
        EXPECT_EQ(res->get_header_value("X-RateLimit-Limit"), "3");
        EXPECT_TRUE(res->has_header("X-RateLimit-Remaining"));
    }

    // 4th request from same client exceeds burst capacity and must be rejected
    auto res_rejected = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
    ASSERT_TRUE(res_rejected);
    EXPECT_EQ(res_rejected->status, 429);
    EXPECT_TRUE(res_rejected->has_header("Retry-After"));
    EXPECT_TRUE(res_rejected->has_header("X-RateLimit-Remaining"));
    EXPECT_EQ(res_rejected->get_header_value("X-RateLimit-Remaining"), "0");
    EXPECT_TRUE(res_rejected->has_header("X-RateLimit-Reset"));

    auto body = nlohmann::json::parse(res_rejected->body);
    EXPECT_EQ(body["status"], 429);
    EXPECT_EQ(body["error"]["code"], "RATE_LIMIT_EXCEEDED");
    EXPECT_EQ(body["type"], "https://securecloud.internal/errors/rate-limit-exceeded");
}

// ============================================================================
// Test 4: RateLimiterTokenRefillAllowsSubsequentTraffic
// Waiting allows token bucket regeneration.
// ============================================================================
TEST_F(GatewayResourceControlsIntegrationTest, RateLimiterTokenRefillAllowsSubsequentTraffic) {
    auto client = create_client();
    nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "secret"}};

    // Exhaust tokens (3 requests)
    for (int i = 0; i < 3; ++i) {
        auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 200);
    }

    // Immediately verify rejection
    auto res_rejected = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
    ASSERT_TRUE(res_rejected);
    EXPECT_EQ(res_rejected->status, 429);

    // Refill rate is 1 token per second. Sleep for 1150ms to allow 1 token to regenerate
    std::this_thread::sleep_for(std::chrono::milliseconds(1150));

    // Request now succeeds
    auto res_allowed = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
    ASSERT_TRUE(res_allowed);
    EXPECT_EQ(res_allowed->status, 200);
}

// ============================================================================
// Test 5: RateLimiterMemoryStaysBoundedUnderClientChurn
// Rapid client IP churn does not leak memory.
// ============================================================================
TEST_F(GatewayResourceControlsIntegrationTest, RateLimiterMemoryStaysBoundedUnderClientChurn) {
    auto client = create_client();
    nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "secret"}};

    // Create a local limiter with small capacity of 5 clients
    GatewayRateLimitingConfig small_cfg;
    small_cfg.enabled = true;
    small_cfg.burst_capacity = 3;
    small_cfg.refill_rate_per_sec = 1.0;
    small_cfg.max_tracked_clients = 5;
    small_cfg.client_ttl = std::chrono::seconds(60);

    http::RateLimiterMiddleware limiter(small_cfg);

    // Simulate 50 distinct client IPs churning
    for (int i = 0; i < 50; ++i) {
        std::string ip_key = "ip:10.0.0." + std::to_string(i);
        auto acq = limiter.acquire(ip_key);
        EXPECT_TRUE(acq.allowed);
    }

    // Tracked count must be strictly bounded by max_tracked_clients
    EXPECT_LE(limiter.tracked_client_count(), 5u);
    EXPECT_EQ(limiter.tracked_client_count(), 5u);
}

// ============================================================================
// Test 6: CircuitBreakerTripsOpenAfterConsecutiveFailures
// 5 consecutive backend failures transitions breaker to OPEN.
// ============================================================================
TEST_F(GatewayResourceControlsIntegrationTest, CircuitBreakerTripsOpenAfterConsecutiveFailures) {
    mock_auth_service_.authenticate_unavailable_count.store(10);

    auto client = create_client();
    nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "secret"}};

    EXPECT_EQ(auth_circuit_breaker_->state(), http::CircuitState::Closed);

    // Dispatch 5 consecutive failing requests (failure_threshold = 5)
    // Using distinct client IPs via X-Forwarded-For to avoid triggering per-IP rate limiter
    for (int i = 0; i < 5; ++i) {
        httplib::Headers headers = {{"X-Forwarded-For", "192.168.1." + std::to_string(i + 10)}};
        auto res = client->Post("/api/v1/auth/login", headers, login_body.dump(), "application/json");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 503);
    }

    // Breaker must now be OPEN
    EXPECT_EQ(auth_circuit_breaker_->state(), http::CircuitState::Open);
}

// ============================================================================
// Test 7: CircuitBreakerOpenFailsFastWithZeroRpcDispatches
// Requests in OPEN fail fast with 0 RPC dispatches.
// ============================================================================
TEST_F(GatewayResourceControlsIntegrationTest, CircuitBreakerOpenFailsFastWithZeroRpcDispatches) {
    // Trip breaker to OPEN
    for (uint32_t i = 0; i < config_.circuit_breaker.failure_threshold; ++i) {
        auth_circuit_breaker_->record_failure(true);
    }
    EXPECT_EQ(auth_circuit_breaker_->state(), http::CircuitState::Open);

    uint32_t rpcs_before = mock_auth_service_.authenticate_invocations.load();

    auto client = create_client();
    nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "secret"}};

    auto t_start = std::chrono::steady_clock::now();
    auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
    auto t_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t_start);

    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 503);
    EXPECT_TRUE(res->has_header("Retry-After"));

    // Fails fast (< 50ms)
    EXPECT_LT(t_elapsed.count(), 50);

    // Exactly 0 RPCs dispatched downstream
    EXPECT_EQ(mock_auth_service_.authenticate_invocations.load(), rpcs_before);

    auto body = nlohmann::json::parse(res->body);
    EXPECT_EQ(body["error"]["code"], "CIRCUIT_BREAKER_OPEN");
    EXPECT_EQ(body["type"], "https://securecloud.internal/errors/circuit-breaker-open");
}

// ============================================================================
// Test 8: CircuitBreakerRecoversToClosedOnSuccessfulProbe
// Breaker transitions HALF_OPEN -> CLOSED when backend recovers.
// ============================================================================
TEST_F(GatewayResourceControlsIntegrationTest, CircuitBreakerRecoversToClosedOnSuccessfulProbe) {
    for (uint32_t i = 0; i < config_.circuit_breaker.failure_threshold; ++i) {
        auth_circuit_breaker_->record_failure(true);
    }
    EXPECT_EQ(auth_circuit_breaker_->state(), http::CircuitState::Open);

    // Wait for recovery timeout (configured as 300ms)
    std::this_thread::sleep_for(std::chrono::milliseconds(350));

    // Ensure backend is healthy
    mock_auth_service_.authenticate_unavailable_count.store(0);

    auto client = create_client();
    nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "secret"}};

    auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);

    // Breaker has successfully healed to CLOSED
    EXPECT_EQ(auth_circuit_breaker_->state(), http::CircuitState::Closed);
}

// ============================================================================
// Test 9: CircuitBreakerRevertsToOpenOnFailedProbe
// Breaker reverts HALF_OPEN -> OPEN if probe fails.
// ============================================================================
TEST_F(GatewayResourceControlsIntegrationTest, CircuitBreakerRevertsToOpenOnFailedProbe) {
    for (uint32_t i = 0; i < config_.circuit_breaker.failure_threshold; ++i) {
        auth_circuit_breaker_->record_failure(true);
    }
    EXPECT_EQ(auth_circuit_breaker_->state(), http::CircuitState::Open);

    // Wait for recovery timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(350));

    // Backend is still failing
    mock_auth_service_.authenticate_unavailable_count.store(5);

    auto client = create_client();
    nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "secret"}};

    auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 503);

    // Probe failure must immediately trip breaker back to OPEN
    EXPECT_EQ(auth_circuit_breaker_->state(), http::CircuitState::Open);
}

// ============================================================================
// Test 10: GracefulShutdownCompletesInFlightRequests
// In-flight request finishes HTTP 200 during drain while new request gets 503.
// ============================================================================
TEST_F(GatewayResourceControlsIntegrationTest, GracefulShutdownCompletesInFlightRequests) {
    // Add artificial delay to mock auth to keep request in flight
    mock_auth_service_.authenticate_delay_ms.store(300);

    std::promise<void> request1_started;
    std::future<int> request1_future = std::async(std::launch::async, [this, &request1_started]() {
        auto client = create_client(std::chrono::milliseconds(4000));
        nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "secret"}};
        request1_started.set_value();
        auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
        return res ? res->status : 0;
    });

    // Wait until request1 has dispatched
    request1_started.get_future().wait();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Initiate graceful drain in a separate thread
    std::future<bool> drain_future = std::async(
        std::launch::async, [this]() { return drain_manager_->start_drain(std::chrono::milliseconds(2000)); });

    // Send a new request while drain is active
    auto client2 = create_client();
    nlohmann::json login_body = {{"identifier", "bob@securecloud.org"}, {"credential", "secret"}};
    auto res2 = client2->Post("/api/v1/auth/login", login_body.dump(), "application/json");

    ASSERT_TRUE(res2);
    // New request rejected during drain with 503
    EXPECT_EQ(res2->status, 503);
    EXPECT_TRUE(res2->has_header("Retry-After"));
    auto body2 = nlohmann::json::parse(res2->body);
    EXPECT_EQ(body2["error"]["code"], "SERVER_SHUTTING_DOWN");

    // Existing in-flight request 1 completes successfully with 200
    int req1_status = request1_future.get();
    EXPECT_EQ(req1_status, 200);

    // Drain completes cleanly
    bool drain_ok = drain_future.get();
    EXPECT_TRUE(drain_ok);
    EXPECT_EQ(drain_manager_->in_flight_count(), 0u);
}

} // namespace
} // namespace securecloud::gateway
