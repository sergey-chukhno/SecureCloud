#include "gateway_config.hpp"
#include "grpc/auth_service_client.hpp"
#include "grpc/channel_manager.hpp"
#include "http/auth/auth_service_token_validator.hpp"
#include "http/auth/authentication_middleware.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/deadline_manager.hpp"
#include "http/error_mapper.hpp"
#include "http/gateway_route_registrar.hpp"
#include "http/https_server.hpp"
#include "http/middleware/logging_middleware.hpp"
#include "http/middleware/request_id_middleware.hpp"
#include "http/middleware/resource_limiter_middleware.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/retry_policy.hpp"
#include "http/router.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/security/mtls_config.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
inline void ensure_integration_winsock() noexcept {
    static const bool initialized = []() noexcept {
        WSADATA wsa{};
        return ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    }();
    (void)initialized;
}
#else
inline void ensure_integration_winsock() noexcept {}
#endif

namespace securecloud::gateway {
namespace {

constexpr auto k_shutdown_timeout = std::chrono::milliseconds(500);
constexpr auto k_default_client_timeout = std::chrono::milliseconds(5000);
constexpr const char* k_loopback_address = "127.0.0.1";

class ControllableResilienceAuthService final : public securecloud::auth::v1::AuthService::Service {
  public:
    std::atomic<bool> is_valid{true};
    std::atomic<int> get_user_delay_ms{0};
    std::atomic<int> authenticate_delay_ms{0};
    std::atomic<int> get_user_unavailable_count{0};
    std::atomic<int> authenticate_unavailable_count{0};
    std::atomic<bool> wait_for_cancellation{false};
    std::atomic<bool> cancellation_detected{false};

    std::atomic<int> get_user_invocations{0};
    std::atomic<int> authenticate_invocations{0};
    std::atomic<int> validate_invocations{0};

    void reset_state() {
        is_valid.store(true);
        get_user_delay_ms.store(0);
        authenticate_delay_ms.store(0);
        get_user_unavailable_count.store(0);
        authenticate_unavailable_count.store(0);
        wait_for_cancellation.store(false);
        cancellation_detected.store(false);

        get_user_invocations.store(0);
        authenticate_invocations.store(0);
        validate_invocations.store(0);
    }

    ::grpc::Status Authenticate(::grpc::ServerContext* context,
                                const securecloud::auth::v1::AuthenticateRequest* /*request*/,
                                securecloud::auth::v1::AuthenticateResponse* response) override {
        authenticate_invocations.fetch_add(1);

        int delay = authenticate_delay_ms.load();
        if (delay > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }

        if (context->IsCancelled()) {
            cancellation_detected.store(true);
            return ::grpc::Status(::grpc::StatusCode::CANCELLED, "Client cancelled RPC");
        }

        int unavail = authenticate_unavailable_count.load();
        if (unavail > 0) {
            authenticate_unavailable_count.fetch_sub(1);
            return ::grpc::Status(::grpc::StatusCode::UNAVAILABLE, "Downstream service temporarily unavailable");
        }

        response->set_session_id("sess-resilience-1");
        response->set_access_token("valid-access-token-1");
        response->set_refresh_token("valid-refresh-token-1");
        response->set_authentication_level(securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
        response->set_expires_at_epoch_ms(2000000000000LL);
        response->set_user_id("user-resilience-1");
        response->set_mfa_required(false);
        return ::grpc::Status::OK;
    }

    ::grpc::Status ValidateSession(::grpc::ServerContext* /*context*/,
                                   const securecloud::auth::v1::ValidateSessionRequest* request,
                                   securecloud::auth::v1::ValidateSessionResponse* response) override {
        validate_invocations.fetch_add(1);
        if (!is_valid.load() || request->access_token() == "invalid-token" || request->access_token().empty()) {
            response->set_is_valid(false);
            return ::grpc::Status::OK;
        }

        response->set_is_valid(true);
        response->set_user_id("user-resilience-1");
        response->set_device_id("dev-resilience-1");
        response->set_authentication_level(securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
        response->set_expires_at_epoch_ms(2000000000000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status GetUser(::grpc::ServerContext* context,
                           const securecloud::auth::v1::GetUserRequest* request,
                           securecloud::auth::v1::GetUserResponse* response) override {
        get_user_invocations.fetch_add(1);

        if (wait_for_cancellation.load()) {
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (!context->IsCancelled() && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            if (context->IsCancelled()) {
                cancellation_detected.store(true);
                return ::grpc::Status(::grpc::StatusCode::CANCELLED, "Client cancelled RPC");
            }
        }

        int delay = get_user_delay_ms.load();
        if (delay > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }

        if (context->IsCancelled()) {
            cancellation_detected.store(true);
            return ::grpc::Status(::grpc::StatusCode::CANCELLED, "Client cancelled RPC");
        }

        int unavail = get_user_unavailable_count.load();
        if (unavail > 0) {
            get_user_unavailable_count.fetch_sub(1);
            return ::grpc::Status(::grpc::StatusCode::UNAVAILABLE, "Downstream service temporarily unavailable");
        }

        auto* u = response->mutable_user();
        u->set_user_id(request->user_id());
        u->set_credential_identifier("alice@securecloud.org");
        u->set_account_status(securecloud::auth::v1::AccountStatus::ACCOUNT_STATUS_ACTIVE);
        u->set_created_at_epoch_ms(1700000000000LL);
        u->set_updated_at_epoch_ms(1705000000000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status RefreshSession(::grpc::ServerContext* /*context*/,
                                  const securecloud::auth::v1::RefreshSessionRequest* /*request*/,
                                  securecloud::auth::v1::RefreshSessionResponse* response) override {
        response->set_session_id("sess-resilience-1");
        response->set_access_token("valid-access-token-refreshed");
        response->set_new_refresh_token("valid-refresh-token-refreshed");
        response->set_expires_at_epoch_ms(2100000000000LL);
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
        response->set_device_id("dev-enrolled-1");
        response->set_status(securecloud::auth::v1::DeviceStatus::DEVICE_STATUS_ACTIVE);
        response->set_registered_at_epoch_ms(1720000000000LL);
        return ::grpc::Status::OK;
    }
};

class GatewayResilienceIntegrationTest : public ::testing::Test {
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

        GatewayConfig cfg;
        cfg.http_listen_address = k_loopback_address;
        cfg.http_listen_port = 0;
        cfg.server_threads = 4;
        cfg.request_timeout_ms = std::chrono::milliseconds(5000);

        // Configure deadlines for integration test
        cfg.deadlines.auth_timeout_ms = 600; // 600ms default for auth
        cfg.deadlines.min_request_deadline_ms = 50;
        cfg.deadlines.max_request_deadline_ms = 10000;

        cfg.tls.enabled = true;
        cfg.tls.cert_path = gateway_cert_path_.string();
        cfg.tls.key_path = gateway_key_path_.string();
        cfg.tls.ca_chain_path = ca_path_.string();
        cfg.tls.https_listen_port = 0;
        cfg.tls.min_tls_version = "TLSv1.3";
        cfg.tls.cipher_suites = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

        router_ = std::make_unique<http::Router>();
        router_->use(std::make_shared<http::RequestIdMiddleware>());
        router_->use(std::make_shared<http::LoggingMiddleware>());
        router_->use(std::make_shared<http::ResourceLimiterMiddleware>(cfg));
        router_->use(std::make_shared<http::AuthenticationMiddleware>(security_policy_, token_validator_));

        health_manager_ = std::make_shared<common::health::HealthStatusManager>("gateway-resilience-test");
        health_manager_->set_live(true);
        health_manager_->set_ready(true);

        deadline_manager_ = std::make_shared<http::DeadlineManager>(cfg.deadlines);
        
        // Fast retry policy for tests (initial 50ms, 2x, zero random jitter)
        http::RetryPolicyConfig retry_cfg;
        retry_cfg.max_attempts = 3;
        retry_cfg.initial_backoff_ms = 50;
        retry_cfg.backoff_multiplier = 2.0;
        retry_cfg.max_backoff_ms = 500;
        retry_cfg.jitter_ratio = 0.0;
        retry_policy_ = std::make_shared<http::RetryPolicy>(retry_cfg);

        auth_proxy_ = std::make_shared<http::AuthProxyHandler>(auth_client_, deadline_manager_, retry_policy_);
        route_registrar_ = std::make_unique<http::GatewayRouteRegistrar>(auth_proxy_, health_manager_);
        route_registrar_->register_all_routes(*router_);

        https_server_ = std::make_unique<http::HttpsServer>(cfg);
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

    ControllableResilienceAuthService mock_auth_service_;
    std::unique_ptr<::grpc::Server> auth_server_;
    int auth_port_{0};
    std::string auth_endpoint_;

    std::filesystem::path pki_root_;
    std::filesystem::path ca_path_;
    std::filesystem::path auth_cert_path_;
    std::filesystem::path auth_key_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;

    std::unique_ptr<grpc::GrpcChannelManager> channel_manager_;
    std::shared_ptr<grpc::AuthServiceClient> auth_client_;
    std::shared_ptr<http::AuthServiceTokenValidator> token_validator_;
    std::shared_ptr<http::GatewaySecurityPolicy> security_policy_;
    std::shared_ptr<common::health::HealthStatusManager> health_manager_;
    std::shared_ptr<http::DeadlineManager> deadline_manager_;
    std::shared_ptr<http::RetryPolicy> retry_policy_;
    std::shared_ptr<http::AuthProxyHandler> auth_proxy_;
    std::unique_ptr<http::GatewayRouteRegistrar> route_registrar_;
    std::unique_ptr<http::Router> router_;
    std::unique_ptr<http::HttpsServer> https_server_;
    int https_port_{0};
};

// ============================================================================
// Scenario 1: DownstreamTimeoutReturns504WithProblemDetails
// Upstream call exceeding deadline triggers HTTP 504 Gateway Timeout with RFC 7807 problem details.
// ============================================================================
TEST_F(GatewayResilienceIntegrationTest, TestCase1_DownstreamTimeoutReturns504WithProblemDetails) {
    mock_auth_service_.get_user_delay_ms.store(1000); // 1000ms delay > 600ms configured timeout

    auto client = create_client(std::chrono::milliseconds(3000));
    httplib::Headers headers = {{"Authorization", "Bearer valid-token"}};

    auto res = client->Get("/api/v1/users/me", headers);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 504);

    auto body = nlohmann::json::parse(res->body);
    EXPECT_EQ(body["status"], 504);
    EXPECT_EQ(body["error"]["code"], "GATEWAY_TIMEOUT");
    EXPECT_EQ(body["type"], "https://securecloud.internal/errors/gateway-timeout");
    EXPECT_FALSE(body["title"].get<std::string>().empty());
    EXPECT_FALSE(body["detail"].get<std::string>().empty());
    EXPECT_FALSE(body["request_id"].get<std::string>().empty());
}

// ============================================================================
// Scenario 2: DownstreamServiceOutageReturns503
// Unreachable downstream service returns HTTP 503 Service Unavailable with RFC 7807 schema.
// ============================================================================
TEST_F(GatewayResilienceIntegrationTest, TestCase2_DownstreamServiceOutageReturns503) {
    mock_auth_service_.authenticate_unavailable_count.store(10);

    auto client = create_client();
    nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "pw"}};

    auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 503);

    auto body = nlohmann::json::parse(res->body);
    EXPECT_EQ(body["status"], 503);
    EXPECT_EQ(body["error"]["code"], "SERVICE_UNAVAILABLE");
    EXPECT_EQ(body["type"], "https://securecloud.internal/errors/service-unavailable");
    EXPECT_FALSE(body["detail"].get<std::string>().empty());
    EXPECT_FALSE(body["request_id"].get<std::string>().empty());
}

// ============================================================================
// Scenario 3: ClientSuppliedDeadlineHeaderEnforced
// Client header X-Request-Timeout: 150 clamps downstream budget and times out early.
// ============================================================================
TEST_F(GatewayResilienceIntegrationTest, TestCase3_ClientSuppliedDeadlineHeaderEnforced) {
    mock_auth_service_.get_user_delay_ms.store(350); // Downstream takes 350ms

    auto client = create_client(std::chrono::milliseconds(3000));
    httplib::Headers headers = {
        {"Authorization", "Bearer valid-token"},
        {"X-Request-Timeout", "150ms"} // Client specifies tight 150ms budget
    };

    auto start_time = std::chrono::steady_clock::now();
    auto res = client->Get("/api/v1/users/me", headers);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time);

    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 504);
    // Request must time out near 150ms, well before the 600ms default
    EXPECT_LE(elapsed.count(), 350);

    auto body = nlohmann::json::parse(res->body);
    EXPECT_EQ(body["status"], 504);
    EXPECT_EQ(body["error"]["code"], "GATEWAY_TIMEOUT");
}

// ============================================================================
// Scenario 4: ExpiredBudgetFastFailsWithoutDownstreamCall
// Request arriving with expired budget fast-fails with 504 without invoking backend RPC.
// ============================================================================
TEST_F(GatewayResilienceIntegrationTest, TestCase4_ExpiredBudgetFastFailsWithoutDownstreamCall) {
    // Override deadline manager with simulated past clock
    auto t0 = std::chrono::steady_clock::now();
    int call_count = 0;
    auto clock_fn = [t0, call_count]() mutable -> std::chrono::steady_clock::time_point {
        if (++call_count == 1) {
            return t0;
        }
        return t0 + std::chrono::milliseconds(5000); // Clock already past 600ms deadline
    };
    deadline_manager_->set_clock_fn(clock_fn);

    auto client = create_client();
    nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "pw"}};

    auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 504);

    // Invariant: downstream authenticate MUST NOT be called!
    EXPECT_EQ(mock_auth_service_.authenticate_invocations.load(), 0);

    // Reset clock fn to default
    deadline_manager_->set_clock_fn(nullptr);
}

// ============================================================================
// Scenario 5: SafeReadOnlyOperationRetriesAndSucceeds
// Simulated transient failure on attempt 1 of GET /api/v1/users/me succeeds on attempt 2.
// ============================================================================
TEST_F(GatewayResilienceIntegrationTest, TestCase5_SafeReadOnlyOperationRetriesAndSucceeds) {
    mock_auth_service_.get_user_unavailable_count.store(1); // 1st fails with UNAVAILABLE, 2nd succeeds

    auto client = create_client();
    httplib::Headers headers = {{"Authorization", "Bearer valid-token"}};

    auto res = client->Get("/api/v1/users/me", headers);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);

    auto body = nlohmann::json::parse(res->body);
    EXPECT_EQ(body["user"]["user_id"], "user-resilience-1");
    EXPECT_EQ(mock_auth_service_.get_user_invocations.load(), 2);
}

// ============================================================================
// Scenario 6: SafeReadOnlyOperationExhaustsRetriesReturns503
// Persistent transient failure stops after 3 attempts and returns 503.
// ============================================================================
TEST_F(GatewayResilienceIntegrationTest, TestCase6_SafeReadOnlyOperationExhaustsRetriesReturns503) {
    mock_auth_service_.get_user_unavailable_count.store(10); // Persistent failure

    auto client = create_client();
    httplib::Headers headers = {{"Authorization", "Bearer valid-token"}};

    auto res = client->Get("/api/v1/users/me", headers);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 503);

    auto body = nlohmann::json::parse(res->body);
    EXPECT_EQ(body["status"], 503);
    EXPECT_EQ(body["error"]["code"], "SERVICE_UNAVAILABLE");
    // Exactly 3 attempts made
    EXPECT_EQ(mock_auth_service_.get_user_invocations.load(), 3);
}

// ============================================================================
// Scenario 7: NonIdempotentOperationDoesNotRetryOnFailure
// POST /api/v1/auth/login failing with transient error executes exactly 1 attempt and never retries.
// ============================================================================
TEST_F(GatewayResilienceIntegrationTest, TestCase7_NonIdempotentOperationDoesNotRetryOnFailure) {
    mock_auth_service_.authenticate_unavailable_count.store(5);

    auto client = create_client();
    nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "pw"}};

    auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 503);

    // Invariant: Non-idempotent operation executes exactly 1 attempt!
    EXPECT_EQ(mock_auth_service_.authenticate_invocations.load(), 1);
}

// ============================================================================
// Scenario 8: RetryAbortsWhenRemainingDeadlineExhausted
// Retry loop terminates early when remaining deadline is smaller than backoff delay.
// ============================================================================
TEST_F(GatewayResilienceIntegrationTest, TestCase8_RetryAbortsWhenRemainingDeadlineExhausted) {
    mock_auth_service_.get_user_unavailable_count.store(5);
    mock_auth_service_.get_user_delay_ms.store(80); // Attempt 1 takes 80ms

    auto client = create_client();
    // Budget is 120ms total. 80ms elapsed + 50ms backoff + 50ms min floor > 120ms -> aborts retry
    httplib::Headers headers = {
        {"Authorization", "Bearer valid-token"},
        {"X-Request-Timeout", "120ms"}
    };

    auto res = client->Get("/api/v1/users/me", headers);
    ASSERT_TRUE(res);
    EXPECT_TRUE(res->status == 503 || res->status == 504);

    // Only 1 attempt made because budget was insufficient for retry backoff
    EXPECT_EQ(mock_auth_service_.get_user_invocations.load(), 1);
}

// ============================================================================
// Scenario 9: ClientCancellationAbortsDownstreamRpc
// Client closing connection / cancelling context aborts active gRPC call on downstream service.
// ============================================================================
TEST_F(GatewayResilienceIntegrationTest, TestCase9_ClientCancellationAbortsDownstreamRpc) {
    mock_auth_service_.wait_for_cancellation.store(true);

    const std::string cancel_req_id = "req-cancellation-resilience-999";
    httplib::Headers headers = {
        {"Authorization", "Bearer valid-token"},
        {"X-Request-ID", cancel_req_id}
    };

    // Run client request asynchronously
    auto future_res = std::async(std::launch::async, [this, headers]() {
        auto client = create_client(std::chrono::milliseconds(4000));
        return client->Get("/api/v1/users/me", headers);
    });

    // Wait until downstream service enters GetUser
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (mock_auth_service_.get_user_invocations.load() == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_GT(mock_auth_service_.get_user_invocations.load(), 0);

    // Cancel in-flight request via AuthProxyHandler::cancel_request
    bool cancel_dispatched = auth_proxy_->cancel_request(cancel_req_id);
    EXPECT_TRUE(cancel_dispatched);

    // Wait for response
    ASSERT_EQ(future_res.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    auto res = future_res.get();
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 499);

    auto body = nlohmann::json::parse(res->body);
    EXPECT_EQ(body["status"], 499);
    EXPECT_EQ(body["error"]["code"], "CLIENT_CANCELLED");
    EXPECT_EQ(body["type"], "https://securecloud.internal/errors/client-cancelled");

    // Verify downstream detected cancellation with brief grace period
    auto cancel_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!mock_auth_service_.cancellation_detected.load() && std::chrono::steady_clock::now() < cancel_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_TRUE(mock_auth_service_.cancellation_detected.load());
}

// ============================================================================
// Scenario 10: DeterministicRfc7807StructureAcrossAllFailureModes
// All failure responses strictly conform to RFC 7807 schema.
// ============================================================================
TEST_F(GatewayResilienceIntegrationTest, TestCase10_DeterministicRfc7807StructureAcrossAllFailureModes) {
    auto client = create_client();

    auto assert_rfc7807 = [](const httplib::Result& res, int expected_status, const std::string& expected_code) {
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, expected_status);
        EXPECT_TRUE(res->has_header("Content-Type"));
        EXPECT_EQ(res->get_header_value("Content-Type"), "application/json");

        auto body = nlohmann::json::parse(res->body);
        EXPECT_EQ(body["status"], expected_status);
        EXPECT_EQ(body["error"]["code"], expected_code);
        EXPECT_TRUE(body.contains("type"));
        EXPECT_TRUE(body["type"].get<std::string>().find("https://securecloud.internal/errors/") == 0);
        EXPECT_TRUE(body.contains("title"));
        EXPECT_FALSE(body["title"].get<std::string>().empty());
        EXPECT_TRUE(body.contains("detail"));
        EXPECT_FALSE(body["detail"].get<std::string>().empty());
        EXPECT_TRUE(body.contains("request_id"));
        EXPECT_FALSE(body["request_id"].get<std::string>().empty());
    };

    // 1. HTTP 400 Bad Request
    {
        auto res = client->Post("/api/v1/auth/login", "not-a-json-body", "application/json");
        assert_rfc7807(res, 400, "BAD_REQUEST");
    }

    // 2. HTTP 401 Unauthorized (missing token on protected route)
    {
        auto res = client->Get("/api/v1/users/me");
        assert_rfc7807(res, 401, "UNAUTHENTICATED");
    }

    // 3. HTTP 404 Not Found (authenticated request to non-existent route)
    {
        httplib::Headers headers = {{"Authorization", "Bearer valid-token"}};
        auto res = client->Get("/api/v1/nonexistent/route", headers);
        assert_rfc7807(res, 404, "NOT_FOUND");
    }

    // 4. HTTP 503 Service Unavailable
    {
        mock_auth_service_.authenticate_unavailable_count.store(1);
        nlohmann::json login_body = {{"identifier", "alice@securecloud.org"}, {"credential", "pw"}};
        auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
        assert_rfc7807(res, 503, "SERVICE_UNAVAILABLE");
    }

    // 5. HTTP 504 Gateway Timeout
    {
        mock_auth_service_.get_user_delay_ms.store(1000);
        httplib::Headers headers = {{"Authorization", "Bearer valid-token"}};
        auto res = client->Get("/api/v1/users/me", headers);
        assert_rfc7807(res, 504, "GATEWAY_TIMEOUT");
    }
}

} // namespace
} // namespace securecloud::gateway

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
#ifdef _WIN32
    std::fflush(nullptr);
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
#else
    return result;
#endif
}
