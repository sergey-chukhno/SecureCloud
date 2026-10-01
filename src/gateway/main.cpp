#include "grpc/auth_service_client.hpp"
#include "grpc/channel_manager.hpp"
#include "health/gateway_health_evaluator.hpp"
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
#include "http/server/http_redirect_server.hpp"
#include "http/server/http_server.hpp"
#include "http/server/https_server.hpp"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/common/version.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <grpcpp/grpcpp.h>
#include <httplib.h>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

namespace {

constexpr auto k_rpc_timeout = std::chrono::seconds(5);
constexpr auto k_poll_interval = std::chrono::milliseconds(100);

std::atomic<bool> g_shutdown_requested{false};

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_shutdown_requested.store(true);
    }
}

void execute_peer_probe(const securecloud::gateway::GatewayConfig& config) {
    if (config.peer_probe_target.empty() || config.peer_probe_name.empty()) {
        return;
    }

    std::cout << "[SecureCloud] [" << config.common.service_name << "] Initiating mTLS peer probe to target "
              << config.peer_probe_target << " (expected SAN: DNS:" << config.peer_probe_name << ")...\n";
    try {
        auto channel = securecloud::common::security::MtlsCredentialLoader::create_mtls_channel(
            config.peer_probe_target, config.common.tls_credentials, config.peer_probe_name);
        auto stub = securecloud::common::v1::HealthService::NewStub(channel);

        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_timeout);
        securecloud::common::v1::HealthCheckRequest req;
        securecloud::common::v1::HealthCheckResponse resp;

        grpc::Status status = stub->Check(&ctx, req, &resp);
        if (status.ok() && resp.status() == securecloud::common::v1::HealthCheckResponse::SERVING) {
            std::cout << "[SecureCloud] [" << config.common.service_name
                      << "] SUCCESS: Container-to-container mTLS RPC to " << config.peer_probe_target
                      << " verified! Peer identity: " << config.peer_probe_name << "\n";
        } else {
            std::cerr << "[SecureCloud] [" << config.common.service_name
                      << "] ERROR: Peer probe failed: " << status.error_message() << "\n";
        }
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [" << config.common.service_name << "] ERROR: Peer probe exception: " << ex.what()
                  << "\n";
    }
}

int run_service() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    securecloud::common::configuration::ProcessEnvironmentSource env_source;
    securecloud::common::configuration::ValidationResult config_errors;
    auto config = securecloud::gateway::GatewayConfig::load(env_source, config_errors);

    if (!config_errors.is_valid()) {
        std::cerr << "[SecureCloud] [" << config.common.service_name << "] FATAL: Configuration validation failed:\n"
                  << config_errors.to_string() << "\n";
        return 1;
    }

    std::cout << "[SecureCloud] Starting " << config.common.service_display_name << " (" << config.common.service_name
              << ") v" << securecloud::common::get_version_string() << "\n";

    std::shared_ptr<grpc::ServerCredentials> server_creds;
    try {
        server_creds = securecloud::common::security::MtlsCredentialLoader::create_server_credentials(
            config.common.tls_credentials);
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [" << config.common.service_name
                  << "] FATAL: Failed to load mTLS server credentials: " << ex.what() << "\n";
        return 1;
    }

    if (!server_creds) {
        std::cerr << "[SecureCloud] [" << config.common.service_name
                  << "] FATAL: Failed to construct mTLS server credentials\n";
        return 1;
    }

    std::string server_address = config.common.listen_address();
    securecloud::common::health::HealthStatusManager health_manager(config.common.service_name);
    securecloud::common::health::HealthServiceImpl health_service(config.common.service_name, health_manager);

    securecloud::gateway::grpc::GrpcChannelManager channel_manager(config);
    securecloud::gateway::health::GatewayHealthEvaluator health_evaluator(channel_manager);
    health_manager.set_readiness_evaluator([&health_evaluator] { return health_evaluator.evaluate_readiness(); });

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, server_creds);
    builder.RegisterService(&health_service);

    std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
    if (!server) {
        std::cerr << "[SecureCloud] [" << config.common.service_name << "] FATAL: Failed to start gRPC mTLS server on "
                  << server_address << "\n";
        return 1;
    }

    health_manager.set_live(true);
    health_manager.set_ready(true);

    std::cout << "[SecureCloud] [" << config.common.service_name << "] mTLS server listening strictly on "
              << server_address << " with service identity 'DNS:" << config.common.service_name << "'\n";

    // Configure downstream Auth gRPC client & perimeter validation
    auto auth_channel = channel_manager.get_auth_channel();
    auto auth_client = std::make_shared<securecloud::gateway::grpc::AuthServiceClient>(auth_channel);
    auto token_validator = std::make_shared<securecloud::gateway::http::AuthServiceTokenValidator>(auth_client);
    auto security_policy = std::make_shared<securecloud::gateway::http::GatewaySecurityPolicy>(
        securecloud::gateway::http::GatewaySecurityPolicy::create_default());

    auto drain_manager = std::make_shared<securecloud::gateway::http::DrainManager>(&health_manager);

    // Assemble deterministic perimeter middleware pipeline:
    // 1. RequestIdMiddleware: assigns/propagates standard correlation ID
    // 2. LoggingMiddleware: measures request duration & logs all responses
    // 3. DrainMiddleware: rejects new requests with 503 SERVER_SHUTTING_DOWN during graceful drain (GW-009-T04)
    // 4. ResourceLimiterMiddleware: enforces transport header/body limits & concurrency boundary (GW-002)
    // 5. AuthenticationMiddleware: verifies Bearer token/MFA, establishes AuthenticatedContext
    // 6. RateLimiterMiddleware: token-bucket per-client/IP rate limiting & memory bounds (GW-009-T02)
    // 7. AuthorizationMiddleware: evaluates Enterprise Route Matrix, scopes, and device binding (GW-007)
    securecloud::gateway::http::Router router;
    router.use(std::make_shared<securecloud::gateway::http::RequestIdMiddleware>());
    router.use(std::make_shared<securecloud::gateway::http::LoggingMiddleware>());
    router.use(std::make_shared<securecloud::gateway::http::DrainMiddleware>(drain_manager));
    router.use(std::make_shared<securecloud::gateway::http::ResourceLimiterMiddleware>(config));
    router.use(
        std::make_shared<securecloud::gateway::http::AuthenticationMiddleware>(security_policy, token_validator));
    router.use(std::make_shared<securecloud::gateway::http::RateLimiterMiddleware>(config));
    router.use(std::make_shared<securecloud::gateway::http::AuthorizationMiddleware>(security_policy));

    // Register all perimeter routes (Health, Auth proxy, and Phase 2 service stubs)
    auto deadline_manager = std::make_shared<securecloud::gateway::http::DeadlineManager>(config.deadlines);
    auto retry_policy = std::make_shared<securecloud::gateway::http::RetryPolicy>();
    auto bulkhead_manager = std::make_shared<securecloud::gateway::http::BulkheadManager>(config.bulkhead);
    auto circuit_breaker_registry =
        std::make_shared<securecloud::gateway::http::CircuitBreakerRegistry>(config.circuit_breaker);
    auto auth_proxy = std::make_shared<securecloud::gateway::http::AuthProxyHandler>(
        auth_client, deadline_manager, retry_policy, bulkhead_manager, circuit_breaker_registry->get("auth"));
    securecloud::gateway::http::GatewayRouteRegistrar route_registrar(auth_proxy, health_manager, bulkhead_manager);
    route_registrar.register_all_routes(router);

    std::unique_ptr<securecloud::gateway::http::HttpServer> http_server;
    std::unique_ptr<securecloud::gateway::http::HttpRedirectServer> redirect_server;
    std::unique_ptr<securecloud::gateway::http::HttpsServer> https_server;

    if (config.tls.enabled) {
        // Enforce Gateway Design 3.24 Invariant 1 (GW-002-TC-05):
        // Cleartext HTTP listener strictly redirects to HTTPS via HTTP 308 with HSTS headers.
        redirect_server = std::make_unique<securecloud::gateway::http::HttpRedirectServer>(config);
        if (!redirect_server->start_async()) {
            std::cerr << "[SecureCloud] [" << config.common.service_name
                      << "] FATAL: Failed to start HTTP redirect server on " << config.http_listen_endpoint() << "\n";
            server->Shutdown();
            return 1;
        }
        std::cout << "[SecureCloud] [" << config.common.service_name << "] HTTP redirect server listening on "
                  << config.http_listen_endpoint() << " (redirecting to HTTPS port " << config.tls.https_listen_port
                  << " via HTTP 308)\n";

        https_server = std::make_unique<securecloud::gateway::http::HttpsServer>(config);
        router.register_into(*https_server);
        if (!https_server->start_async()) {
            std::cerr << "[SecureCloud] [" << config.common.service_name << "] FATAL: Failed to start HTTPS server on "
                      << config.http_listen_address << ":" << config.tls.https_listen_port << "\n";
            redirect_server->stop();
            server->Shutdown();
            return 1;
        }
        std::cout << "[SecureCloud] [" << config.common.service_name << "] HTTPS server listening on "
                  << config.http_listen_address << ":" << config.tls.https_listen_port << " (TLS 1.3 strict)\n";
    } else {
        http_server = std::make_unique<securecloud::gateway::http::HttpServer>(config);
        router.register_into(*http_server);
        if (!http_server->start_async()) {
            std::cerr << "[SecureCloud] [" << config.common.service_name << "] FATAL: Failed to start HTTP server on "
                      << config.http_listen_endpoint() << "\n";
            server->Shutdown();
            return 1;
        }
        std::cout << "[SecureCloud] [" << config.common.service_name << "] HTTP server listening on "
                  << config.http_listen_endpoint() << "\n";
    }

    execute_peer_probe(config);

    while (!g_shutdown_requested.load()) {
        std::this_thread::sleep_for(k_poll_interval);
    }

    std::cout << "[SecureCloud] [" << config.common.service_name
              << "] Shutdown signal received: starting coordinated graceful drain...\n";
    drain_manager->start_drain(std::chrono::milliseconds(5000));
    health_manager.set_shutting_down(true);

    if (https_server) {
        std::cout << "[SecureCloud] [" << config.common.service_name << "] Shutting down HTTPS server...\n";
        https_server->stop();
    }
    if (redirect_server) {
        std::cout << "[SecureCloud] [" << config.common.service_name << "] Shutting down HTTP redirect server...\n";
        redirect_server->stop();
    }
    if (http_server) {
        std::cout << "[SecureCloud] [" << config.common.service_name << "] Shutting down HTTP server...\n";
        http_server->stop();
    }
    channel_manager.reset();
    std::cout << "[SecureCloud] [" << config.common.service_name << "] Shutting down mTLS server...\n";
    server->Shutdown();
    return 0;
}

} // namespace

int main() noexcept {
    try {
        return run_service();
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [gateway] Unhandled exception: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "[SecureCloud] [gateway] Unknown fatal error occurred\n";
        return 1;
    }
}
