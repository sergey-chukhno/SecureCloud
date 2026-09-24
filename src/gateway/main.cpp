#include "gateway_config.hpp"
#include "grpc/channel_manager.hpp"
#include "health/gateway_health_evaluator.hpp"
#include "http/http_server.hpp"
#include "http/https_server.hpp"
#include "http/router.hpp"
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

constexpr int k_http_status_ok = 200;
constexpr int k_http_status_service_unavailable = 503;

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

    securecloud::gateway::http::Router router;
    router.get("/health/live", [&health_manager](const httplib::Request&, httplib::Response& res) {
        if (health_manager.is_live()) {
            res.status = k_http_status_ok;
            res.set_content(R"({"status":"SERVING"})", "application/json");
        } else {
            res.status = k_http_status_service_unavailable;
            res.set_content(R"({"status":"NOT_SERVING"})", "application/json");
        }
    });

    router.get("/health/ready", [&health_manager](const httplib::Request&, httplib::Response& res) {
        if (health_manager.is_ready() && health_manager.evaluate_readiness()) {
            res.status = k_http_status_ok;
            res.set_content(R"({"status":"SERVING"})", "application/json");
        } else {
            res.status = k_http_status_service_unavailable;
            res.set_content(R"({"status":"NOT_SERVING"})", "application/json");
        }
    });

    securecloud::gateway::http::HttpServer http_server(config);
    router.register_into(http_server);

    if (!http_server.start_async()) {
        std::cerr << "[SecureCloud] [" << config.common.service_name << "] FATAL: Failed to start HTTP server on "
                  << config.http_listen_endpoint() << "\n";
        server->Shutdown();
        return 1;
    }
    std::cout << "[SecureCloud] [" << config.common.service_name << "] HTTP server listening on "
              << config.http_listen_endpoint() << "\n";

    std::unique_ptr<securecloud::gateway::http::HttpsServer> https_server;
    if (config.tls.enabled) {
        https_server = std::make_unique<securecloud::gateway::http::HttpsServer>(config);
        router.register_into(*https_server);
        if (!https_server->start_async()) {
            std::cerr << "[SecureCloud] [" << config.common.service_name << "] FATAL: Failed to start HTTPS server on "
                      << config.http_listen_address << ":" << config.tls.https_listen_port << "\n";
            http_server.stop();
            server->Shutdown();
            return 1;
        }
        std::cout << "[SecureCloud] [" << config.common.service_name << "] HTTPS server listening on "
                  << config.http_listen_address << ":" << config.tls.https_listen_port << " (TLS 1.3 strict)\n";
    }

    if (!config.peer_probe_target.empty() && !config.peer_probe_name.empty()) {
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
            std::cerr << "[SecureCloud] [" << config.common.service_name
                      << "] ERROR: Peer probe exception: " << ex.what() << "\n";
        }
    }

    while (!g_shutdown_requested.load()) {
        std::this_thread::sleep_for(k_poll_interval);
    }

    health_manager.set_shutting_down(true);
    if (https_server) {
        std::cout << "[SecureCloud] [" << config.common.service_name << "] Shutting down HTTPS server...\n";
        https_server->stop();
    }
    std::cout << "[SecureCloud] [" << config.common.service_name << "] Shutting down HTTP server...\n";
    http_server.stop();
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
