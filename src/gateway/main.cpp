#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/common/version.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

namespace {

constexpr std::string_view service_name = "gateway";
constexpr std::string_view service_display_name = "Gateway Service";
constexpr uint16_t default_port = 50051;

constexpr auto k_rpc_timeout = std::chrono::seconds(5);
constexpr auto k_poll_interval = std::chrono::milliseconds(100);

std::atomic<bool> g_shutdown_requested{false};

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_shutdown_requested.store(true);
    }
}

std::string get_env_or_default(const char* env_var, const std::string& default_val) {
    const char* val = std::getenv(env_var); // NOLINT(concurrency-mt-unsafe)
    if (val != nullptr && *val != '\0') {
        return val;
    }
    return default_val;
}

class HealthServiceImpl final : public securecloud::common::v1::HealthService::Service {
  public:
    grpc::Status Check(grpc::ServerContext* context, const securecloud::common::v1::HealthCheckRequest* request,
                       securecloud::common::v1::HealthCheckResponse* response) override {
        (void)request;
        if (!context->auth_context()->IsPeerAuthenticated()) {
            return {grpc::StatusCode::UNAUTHENTICATED, "Peer unauthenticated"};
        }
        response->set_status(securecloud::common::v1::HealthCheckResponse::SERVING);
        return grpc::Status::OK;
    }
};

int run_service() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::cout << "[SecureCloud] Starting " << service_display_name << " (" << service_name << ") v"
              << securecloud::common::get_version_string() << "\n";

    std::string ca_path = get_env_or_default("SECURECLOUD_CA_CERT_PATH", "/etc/securecloud/certs/ca.crt");
    std::string service_cert_path =
        get_env_or_default("SECURECLOUD_SERVICE_CERT_PATH", "/etc/securecloud/certs/service.crt");
    std::string service_key_path =
        get_env_or_default("SECURECLOUD_SERVICE_KEY_PATH", "/etc/securecloud/certs/service.key");
    std::string port_str = get_env_or_default("SECURECLOUD_GRPC_PORT", std::to_string(default_port));

    securecloud::common::security::SecurityCredentialsConfig cred_config{
        .ca_cert_path = ca_path,
        .service_cert_path = service_cert_path,
        .service_key_path = service_key_path,
    };

    std::shared_ptr<grpc::ServerCredentials> server_creds;
    try {
        server_creds = securecloud::common::security::MtlsCredentialLoader::create_server_credentials(cred_config);
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [" << service_name
                  << "] FATAL: Failed to load mTLS server credentials: " << ex.what() << "\n";
        return 1;
    }

    if (!server_creds) {
        std::cerr << "[SecureCloud] [" << service_name << "] FATAL: Failed to construct mTLS server credentials\n";
        return 1;
    }

    std::string server_address = "0.0.0.0:" + port_str;
    HealthServiceImpl health_service;

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, server_creds);
    builder.RegisterService(&health_service);

    std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
    if (!server) {
        std::cerr << "[SecureCloud] [" << service_name << "] FATAL: Failed to start gRPC mTLS server on "
                  << server_address << "\n";
        return 1;
    }

    std::cout << "[SecureCloud] [" << service_name << "] mTLS server listening strictly on " << server_address
              << " with service identity 'DNS:" << service_name << "'\n";

    std::string probe_target = get_env_or_default("SECURECLOUD_PEER_PROBE_TARGET", "");
    std::string probe_name = get_env_or_default("SECURECLOUD_PEER_PROBE_NAME", "");
    if (!probe_target.empty() && !probe_name.empty()) {
        std::cout << "[SecureCloud] [" << service_name << "] Initiating mTLS peer probe to target " << probe_target
                  << " (expected SAN: DNS:" << probe_name << ")...\n";
        try {
            auto channel = securecloud::common::security::MtlsCredentialLoader::create_mtls_channel(
                probe_target, cred_config, probe_name);
            auto stub = securecloud::common::v1::HealthService::NewStub(channel);

            grpc::ClientContext ctx;
            ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_timeout);
            securecloud::common::v1::HealthCheckRequest req;
            securecloud::common::v1::HealthCheckResponse resp;

            grpc::Status status = stub->Check(&ctx, req, &resp);
            if (status.ok() && resp.status() == securecloud::common::v1::HealthCheckResponse::SERVING) {
                std::cout << "[SecureCloud] [" << service_name << "] SUCCESS: Container-to-container mTLS RPC to "
                          << probe_target << " verified! Peer identity: " << probe_name << "\n";
            } else {
                std::cerr << "[SecureCloud] [" << service_name
                          << "] ERROR: Peer probe failed: " << status.error_message() << "\n";
            }
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [" << service_name << "] ERROR: Peer probe exception: " << ex.what() << "\n";
        }
    }

    while (!g_shutdown_requested.load()) {
        std::this_thread::sleep_for(k_poll_interval);
    }

    std::cout << "[SecureCloud] [" << service_name << "] Shutting down mTLS server...\n";
    server->Shutdown();
    return 0;
}

} // namespace

int main() noexcept {
    try {
        return run_service();
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [" << service_name << "] Unhandled exception: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "[SecureCloud] [" << service_name << "] Unknown fatal error occurred\n";
        return 1;
    }
}
