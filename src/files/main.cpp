#include "files/db/files_connection_pool.hpp"
#include "files/files_config.hpp"
#include "files/health/files_health_evaluator.hpp"
#include "files/service/files_service_impl.hpp"
#include "files/storage/s3_client.hpp"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/common/version.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/health/transport_probe.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace {

constexpr auto k_poll_interval = std::chrono::milliseconds(100);

std::atomic<bool> g_shutdown_requested{false};

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_shutdown_requested.store(true);
    }
}

int run_service() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    securecloud::common::configuration::ProcessEnvironmentSource env_source;
    securecloud::common::configuration::ValidationResult config_errors;
    auto config = securecloud::files::FilesConfig::load(env_source, config_errors);

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

    // Initialize PostgreSQL connection pool and MinIO S3 client
    auto db_pool_config = securecloud::files::db::ConnectionPoolConfig::from_files_config(config);
    auto db_pool = std::make_shared<securecloud::files::db::FilesDbConnectionPool>(std::move(db_pool_config));

    auto s3_config = securecloud::files::storage::S3ClientConfig::from_files_config(config);
    auto s3_client = std::make_shared<securecloud::files::storage::S3Client>(std::move(s3_config));

    // Initialize FilesServiceImpl enforcing Gateway mTLS client identity (DNS:gateway)
    securecloud::files::service::FilesServiceImpl files_service(
        db_pool, s3_client, /*expected_client_identity=*/"gateway");

    std::string server_address = config.common.listen_address();

    securecloud::common::health::HealthStatusManager health_manager(config.common.service_name);
    securecloud::files::health::FilesHealthEvaluator health_evaluator(
        health_manager, db_pool, s3_client);
    securecloud::common::health::HealthServiceImpl health_service(config.common.service_name, health_manager);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, server_creds);
    builder.RegisterService(&files_service);
    builder.RegisterService(&health_service);

    std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
    if (!server) {
        std::cerr << "[SecureCloud] [" << config.common.service_name << "] FATAL: Failed to start gRPC mTLS server on "
                  << server_address << "\n";
        return 1;
    }

    health_manager.set_live(true);
    health_evaluator.evaluate_once();

    std::cout << "[SecureCloud] [" << config.common.service_name << "] mTLS server listening strictly on "
              << server_address << " with service identity 'DNS:" << config.common.service_name << "'\n";

    while (!g_shutdown_requested.load()) {
        std::this_thread::sleep_for(k_poll_interval);
    }

    health_manager.set_shutting_down(true);
    health_evaluator.stop();
    std::cout << "[SecureCloud] [" << config.common.service_name << "] Shutting down mTLS server...\n";
    server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));

    std::cout << "[SecureCloud] [" << config.common.service_name << "] Draining database connection pool...\n";
    db_pool->drain();
    db_pool->close();

    return 0;
}

} // namespace

int main() noexcept {
    try {
        return run_service();
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [files] Unhandled exception: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "[SecureCloud] [files] Unknown fatal error occurred\n";
        return 1;
    }
}
