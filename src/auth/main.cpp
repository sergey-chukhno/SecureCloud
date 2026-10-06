#include "auth/crypto/argon2id_hasher.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/repository/user_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/credential_verifier.hpp"
#include "auth/service/session_manager.hpp"
#include "auth_config.hpp"
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
#include <iostream>
#include <memory>
#include <string>
#include <thread>

namespace {

constexpr auto k_poll_interval = std::chrono::milliseconds(100);
constexpr auto k_db_ping_timeout = std::chrono::milliseconds(250);
constexpr auto k_grpc_shutdown_timeout = std::chrono::seconds(5);
constexpr auto k_pool_drain_timeout = std::chrono::seconds(2);

std::atomic<bool> g_shutdown_requested{false};

// Signal handler: Strictly async-signal-safe (relaxed atomic store only).
// No logging, no mutexes, no dynamic memory allocation, no gRPC calls.
void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_shutdown_requested.store(true, std::memory_order_relaxed);
    }
}

int run_service() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    securecloud::common::configuration::ProcessEnvironmentSource env_source;
    securecloud::common::configuration::ValidationResult config_errors;
    auto config = securecloud::auth::AuthConfig::load(env_source, config_errors);

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

    // Initialize database connection pool
    auto pool = config.create_database_pool();

    std::string server_address = config.common.listen_address();
    securecloud::common::health::HealthStatusManager health_manager(config.common.service_name);

    // Bind pool->ping(250ms) to readiness evaluator (fail-closed: catches all exceptions internally)
    health_manager.set_readiness_evaluator([pool]() noexcept {
        try {
            return pool && pool->ping(k_db_ping_timeout);
        } catch (...) {
            return false;
        }
    });

    securecloud::common::health::HealthServiceImpl health_service(config.common.service_name, health_manager);

    // Instantiate wired domain components
    std::shared_ptr<securecloud::auth::service::CredentialVerifier> verifier;
    std::shared_ptr<securecloud::auth::service::SessionManager> session_mgr;
    auto audit_publisher = std::make_shared<securecloud::auth::service::AuditEventPublisher>();

    if (pool) {
        auto user_repo = std::make_shared<securecloud::auth::repository::PostgresUserRepository>(*pool);
        auto device_repo = std::make_shared<securecloud::auth::repository::PostgresDeviceRepository>(*pool);
        auto session_repo = std::make_shared<securecloud::auth::repository::PostgresSessionRepository>(*pool);
        auto hasher = std::make_shared<securecloud::auth::crypto::OpenSslArgon2idHasher>();

        verifier = std::make_shared<securecloud::auth::service::CredentialVerifier>(user_repo, hasher);
        session_mgr = std::make_shared<securecloud::auth::service::SessionManager>(session_repo, device_repo);
    }

    // Instantiate AuthServiceImpl wired with domain verifier, session manager, and audit publisher
    securecloud::auth::service::AuthServiceImpl auth_service(verifier, session_mgr, audit_publisher);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, server_creds);

    // Register both Health and Auth services
    builder.RegisterService(&health_service);
    builder.RegisterService(&auth_service);

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

    // Main event loop waiting for shutdown signal
    while (!g_shutdown_requested.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(k_poll_interval);
    }

    std::cout << "[SecureCloud] [" << config.common.service_name
              << "] Signal received, initiating graceful shutdown...\n";

    // --- Deterministic Bounded Graceful Shutdown Sequence ---

    // Step 1: Set health status to NOT_SERVING (set_shutting_down(true))
    health_manager.set_shutting_down(true);

    // Step 2: Bounded gRPC server shutdown with 5s timeout using std::chrono::system_clock
    const auto grpc_deadline = std::chrono::system_clock::now() + k_grpc_shutdown_timeout;
    server->Shutdown(grpc_deadline);

    // Step 3: Destroy server instance (avoids deadlock-prone server->Wait() call after bounded Shutdown)
    server.reset();

    // Step 4: Bounded database pool drain (2s)
    if (pool) {
        pool->shutdown(k_pool_drain_timeout);
    }

    // Step 5: Process termination with exit code 0
    std::cout << "[SecureCloud] [" << config.common.service_name << "] Graceful shutdown completed successfully.\n";
    return 0;
}

} // namespace

int main() noexcept {
    try {
        return run_service();
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [auth] Unhandled exception: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "[SecureCloud] [auth] Unknown fatal error occurred\n";
        return 1;
    }
}