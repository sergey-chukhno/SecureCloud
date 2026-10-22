#include "concurrency/bounded_worker_pool.hpp"
#include "messaging_config.hpp"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/common/version.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/health/transport_probe.hpp"
#include "securecloud/security/mtls_config.hpp"
#include "service/messaging_service_impl.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <utility>

namespace {

constexpr auto k_poll_interval = std::chrono::milliseconds(100);

std::atomic<bool> g_shutdown_requested{false};

// Signal handler: Strictly async-signal-safe (relaxed atomic store only).
// No logging, no mutexes, no allocations, no gRPC calls.
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
    auto config = securecloud::messaging::MessagingConfig::load(env_source, config_errors);

    if (!config_errors.is_valid()) {
        std::cerr << "[SecureCloud] [" << config.common.service_name << "] FATAL: Configuration validation failed:\n"
                  << config_errors.to_string() << "\n";
        return 1;
    }

    std::cout << "[SecureCloud] Starting " << config.common.service_display_name << " (" << config.common.service_name
              << ") v" << securecloud::common::get_version_string() << "\n";

    // 1. Initialize mTLS server credentials
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

    // 2. Initialize bounded worker pools with configured bounds (ADR-009, ADR-010)
    auto submission_pool = std::make_shared<securecloud::messaging::concurrency::BoundedWorkerPool>(
        config.workers.submission_workers, config.workers.max_queued_submissions, "submission");
    auto delivery_pool = std::make_shared<securecloud::messaging::concurrency::BoundedWorkerPool>(
        config.workers.delivery_workers, config.workers.max_queued_deliveries, "delivery");
    auto sync_pool = std::make_shared<securecloud::messaging::concurrency::BoundedWorkerPool>(
        config.workers.sync_workers, config.workers.max_queued_syncs, "sync");

    std::cout << "[SecureCloud] [" << config.common.service_name << "] Initialized bounded worker pools: "
              << "submission (" << config.workers.submission_workers << " workers, queue "
              << config.workers.max_queued_submissions << "), delivery (" << config.workers.delivery_workers
              << " workers, queue " << config.workers.max_queued_deliveries << "), sync ("
              << config.workers.sync_workers << " workers, queue " << config.workers.max_queued_syncs << ")\n";

    // 3. Instantiate MessagingServiceImpl
    securecloud::messaging::service::MessagingServiceImpl messaging_service(submission_pool, delivery_pool, sync_pool);

    // 4. Initialize health status manager and health service
    const std::string server_address = config.common.listen_address();
    securecloud::common::health::HealthStatusManager health_manager(config.common.service_name);
    health_manager.set_readiness_evaluator([&config] {
        return securecloud::common::health::probe_tcp_connectivity(config.scylla.host, config.scylla.port);
    });
    securecloud::common::health::HealthServiceImpl health_service(config.common.service_name, health_manager);

    // 5. Construct and start gRPC server strictly over mTLS
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, server_creds);
    builder.RegisterService(&messaging_service);
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

    // 6. Main service loop waiting for shutdown signal
    while (!g_shutdown_requested.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(k_poll_interval);
    }

    // 7. Deterministic Graceful Drain Sequence (ADR-009, ADR-010)
    std::cout << "[SecureCloud] [" << config.common.service_name
              << "] Shutdown signal received; initiating graceful drain...\n";
    health_manager.set_shutting_down(true);

    const auto drain_deadline =
        std::chrono::system_clock::now() + std::chrono::milliseconds(config.shutdown_grace_period_ms);
    std::cout << "[SecureCloud] [" << config.common.service_name
              << "] Draining gRPC server (deadline: " << config.shutdown_grace_period_ms << "ms)...\n";
    server->Shutdown(drain_deadline);

    std::cout << "[SecureCloud] [" << config.common.service_name << "] Draining bounded worker pools...\n";
    submission_pool->drain_and_stop();
    delivery_pool->drain_and_stop();
    sync_pool->drain_and_stop();

    std::cout << "[SecureCloud] [" << config.common.service_name << "] Graceful shutdown completed successfully.\n";
    return 0;
}

} // namespace

int main() noexcept {
    try {
        return run_service();
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [messaging] Unhandled exception: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "[SecureCloud] [messaging] Unknown fatal error occurred\n";
        return 1;
    }
}
