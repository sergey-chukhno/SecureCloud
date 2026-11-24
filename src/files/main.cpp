#include "files/audit/files_outbox_relay.hpp"
#include "files/audit/grpc_audit_client.hpp"
#include "files/db/files_connection_pool.hpp"
#include "files/files_config.hpp"
#include "files/health/files_health_evaluator.hpp"
#include "files/repository/files_outbox_repository.hpp"
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

    auto db_pool_config = securecloud::files::db::ConnectionPoolConfig::from_files_config(config);
    auto db_pool = std::make_shared<securecloud::files::db::FilesDbConnectionPool>(std::move(db_pool_config));

    auto s3_config = securecloud::files::storage::S3ClientConfig::from_files_config(config);
    auto s3_client = std::make_shared<securecloud::files::storage::S3Client>(std::move(s3_config));

    auto outbox_repo = std::make_shared<securecloud::files::FilesOutboxRepository>(db_pool);
    auto audit_publisher = std::make_shared<securecloud::files::service::FilesAuditEventPublisher>(outbox_repo);
    auto assembly_engine = std::make_shared<securecloud::files::service::ObjectAssemblyEngine>(s3_client);

    securecloud::files::service::FilesServiceDependencies service_deps;
    service_deps.db_pool = db_pool;
    service_deps.s3_client = s3_client;
    service_deps.audit_publisher = audit_publisher;
    service_deps.storage_engine = std::make_shared<securecloud::files::service::StorageEngine>();
    service_deps.metadata_manager = std::make_shared<securecloud::files::service::MetadataManager>(db_pool);
    service_deps.upload_session_manager =
        std::make_shared<securecloud::files::service::UploadSessionManager>(db_pool, nullptr, nullptr, audit_publisher);
    service_deps.download_manager = std::make_shared<securecloud::files::service::DownloadManager>(
        db_pool, std::make_shared<securecloud::files::service::ChunkDownloadEngine>(s3_client), nullptr, nullptr,
        nullptr, audit_publisher);
    service_deps.lifecycle_service = std::make_shared<securecloud::files::FileLifecycleService>(
        db_pool, nullptr, nullptr, nullptr, outbox_repo, audit_publisher);
    service_deps.chunk_storage_service = std::make_shared<securecloud::files::service::ChunkStorageService>(
        db_pool, s3_client, nullptr, nullptr, nullptr, audit_publisher);
    service_deps.object_assembly_engine = assembly_engine;
    service_deps.finalization_service = std::make_shared<securecloud::files::service::FileFinalizationService>(
        db_pool, assembly_engine, nullptr, nullptr, nullptr, nullptr, outbox_repo, audit_publisher);

    securecloud::files::service::FilesServiceImpl files_service(std::move(service_deps), "gateway");

    std::string server_address = config.common.listen_address();

    securecloud::common::health::HealthStatusManager health_manager(config.common.service_name);
    securecloud::files::health::FilesHealthEvaluator health_evaluator(health_manager, db_pool, s3_client);
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

    auto& outbox_metrics = securecloud::files::audit::FilesOutboxMetrics::instance();
    auto& outbox_diagnostics = securecloud::files::audit::FilesOutboxDiagnostics::instance();
    std::unique_ptr<securecloud::files::audit::FilesOutboxRelay> outbox_relay;

    if (config.audit.outbox_relay_enabled) {
        securecloud::files::audit::GrpcAuditClientConfig audit_config{
            .target_endpoint = config.audit.audit_endpoint,
            .timeout = config.audit.audit_timeout,
            .tls_credentials = config.common.tls_credentials,
            .expected_peer_san = config.audit.audit_expected_peer_san,
        };
        auto audit_client = std::make_shared<securecloud::files::audit::GrpcAuditClient>(audit_config);
        outbox_relay = std::make_unique<securecloud::files::audit::FilesOutboxRelay>(
            outbox_repo, audit_client, config.audit.relay, config.audit.producer_instance, &outbox_metrics,
            &outbox_diagnostics);
        audit_publisher->set_notify_callback([relay = outbox_relay.get()]() noexcept { relay->notify(); });
        outbox_relay->start();
    }

    std::cout << "[SecureCloud] [" << config.common.service_name << "] mTLS server listening strictly on "
              << server_address << " with service identity 'DNS:" << config.common.service_name << "'\n";

    while (!g_shutdown_requested.load()) {
        std::this_thread::sleep_for(k_poll_interval);
    }

    health_manager.set_shutting_down(true);
    health_evaluator.stop();

    std::cout << "[SecureCloud] [" << config.common.service_name << "] Shutting down mTLS server...\n";
    server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));

    audit_publisher->set_notify_callback(nullptr);
    if (outbox_relay) {
        std::cout << "[SecureCloud] [" << config.common.service_name << "] Stopping outbox relay...\n";
        outbox_relay->stop();
    }

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
