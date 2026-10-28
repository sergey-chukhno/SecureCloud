#include "audit_server.hpp"

#include "securecloud/common/version.hpp"
#include "securecloud/health/transport_probe.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <chrono>
#include <iostream>
#include <utility>

namespace securecloud::audit {

AuditServer::AuditServer(AuditConfig config) : config_(std::move(config)) {
    state_.store(ServiceState::Configured, std::memory_order_release);
}

AuditServer::~AuditServer() {
    if (state_.load(std::memory_order_acquire) == ServiceState::Running) {
        stop();
    }
}

bool AuditServer::start() {
    auto expected = ServiceState::Configured;
    if (!state_.compare_exchange_strong(expected, ServiceState::Starting, std::memory_order_acq_rel)) {
        return false;
    }

    std::cout << "[SecureCloud] Starting " << config_.common.service_display_name << " (" << config_.common.service_name
              << ") v" << securecloud::common::get_version_string() << "\n";

    // 1. Load mTLS server credentials
    std::shared_ptr<grpc::ServerCredentials> server_creds;
    try {
        server_creds = securecloud::common::security::MtlsCredentialLoader::create_server_credentials(
            config_.common.tls_credentials);
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [" << config_.common.service_name
                  << "] FATAL: Failed to load mTLS server credentials: " << ex.what() << "\n";
        state_.store(ServiceState::Failed, std::memory_order_release);
        return false;
    }

    if (!server_creds) {
        std::cerr << "[SecureCloud] [" << config_.common.service_name
                  << "] FATAL: Failed to construct mTLS server credentials\n";
        state_.store(ServiceState::Failed, std::memory_order_release);
        return false;
    }

    std::string server_address = config_.common.listen_address();

    // 2. Initialize Health Manager and Service with ClickHouse probe
    health_manager_ = std::make_shared<common::health::HealthStatusManager>(config_.common.service_name);
    health_manager_->set_readiness_evaluator([this] {
        return securecloud::common::health::probe_tcp_connectivity(config_.clickhouse.host, config_.clickhouse.port);
    });

    health_service_ =
        std::make_unique<common::health::HealthServiceImpl>(config_.common.service_name, *health_manager_);

    // 3. Initialize ClickHouse client, repository, pipeline, and gRPC service
    clickhouse_client_ = std::make_shared<repository::ClickHouseClient>(config_.clickhouse);
    repository_ = std::make_shared<repository::ClickHouseAuditEventRepository>(clickhouse_client_);

    pipeline_ = std::make_shared<ingestion::AuditIngestionPipeline>(config_.ingestion, repository_);
    pipeline_->start();

    ingestion_service_ = std::make_shared<service::AuditIngestionService>(repository_);
    audit_service_ = std::make_unique<service::AuditServiceImpl>(ingestion_service_);

    // 4. Build and start gRPC server
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, server_creds);
    builder.RegisterService(health_service_.get());
    builder.RegisterService(audit_service_.get());

    server_ = builder.BuildAndStart();
    if (!server_) {
        std::cerr << "[SecureCloud] [" << config_.common.service_name << "] FATAL: Failed to start gRPC mTLS server on "
                  << server_address << "\n";
        state_.store(ServiceState::Failed, std::memory_order_release);
        return false;
    }

    // 5. Activate health probes and state
    health_manager_->set_live(true);
    health_manager_->set_ready(true);
    state_.store(ServiceState::Running, std::memory_order_release);

    std::cout << "[SecureCloud] [" << config_.common.service_name << "] mTLS server listening strictly on "
              << server_address << " with service identity 'DNS:" << config_.common.service_name << "'\n";

    return true;
}

void AuditServer::stop() {
    auto expected = ServiceState::Running;
    if (!state_.compare_exchange_strong(expected, ServiceState::Draining, std::memory_order_acq_rel)) {
        return;
    }

    std::cout << "[SecureCloud] [" << config_.common.service_name << "] Shutting down mTLS server...\n";

    if (health_manager_) {
        health_manager_->set_shutting_down(true);
        health_manager_->set_ready(false);
    }

    if (pipeline_) {
        pipeline_->shutdown(std::chrono::milliseconds(config_.retention.shutdown_grace_period_ms));
    }

    if (server_) {
        auto deadline =
            std::chrono::system_clock::now() + std::chrono::milliseconds(config_.retention.shutdown_grace_period_ms);
        server_->Shutdown(deadline);
    }

    state_.store(ServiceState::Stopped, std::memory_order_release);
    std::cout << "[SecureCloud] [" << config_.common.service_name << "] AuditServer stopped gracefully.\n";
}

void AuditServer::wait() {
    if (server_) {
        server_->Wait();
    }
}

ServiceState AuditServer::state() const noexcept {
    return state_.load(std::memory_order_acquire);
}

const AuditConfig& AuditServer::config() const noexcept {
    return config_;
}

bool AuditServer::is_healthy() const noexcept {
    return state_.load(std::memory_order_acquire) == ServiceState::Running && health_manager_ != nullptr &&
           health_manager_->is_live() && health_manager_->is_ready() && !health_manager_->is_shutting_down();
}

} // namespace securecloud::audit
