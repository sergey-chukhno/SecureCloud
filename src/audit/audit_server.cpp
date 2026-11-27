#include "audit_server.hpp"

#include "securecloud/common/version.hpp"
#include "securecloud/security/mtls_config.hpp"
#include "telemetry/audit_metrics.hpp"

#include <chrono>
#include <iostream>
#include <string>
#include <utility>

namespace securecloud::audit {

AuditServer::AuditServer(AuditConfig config) : config_(std::move(config)) {
    state_.store(ServiceState::Configured, std::memory_order_release);
}

AuditServer::~AuditServer() {
    stop();
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

    // 2. Initialize health manager. The evaluator is connected after the live ingestion queue exists.
    health_manager_ = std::make_shared<common::health::HealthStatusManager>(config_.common.service_name);

    health_service_ =
        std::make_unique<common::health::HealthServiceImpl>(config_.common.service_name, *health_manager_);

    // 3. Initialize ClickHouse client, repository, pipeline, query service, and gRPC services
    clickhouse_client_ = std::make_shared<repository::ClickHouseClient>(config_.clickhouse);
    repository_ = std::make_shared<repository::ClickHouseAuditEventRepository>(clickhouse_client_);

    dedup_cache_ = std::make_shared<ingestion::BoundedDeduplicationCache>(
        config_.ingestion.dedup_cache_capacity, std::chrono::milliseconds(config_.ingestion.dedup_cache_ttl_ms),
        config_.ingestion.dedup_cache_shards);
    pipeline_ = std::make_shared<ingestion::AuditIngestionPipeline>(config_.ingestion, repository_, dedup_cache_);
    pipeline_->start();

    ingestion_service_ = std::make_shared<service::AuditIngestionService>(
        repository_, dedup_cache_, std::chrono::milliseconds(config_.ingestion.in_flight_ack_timeout_ms), pipeline_);
    security_recorder_ =
        std::make_shared<security::InternalSecurityEventRecorder>(ingestion_service_, config_.common.service_name);
    audit_service_ = std::make_unique<service::AuditServiceImpl>(ingestion_service_, security_recorder_);

    query_app_service_ = std::make_shared<query::AuditQueryApplicationService>(repository_, config_.query);
    query_service_ = std::make_unique<service::AuditQueryServiceImpl>(query_app_service_);

    health::AuditHealthEvaluatorConfig health_config;
    health_config.check_interval = std::chrono::milliseconds(config_.health.probe_interval_ms);
    health_config.probe_timeout = std::chrono::milliseconds(config_.health.probe_timeout_ms);
    health_config.consecutive_failures_threshold = config_.health.consecutive_failures_threshold;
    health_config.queue_high_water_pct = config_.health.queue_high_water_pct;
    health_config.auto_start = false;
    health_evaluator_ = std::make_unique<health::AuditHealthEvaluator>(
        *health_manager_, clickhouse_client_,
        [pipeline = std::weak_ptr<ingestion::AuditIngestionPipeline>(pipeline_)](uint32_t& occupancy_pct) {
            const auto live_pipeline = pipeline.lock();
            if (!live_pipeline) {
                occupancy_pct = 100;
                return false;
            }
            const auto queue = live_pipeline->input_queue();
            const auto capacity = queue->capacity();
            occupancy_pct = capacity == 0 ? 100 : static_cast<uint32_t>((queue->size() * 100U) / capacity);
            return true;
        },
        health_config);

    // 4. Build and start gRPC server
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, server_creds);
    builder.RegisterService(health_service_.get());
    builder.RegisterService(audit_service_.get());
    builder.RegisterService(query_service_.get());

    server_ = builder.BuildAndStart();
    if (!server_) {
        std::cerr << "[SecureCloud] [" << config_.common.service_name << "] FATAL: Failed to start gRPC mTLS server on "
                  << server_address << "\n";
        state_.store(ServiceState::Failed, std::memory_order_release);
        return false;
    }

    // 5. Activate health probes and state
    health_manager_->set_live(true);
    if (health_evaluator_) {
        health_evaluator_->start();
    }
    telemetry::AuditMetrics::instance().set_service_draining(false);
    state_.store(ServiceState::Running, std::memory_order_release);

    security::SecurityEventContext start_ctx;
    start_ctx.rpc_method = "start";
    security_recorder_->record_event(security::InternalSecurityEventType::ServiceStarted, start_ctx);

    std::cout << "[SecureCloud] [" << config_.common.service_name << "] mTLS server listening strictly on "
              << server_address << " with service identity 'DNS:" << config_.common.service_name << "'\n";

    return true;
}

void AuditServer::stop() {
    auto expected = ServiceState::Running;
    if (!state_.compare_exchange_strong(expected, ServiceState::Draining, std::memory_order_acq_rel)) {
        // Already draining, stopped, or failed; return safely without redundant work
        return;
    }

    std::cout << "[SecureCloud] [" << config_.common.service_name
              << "] Initiating multi-phase graceful drain sequence...\n";

    // Phase 1: Withdraw Readiness (health check becomes NOT_SERVING)
    if (health_manager_) {
        health_manager_->set_shutting_down(true);
        health_manager_->set_ready(false);
    }
    if (health_evaluator_) {
        health_evaluator_->stop();
    }
    telemetry::AuditMetrics::instance().set_service_draining(true);

    // Phase 2: Reject New Ingress
    if (audit_service_) {
        audit_service_->set_draining(true);
    }

    if (security_recorder_) {
        security::SecurityEventContext drain_ctx;
        drain_ctx.rpc_method = "stop";
        security_recorder_->record_event(security::InternalSecurityEventType::ServiceDraining, drain_ctx);
    }

    // Phase 3, 4 & 5: Flush existing ingestion queue, await in-flight batches, complete durability promises
    if (pipeline_) {
        pipeline_->shutdown(std::chrono::milliseconds(config_.retention.shutdown_grace_period_ms));
    }

    // Phase 6: Shutdown gRPC server
    if (server_) {
        auto deadline =
            std::chrono::system_clock::now() + std::chrono::milliseconds(config_.retention.shutdown_grace_period_ms);
        server_->Shutdown(deadline);
    }

    // Phase 7: Transition state to Stopped
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
