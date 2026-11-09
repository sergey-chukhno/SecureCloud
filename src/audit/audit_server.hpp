#pragma once

#include "audit_config.hpp"
#include "ingestion/audit_ingestion_pipeline.hpp"
#include "query/audit_query_application_service.hpp"
#include "repository/clickhouse_audit_event_repository.hpp"
#include "repository/clickhouse_client.hpp"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "security/internal_security_event_recorder.hpp"
#include "service/audit_ingestion_service.hpp"
#include "service/audit_query_service_impl.hpp"
#include "service/audit_service_impl.hpp"

#include <atomic>
#include <grpcpp/grpcpp.h>
#include <memory>

namespace securecloud::audit {

enum class ServiceState { Uninitialized, Configured, Starting, Running, Draining, Stopped, Failed };

class AuditServer {
  public:
    explicit AuditServer(AuditConfig config);
    ~AuditServer();

    AuditServer(const AuditServer&) = delete;
    AuditServer& operator=(const AuditServer&) = delete;
    AuditServer(AuditServer&&) = delete;
    AuditServer& operator=(AuditServer&&) = delete;

    /// Deterministic startup sequence:
    /// 1. Loads mTLS server credentials via MtlsCredentialLoader.
    /// 2. Registers HealthServiceImpl with ClickHouse probe.
    /// 3. Instantiates ClickHouse repository, ingestion engine, query engine, and gRPC services.
    /// 4. Binds gRPC mTLS port 50055 and registers services.
    /// 5. Transitions to Running and sets health probes to active.
    bool start();

    /// Multi-phase graceful drain sequence (AUDIT-010-T03/T04):
    /// Thread-safe, non-reentrant, and idempotent teardown orchestration.
    /// Phase 1: Withdraw Readiness (health check becomes NOT_SERVING)
    /// Phase 2: Reject New Ingress (audit_service_->set_draining(true) & record ServiceDraining event)
    /// Phase 3: Flush existing ingestion queue into ClickHouse within shutdown_grace_period_ms
    /// Phase 4: Await completion of in-flight ClickHouse batches
    /// Phase 5: Complete durability promises
    /// Phase 6: Shutdown gRPC server (server_->Shutdown(deadline))
    /// Phase 7: Join worker threadpools & transition to Stopped state
    void stop();

    /// Blocks the calling thread until the gRPC server shuts down.
    void wait();

    [[nodiscard]] ServiceState state() const noexcept;
    [[nodiscard]] const AuditConfig& config() const noexcept;
    [[nodiscard]] bool is_healthy() const noexcept;
    [[nodiscard]] std::shared_ptr<ingestion::AuditIngestionPipeline> pipeline() const noexcept { return pipeline_; }
    [[nodiscard]] std::shared_ptr<query::AuditQueryApplicationService> query_app_service() const noexcept {
        return query_app_service_;
    }

  private:
    AuditConfig config_;
    std::atomic<ServiceState> state_{ServiceState::Uninitialized};

    std::shared_ptr<repository::ClickHouseClient> clickhouse_client_;
    std::shared_ptr<repository::ClickHouseAuditEventRepository> repository_;
    std::shared_ptr<ingestion::AuditIngestionPipeline> pipeline_;
    std::shared_ptr<service::AuditIngestionService> ingestion_service_;
    std::shared_ptr<security::InternalSecurityEventRecorder> security_recorder_;
    std::shared_ptr<query::AuditQueryApplicationService> query_app_service_;

    std::unique_ptr<service::AuditServiceImpl> audit_service_;
    std::unique_ptr<service::AuditQueryServiceImpl> query_service_;

    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<common::health::HealthStatusManager> health_manager_;
    std::unique_ptr<common::health::HealthServiceImpl> health_service_;
};

} // namespace securecloud::audit
