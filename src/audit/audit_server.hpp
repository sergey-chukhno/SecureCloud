#pragma once

#include "audit_config.hpp"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"

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
    /// 3. Binds gRPC mTLS port.
    /// 4. Transitions to Running and sets health probes to active.
    bool start();

    /// Graceful drain sequence:
    /// 1. Transitions to Draining; marks health probes as shutting down.
    /// 2. Initiates bounded gRPC server shutdown within shutdown_grace_period_ms budget.
    /// 3. Transitions to Stopped.
    void stop();

    /// Blocks the calling thread until the gRPC server shuts down.
    void wait();

    [[nodiscard]] ServiceState state() const noexcept;
    [[nodiscard]] const AuditConfig& config() const noexcept;
    [[nodiscard]] bool is_healthy() const noexcept;

  private:
    AuditConfig config_;
    std::atomic<ServiceState> state_{ServiceState::Uninitialized};

    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<common::health::HealthStatusManager> health_manager_;
    std::unique_ptr<common::health::HealthServiceImpl> health_service_;
};

} // namespace securecloud::audit