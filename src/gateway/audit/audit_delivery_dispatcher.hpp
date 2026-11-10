#pragma once

#include "audit/audit_pending_store.hpp"
#include "grpc/audit_client_interface.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/retry_policy.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

namespace securecloud::gateway::audit {

class AuditProducerMetrics; // Forward declaration

struct AuditDeliveryDispatcherConfig {
    size_t batch_max_records{100};
    uint32_t audit_timeout_ms{1000};
    uint32_t audit_drain_budget_ms{3000};
    uint32_t poll_interval_ms{100};
};

/**
 * @brief Background worker thread delivering pending audit events to Audit Service via gRPC.
 */
class AuditDeliveryDispatcher {
  public:
    AuditDeliveryDispatcher(std::shared_ptr<IAuditPendingStore> pending_store,
                            std::shared_ptr<securecloud::gateway::grpc::IAuditIngestionClient> audit_client,
                            std::shared_ptr<securecloud::gateway::http::CircuitBreaker> circuit_breaker,
                            std::shared_ptr<AuditProducerMetrics> metrics,
                            AuditDeliveryDispatcherConfig config = {});

    ~AuditDeliveryDispatcher();

    AuditDeliveryDispatcher(const AuditDeliveryDispatcher&) = delete;
    AuditDeliveryDispatcher& operator=(const AuditDeliveryDispatcher&) = delete;

    void start();
    void stop();
    void notify_new_records();

    [[nodiscard]] bool is_running() const noexcept { return running_.load(std::memory_order_relaxed); }

  private:
    void worker_loop();
    bool process_next_batch();
    void update_circuit_state_metrics();

    std::shared_ptr<IAuditPendingStore> pending_store_;
    std::shared_ptr<securecloud::gateway::grpc::IAuditIngestionClient> audit_client_;
    std::shared_ptr<securecloud::gateway::http::CircuitBreaker> circuit_breaker_;
    std::shared_ptr<AuditProducerMetrics> metrics_;
    AuditDeliveryDispatcherConfig config_;
    securecloud::gateway::http::RetryPolicy retry_policy_;

    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};

    mutable std::mutex mutex_;
    std::condition_variable cv_;

    std::thread worker_thread_;
};

} // namespace securecloud::gateway::audit
