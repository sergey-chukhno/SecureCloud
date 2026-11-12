#pragma once

#include "auth/repository/auth_outbox_repository.hpp"
#include "securecloud/audit/v1/audit.grpc.pb.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>

namespace securecloud::auth::service {

struct OutboxRelayConfig {
    std::size_t batch_size{100};
    std::chrono::seconds lease_duration{30};
    std::chrono::milliseconds poll_interval{250};
    std::chrono::milliseconds max_backoff{10000};
    std::chrono::milliseconds rpc_timeout{2000};
    int32_t max_retries{15};
    std::chrono::hours published_retention{24 * 7}; // 7 days
    std::chrono::minutes cleanup_interval{15};
    std::size_t cleanup_batch_size{500};
};

struct OutboxRelayMetrics {
    std::atomic<uint64_t> batches_processed{0};
    std::atomic<uint64_t> events_published{0};
    std::atomic<uint64_t> events_failed{0};
    std::atomic<uint64_t> events_quarantined{0};
    std::atomic<uint64_t> events_purged{0};
};

/// Background worker that drains `auth_outbox` and ships batches to AuditIngestionService via gRPC.
class OutboxRelayWorker {
  public:
    OutboxRelayWorker(std::shared_ptr<repository::IAuthOutboxRepository> outbox_repo,
                      std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> audit_stub,
                      OutboxRelayConfig config = OutboxRelayConfig{});

    ~OutboxRelayWorker();

    OutboxRelayWorker(const OutboxRelayWorker&) = delete;
    OutboxRelayWorker& operator=(const OutboxRelayWorker&) = delete;

    /// Starts the background polling thread. Idempotent.
    void start();

    /// Signals shutdown, wakes the worker immediately, and joins the thread.
    void stop();

    /// Wakes the polling loop early (optional hint after staging).
    void notify_new_events() noexcept;

    /// Executes a single poll-and-ship cycle synchronously (useful for deterministic integration tests).
    std::size_t drain_once();

    [[nodiscard]] const OutboxRelayMetrics& metrics() const noexcept { return metrics_; }

  private:
    void run_loop();
    void maybe_run_cleanup();

    std::shared_ptr<repository::IAuthOutboxRepository> outbox_repo_;
    std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> audit_stub_;
    OutboxRelayConfig config_;
    OutboxRelayMetrics metrics_;

    std::mutex mutex_;
    std::condition_variable cv_;
    bool running_{false};
    bool stop_requested_{false};
    bool wakeup_requested_{false};
    std::thread worker_thread_;
    std::chrono::steady_clock::time_point last_cleanup_{std::chrono::steady_clock::now()};
};

} // namespace securecloud::auth::service
