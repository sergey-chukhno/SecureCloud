#pragma once

#include "audit/messaging_audit_client.hpp"
#include "repository/messaging_audit_outbox_repository_interface.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::messaging::audit {

struct OutboxRelayConfig {
    uint32_t worker_threads{4};
    uint32_t total_shards{16};
    std::chrono::milliseconds active_poll_interval{50};
    std::chrono::milliseconds idle_poll_interval{500};
    std::chrono::seconds lease_duration{30};
    size_t batch_size{100}; // Bound to AUDIT-005 limits
    int32_t max_retries{5}; // Quarantine threshold
    std::chrono::milliseconds base_backoff{100};
    std::chrono::milliseconds max_backoff{10000};
};

/**
 * @brief Asynchronous worker pool that relays messaging audit events to the central Audit Service.
 *
 * Implements a sharded polling strategy over ScyllaDB outbox partitions, enforcing
 * exponential backoff for transient failures, a quarantine engine for poison pills,
 * lock-free Prometheus telemetry, and Zero-PII structured JSON diagnostics (AUDIT-014-T06).
 */
class MessagingOutboxRelay {
  public:
    MessagingOutboxRelay(std::shared_ptr<repository::IMessagingAuditOutboxRepository> repository,
                         std::shared_ptr<IMessagingAuditClient> audit_client, OutboxRelayConfig config = {});

    ~MessagingOutboxRelay();

    void start();
    void stop();

  private:
    void worker_loop(uint32_t worker_index);
    bool process_shard(const std::string& bucket, int32_t shard_id);
    void interruptible_wait(std::chrono::milliseconds duration);

    std::string get_current_hourly_bucket() const;
    std::string get_previous_hourly_bucket() const;
    std::chrono::milliseconds calculate_backoff_with_jitter(int32_t attempt_count) const;

    std::shared_ptr<repository::IMessagingAuditOutboxRepository> repository_;
    std::shared_ptr<IMessagingAuditClient> audit_client_;
    OutboxRelayConfig config_;

    std::atomic<bool> is_running_{false};
    std::mutex wake_mutex_;
    std::condition_variable wake_cv_;
    std::vector<std::thread> workers_;
};

} // namespace securecloud::messaging::audit
