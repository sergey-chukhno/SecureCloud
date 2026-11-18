#pragma once

#include "repository/messaging_audit_outbox_repository_interface.hpp"
#include "securecloud/audit/v1/audit.pb.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::messaging::audit {

// Forward declaration of the gRPC client interface (to be implemented in T04/T05 integration)
class IMessagingAuditClient {
public:
    virtual ~IMessagingAuditClient() = default;

    struct BatchResult {
        bool success{false};
        bool is_transient_error{false};
        std::string error_message;
        std::vector<std::string> rejected_event_ids;
    };

    // Synchronous or blocking-asynchronous dispatch of a batch of events
    virtual BatchResult send_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) = 0;
};

// Configuration properties for the Sharded Poller
struct OutboxRelayConfig {
    uint32_t worker_threads{4};
    uint32_t total_shards{16};
    std::chrono::milliseconds active_poll_interval{50};
    std::chrono::milliseconds idle_poll_interval{500};
    std::chrono::seconds lease_duration{30};
    size_t batch_size{100}; // Bound to AUDIT-005 limits
    int32_t max_retries{5}; // Quarantine threshold
};

/**
 * @brief Asynchronous worker pool that relays messaging audit events to the central Audit Service.
 *
 * Implements a sharded polling strategy over ScyllaDB outbox partitions, enforcing
 * exponential backoff for transient failures and a quarantine engine for poison pills.
 */
class MessagingOutboxRelay {
public:
    MessagingOutboxRelay(
        std::shared_ptr<repository::IMessagingAuditOutboxRepository> repository,
        std::shared_ptr<IMessagingAuditClient> audit_client,
        OutboxRelayConfig config = {}
    );

    ~MessagingOutboxRelay();

    // Starts the background worker threads. Safe to call multiple times.
    void start();

    // Gracefully stops workers, allowing in-flight batches to drain.
    void stop();

private:
    void worker_loop(uint32_t worker_index);
    bool process_shard(const std::string& bucket, int32_t shard_id);

    std::string get_current_hourly_bucket() const;
    std::string get_previous_hourly_bucket() const;
    std::chrono::milliseconds calculate_backoff_with_jitter(int32_t attempt_count) const;

    std::shared_ptr<repository::IMessagingAuditOutboxRepository> repository_;
    std::shared_ptr<IMessagingAuditClient> audit_client_;
    OutboxRelayConfig config_;

    std::atomic<bool> is_running_{false};
    std::vector<std::thread> workers_;
};

} // namespace securecloud::messaging::audit
