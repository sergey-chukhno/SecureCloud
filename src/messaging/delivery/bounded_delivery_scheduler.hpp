#pragma once

#include "delivery/delivery_scheduler_config.hpp"
#include "domain/delivery_types.hpp"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace securecloud::messaging::delivery {

/// Thread-safe, bounded, multi-tier delivery scheduler providing per-device fairness
/// and drop-to-durable backpressure under load (ADR-007, ADR-009, ADR-010).
class BoundedDeliveryScheduler {
  public:
    explicit BoundedDeliveryScheduler(DeliverySchedulerConfig config = {});
    ~BoundedDeliveryScheduler();

    BoundedDeliveryScheduler(const BoundedDeliveryScheduler&) = delete;
    BoundedDeliveryScheduler& operator=(const BoundedDeliveryScheduler&) = delete;
    BoundedDeliveryScheduler(BoundedDeliveryScheduler&&) = delete;
    BoundedDeliveryScheduler& operator=(BoundedDeliveryScheduler&&) = delete;

    /// Schedules an online delivery task into the in-memory queue hierarchy.
    /// Returns Enqueued on success, or backpressure status (DeviceQueueFull, GlobalCapacityExhausted, etc.).
    SchedulerStatus schedule(domain::DeliveryTask task);

    /// Dequeues the next highest-priority, fair delivery task.
    /// If timeout > 0, blocks up to timeout waiting for a task.
    /// If timeout == 0, blocks indefinitely until a task is available or the scheduler is shut down.
    /// Returns std::nullopt on timeout or if the scheduler is shut down and empty.
    std::optional<domain::DeliveryTask> dequeue(std::chrono::milliseconds timeout = std::chrono::milliseconds(0));

    /// Non-blocking polling attempt to dequeue the next available task.
    /// Returns std::nullopt immediately if no tasks are available.
    std::optional<domain::DeliveryTask> try_dequeue();

    /// Drains and returns all queued tasks for a specific recipient device.
    /// Invoked when a device disconnects or is revoked.
    std::vector<domain::DeliveryTask> drain_device_queue(const domain::DeviceId& device_id);

    /// Clears all queues and discards all pending tasks.
    void clear();

    /// Initiates graceful shutdown, waking all blocking dequeue calls.
    void shutdown();

    /// Checks if scheduler has been shut down.
    [[nodiscard]] bool is_shutdown() const;

    // --- Observability & Metrics ---
    [[nodiscard]] size_t global_queue_depth() const;
    [[nodiscard]] size_t device_queue_depth(const domain::DeviceId& device_id) const;
    [[nodiscard]] size_t emergency_queue_depth() const;
    [[nodiscard]] size_t active_device_count() const;
    [[nodiscard]] const DeliverySchedulerConfig& config() const noexcept;

  private:
    [[nodiscard]] std::optional<domain::DeliveryTask> dequeue_locked();

    DeliverySchedulerConfig config_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool shutdown_{false};
    size_t total_tasks_count_{0};

    // Dedicated high-priority emergency queue (bypasses device round-robin)
    std::deque<domain::DeliveryTask> emergency_queue_;

    // Per-device FIFO queues for Normal & Urgent traffic
    std::unordered_map<domain::DeviceId, std::deque<domain::DeliveryTask>> per_device_queues_;

    // Round-robin active device tracking ring
    std::deque<domain::DeviceId> active_device_ring_;
    std::unordered_set<domain::DeviceId> active_device_set_;
    size_t current_device_quanta_consumed_{0};
};

} // namespace securecloud::messaging::delivery
