#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace securecloud::messaging::delivery {

/// Scheduling result status returned when attempting to submit a DeliveryTask to the scheduler.
enum class SchedulerStatus : std::uint8_t {
    Enqueued = 0,                ///< Task successfully accepted into the in-memory queue.
    DeviceQueueFull = 1,         ///< Recipient device queue reached capacity (backpressure applied, drops to durable).
    GlobalCapacityExhausted = 2, ///< Global scheduler memory ceiling reached (backpressure applied, drops to durable).
    RejectedShuttingDown = 3,    ///< Scheduler is shutting down or terminated.
    InvalidTask = 4              ///< Task has invalid parameters (e.g. empty recipient device ID or already expired).
};

[[nodiscard]] constexpr std::string_view to_string(SchedulerStatus status) noexcept {
    switch (status) {
    case SchedulerStatus::Enqueued:
        return "ENQUEUED";
    case SchedulerStatus::DeviceQueueFull:
        return "DEVICE_QUEUE_FULL";
    case SchedulerStatus::GlobalCapacityExhausted:
        return "GLOBAL_CAPACITY_EXHAUSTED";
    case SchedulerStatus::RejectedShuttingDown:
        return "REJECTED_SHUTTING_DOWN";
    case SchedulerStatus::InvalidTask:
        return "INVALID_TASK";
    }
    return "UNKNOWN";
}

/// Configuration parameters for BoundedDeliveryScheduler (ADR-007, ADR-010).
struct DeliverySchedulerConfig {
    /// Maximum total tasks held across all device queues in process memory (default: 10,000).
    size_t max_global_queued_tasks{10000};

    /// Maximum active tasks permitted in a single recipient device's queue (default: 50).
    size_t max_tasks_per_device{50};

    /// Number of reserved emergency queue slots guaranteeing prompt dispatch of critical traffic (default: 1,000).
    size_t emergency_queue_reserved_slots{1000};

    /// Number of tasks a device queue can consecutively yield to worker threads before yielding turn (default: 5).
    size_t fairness_quanta_per_device{5};
};

} // namespace securecloud::messaging::delivery
