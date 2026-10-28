#include "delivery/bounded_delivery_scheduler.hpp"

#include <algorithm>

namespace securecloud::messaging::delivery {

BoundedDeliveryScheduler::BoundedDeliveryScheduler(DeliverySchedulerConfig config) : config_(config) {}

BoundedDeliveryScheduler::~BoundedDeliveryScheduler() {
    shutdown();
}

SchedulerStatus BoundedDeliveryScheduler::schedule(domain::DeliveryTask task) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (shutdown_) {
        return SchedulerStatus::RejectedShuttingDown;
    }

    if (task.recipient_device_id.empty() || task.message_id.is_nil() || task.conversation_id.is_nil()) {
        return SchedulerStatus::InvalidTask;
    }

    if (task.expires_at.has_value() && task.expires_at.value() <= std::chrono::system_clock::now()) {
        return SchedulerStatus::InvalidTask;
    }

    // High-priority emergency traffic uses dedicated reserved capacity
    if (task.priority == domain::MessagePriority::Emergency) {
        if (total_tasks_count_ >= config_.max_global_queued_tasks + config_.emergency_queue_reserved_slots) {
            return SchedulerStatus::GlobalCapacityExhausted;
        }

        emergency_queue_.push_back(std::move(task));
        ++total_tasks_count_;
        cv_.notify_one();
        return SchedulerStatus::Enqueued;
    }

    // Normal & Urgent traffic: apply bounded capacity limits (ADR-007, ADR-010)
    if (total_tasks_count_ >= config_.max_global_queued_tasks) {
        return SchedulerStatus::GlobalCapacityExhausted;
    }

    auto& dev_queue = per_device_queues_[task.recipient_device_id];
    if (dev_queue.size() >= config_.max_tasks_per_device) {
        return SchedulerStatus::DeviceQueueFull;
    }

    const auto dev_id = task.recipient_device_id;
    dev_queue.push_back(std::move(task));
    ++total_tasks_count_;

    if (active_device_set_.insert(dev_id).second) {
        active_device_ring_.push_back(dev_id);
    }

    cv_.notify_one();
    return SchedulerStatus::Enqueued;
}

std::optional<domain::DeliveryTask> BoundedDeliveryScheduler::dequeue(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);

    if (timeout == std::chrono::milliseconds(0)) {
        cv_.wait(lock, [this] { return shutdown_ || total_tasks_count_ > 0; });
    } else {
        const bool ready = cv_.wait_for(lock, timeout, [this] { return shutdown_ || total_tasks_count_ > 0; });
        if (!ready && total_tasks_count_ == 0) {
            return std::nullopt;
        }
    }

    return dequeue_locked();
}

std::optional<domain::DeliveryTask> BoundedDeliveryScheduler::try_dequeue() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (total_tasks_count_ == 0) {
        return std::nullopt;
    }
    return dequeue_locked();
}

std::optional<domain::DeliveryTask> BoundedDeliveryScheduler::dequeue_locked() {
    // 1. Strict Priority: Emergency queue preemption
    if (!emergency_queue_.empty()) {
        auto task = std::move(emergency_queue_.front());
        emergency_queue_.pop_front();
        --total_tasks_count_;
        return task;
    }

    // 2. Round-Robin Fair Dispatch across active device queues
    while (!active_device_ring_.empty()) {
        const auto current_dev = active_device_ring_.front();
        auto it = per_device_queues_.find(current_dev);

        if (it == per_device_queues_.end() || it->second.empty()) {
            active_device_set_.erase(current_dev);
            active_device_ring_.pop_front();
            if (it != per_device_queues_.end()) {
                per_device_queues_.erase(it);
            }
            current_device_quanta_consumed_ = 0;
            continue;
        }

        auto task = std::move(it->second.front());
        it->second.pop_front();
        --total_tasks_count_;
        ++current_device_quanta_consumed_;

        if (it->second.empty()) {
            per_device_queues_.erase(it);
            active_device_set_.erase(current_dev);
            active_device_ring_.pop_front();
            current_device_quanta_consumed_ = 0;
        } else if (current_device_quanta_consumed_ >= config_.fairness_quanta_per_device) {
            // Quantum expired: yield turn and rotate device to the back of the ring
            auto dev = std::move(active_device_ring_.front());
            active_device_ring_.pop_front();
            active_device_ring_.push_back(std::move(dev));
            current_device_quanta_consumed_ = 0;
        }

        return task;
    }

    return std::nullopt;
}

std::vector<domain::DeliveryTask> BoundedDeliveryScheduler::drain_device_queue(const domain::DeviceId& device_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<domain::DeliveryTask> drained;

    // Drain from per-device queue
    auto it = per_device_queues_.find(device_id);
    if (it != per_device_queues_.end()) {
        drained.reserve(it->second.size());
        total_tasks_count_ -= it->second.size();
        while (!it->second.empty()) {
            drained.push_back(std::move(it->second.front()));
            it->second.pop_front();
        }
        per_device_queues_.erase(it);
    }

    // Remove from active ring and set
    active_device_set_.erase(device_id);
    if (!active_device_ring_.empty() && active_device_ring_.front() == device_id) {
        current_device_quanta_consumed_ = 0;
    }
    std::deque<domain::DeviceId> filtered_ring;
    for (const auto& dev : active_device_ring_) {
        if (dev != device_id) {
            filtered_ring.push_back(dev);
        }
    }
    active_device_ring_ = std::move(filtered_ring);

    // Also drain any emergency tasks scheduled for this device
    std::deque<domain::DeliveryTask> remaining_emergency;
    for (auto& task : emergency_queue_) {
        if (task.recipient_device_id == device_id) {
            drained.push_back(std::move(task));
            --total_tasks_count_;
        } else {
            remaining_emergency.push_back(std::move(task));
        }
    }
    emergency_queue_ = std::move(remaining_emergency);

    return drained;
}

size_t BoundedDeliveryScheduler::purge_device_tasks(const domain::DeviceId& device_id) {
    auto drained = drain_device_queue(device_id);
    return drained.size();
}

void BoundedDeliveryScheduler::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    emergency_queue_.clear();
    per_device_queues_.clear();
    active_device_ring_.clear();
    active_device_set_.clear();
    total_tasks_count_ = 0;
    current_device_quanta_consumed_ = 0;
}

void BoundedDeliveryScheduler::shutdown() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
    }
    cv_.notify_all();
}

bool BoundedDeliveryScheduler::is_shutdown() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return shutdown_;
}

size_t BoundedDeliveryScheduler::global_queue_depth() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_tasks_count_;
}

size_t BoundedDeliveryScheduler::device_queue_depth(const domain::DeviceId& device_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = per_device_queues_.find(device_id);
    if (it != per_device_queues_.end()) {
        return it->second.size();
    }
    return 0;
}

size_t BoundedDeliveryScheduler::emergency_queue_depth() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return emergency_queue_.size();
}

size_t BoundedDeliveryScheduler::active_device_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_device_set_.size();
}

const DeliverySchedulerConfig& BoundedDeliveryScheduler::config() const noexcept {
    return config_;
}

} // namespace securecloud::messaging::delivery
