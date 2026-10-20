#pragma once

#include "delivery/device_delivery_channel_interface.hpp"

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace securecloud::messaging::delivery {

/// High-fidelity mock delivery channel for testing online message delivery.
/// Simulates network latency, disconnections, transient socket timeouts,
/// and terminal errors while recording dispatched tasks.
class MockDeviceDeliveryChannel final : public IDeviceDeliveryChannel {
  public:
    MockDeviceDeliveryChannel(domain::DeviceId device_id, domain::UserId user_id)
        : device_id_(std::move(device_id)), user_id_(std::move(user_id)) {}

    ~MockDeviceDeliveryChannel() override = default;

    [[nodiscard]] domain::DeviceId device_id() const noexcept override { return device_id_; }

    [[nodiscard]] domain::UserId user_id() const noexcept override { return user_id_; }

    [[nodiscard]] bool is_active() const noexcept override { return active_.load(std::memory_order_relaxed); }

    domain::DeliveryAttemptResult send_envelope(const domain::DeliveryTask& task,
                                                std::chrono::milliseconds timeout) override {
        if (!is_active()) {
            return domain::DeliveryAttemptResult::RecipientOffline;
        }

        const auto latency = simulated_latency_.load(std::memory_order_relaxed);
        if (latency.count() > 0) {
            if (timeout.count() > 0 && latency > timeout) {
                return domain::DeliveryAttemptResult::TransientFailure;
            }
            std::this_thread::sleep_for(latency);
        }

        {
            std::lock_guard<std::mutex> lock(record_mutex_);
            sent_tasks_.push_back(task);
        }

        {
            std::lock_guard<std::mutex> lock(handler_mutex_);
            if (custom_handler_) {
                return custom_handler_(task);
            }
        }

        return next_result_.load(std::memory_order_relaxed);
    }

    // --- Test Control & Inspection Hooks ---

    void set_active(bool active) noexcept { active_.store(active, std::memory_order_relaxed); }

    void set_next_result(domain::DeliveryAttemptResult result) noexcept {
        next_result_.store(result, std::memory_order_relaxed);
    }

    void set_simulated_latency(std::chrono::milliseconds latency) noexcept {
        simulated_latency_.store(latency, std::memory_order_relaxed);
    }

    void set_custom_handler(std::function<domain::DeliveryAttemptResult(const domain::DeliveryTask&)> handler) {
        std::lock_guard<std::mutex> lock(handler_mutex_);
        custom_handler_ = std::move(handler);
    }

    [[nodiscard]] std::vector<domain::DeliveryTask> sent_tasks() const {
        std::lock_guard<std::mutex> lock(record_mutex_);
        return sent_tasks_;
    }

    [[nodiscard]] size_t sent_task_count() const {
        std::lock_guard<std::mutex> lock(record_mutex_);
        return sent_tasks_.size();
    }

    void clear_sent_tasks() {
        std::lock_guard<std::mutex> lock(record_mutex_);
        sent_tasks_.clear();
    }

  private:
    const domain::DeviceId device_id_;
    const domain::UserId user_id_;
    std::atomic<bool> active_{true};
    std::atomic<domain::DeliveryAttemptResult> next_result_{domain::DeliveryAttemptResult::Success};
    std::atomic<std::chrono::milliseconds> simulated_latency_{std::chrono::milliseconds{0}};

    mutable std::mutex record_mutex_;
    std::vector<domain::DeliveryTask> sent_tasks_;

    mutable std::mutex handler_mutex_;
    std::function<domain::DeliveryAttemptResult(const domain::DeliveryTask&)> custom_handler_{nullptr};
};

} // namespace securecloud::messaging::delivery
