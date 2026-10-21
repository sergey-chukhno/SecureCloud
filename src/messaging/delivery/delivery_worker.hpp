#pragma once

#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/device_connection_registry_interface.hpp"
#include "repository/delivery_state_repository_interface.hpp"
#include "repository/outbox_repository_interface.hpp"
#include "service/delivery_retry_policy.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>

namespace securecloud::messaging::delivery {

/// Runtime configuration for the background delivery worker pipeline.
struct DeliveryWorkerConfig {
    std::chrono::milliseconds send_timeout{5000};
    std::chrono::milliseconds poll_timeout{100};
    size_t worker_threads{4};
};

/// Active Delivery Worker executing the asynchronous push pipeline from message acceptance
/// through network dispatch. Operates either step-by-step or with an internal worker thread pool.
/// Handles transient backoff, durable ACK commits, and drop-to-durable backpressure.
class DeliveryWorker {
  public:
    DeliveryWorker(std::shared_ptr<BoundedDeliveryScheduler> scheduler,
                   std::shared_ptr<IDeviceConnectionRegistry> connection_registry,
                   std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                   std::shared_ptr<repository::IOutboxRepository> outbox_repo,
                   std::shared_ptr<service::DeliveryRetryPolicy> retry_policy, DeliveryWorkerConfig config = {});

    ~DeliveryWorker();

    DeliveryWorker(const DeliveryWorker&) = delete;
    DeliveryWorker& operator=(const DeliveryWorker&) = delete;
    DeliveryWorker(DeliveryWorker&&) = delete;
    DeliveryWorker& operator=(DeliveryWorker&&) = delete;

    /// Spawns the worker threads.
    void start();

    /// Signals shutdown and cleanly joins all worker threads.
    void stop();

    /// Returns whether the worker pool is actively running.
    [[nodiscard]] bool is_running() const noexcept;

    /// Processes a single delivery task synchronously from the scheduler.
    /// Returns true if a task was dequeued and processed, false if timed out or shutdown.
    bool process_single_task(std::chrono::milliseconds poll_timeout);

  private:
    void worker_loop();

    std::shared_ptr<BoundedDeliveryScheduler> scheduler_;
    std::shared_ptr<IDeviceConnectionRegistry> connection_registry_;
    std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<repository::IOutboxRepository> outbox_repo_;
    std::shared_ptr<service::DeliveryRetryPolicy> retry_policy_;
    DeliveryWorkerConfig config_;

    std::atomic<bool> running_{false};
    std::vector<std::thread> workers_;
};

} // namespace securecloud::messaging::delivery
