#pragma once

#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/device_connection_registry_interface.hpp"
#include "domain/delivery_types.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::messaging::delivery {

/// Configuration tuning parameters for the durable delivery crash-recovery engine.
struct DeliveryRecoveryConfig {
    size_t batch_size{100};
    std::chrono::milliseconds sweep_interval{5000};
    int32_t max_retry_attempts{5};
    std::chrono::hours max_delivery_ttl{24};
};

/**
 * @brief Crash Recovery & Delayed Retry Sweeper Service (ADR-007, ADR-009, ADR-010).
 *
 * Guarantees zero message loss across process restarts, node crashes, and memory backpressure:
 * 1. Startup Recovery: Hydrates unacknowledged pending deliveries from ScyllaDB into BoundedDeliveryScheduler.
 * 2. Retry Sweeper: Identifies records in RETRY_WAIT whose backoff timestamp has elapsed, re-enqueuing into scheduler.
 * 3. Expired Delivery Purger: Detects tasks exceeding maximum delivery TTL and marks them EXPIRED.
 * 4. Drop-to-Durable Backpressure: Respects bounded memory limits; excess tasks remain safely in ScyllaDB.
 */
class DurableDeliveryRecoveryService {
  public:
    DurableDeliveryRecoveryService(std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                                   std::shared_ptr<BoundedDeliveryScheduler> scheduler,
                                   std::shared_ptr<IDeviceConnectionRegistry> connection_registry = nullptr,
                                   DeliveryRecoveryConfig config = {});
    ~DurableDeliveryRecoveryService();

    DurableDeliveryRecoveryService(const DurableDeliveryRecoveryService&) = delete;
    DurableDeliveryRecoveryService& operator=(const DurableDeliveryRecoveryService&) = delete;
    DurableDeliveryRecoveryService(DurableDeliveryRecoveryService&&) = delete;
    DurableDeliveryRecoveryService& operator=(DurableDeliveryRecoveryService&&) = delete;

    /// Hydrates pending (QUEUED / DELIVERING) tasks for a specific recipient device into the scheduler.
    /// Returns the number of tasks successfully enqueued into the scheduler.
    size_t recover_pending_for_device(const domain::DeviceId& device_id, const std::string& delivery_bucket);

    /// Sweeps records in RETRY_WAIT whose next_retry_at <= now, re-enqueuing ready tasks.
    /// Returns the number of retried tasks re-enqueued into the scheduler.
    size_t sweep_retries_for_device(const domain::DeviceId& device_id, const std::string& delivery_bucket,
                                    std::chrono::system_clock::time_point now);

    /// Identifies and purges deliveries exceeding expiration TTL, marking them EXPIRED in ScyllaDB.
    /// Returns the number of expired tasks updated.
    size_t purge_expired_for_device(const domain::DeviceId& device_id, const std::string& delivery_bucket,
                                    std::chrono::system_clock::time_point now);

    /// Executes a single synchronous recovery cycle over candidate devices.
    /// Returns the total number of tasks scheduled.
    size_t run_recovery_cycle(const std::vector<domain::DeviceId>& candidate_devices,
                              const std::string& delivery_bucket = "");

    /// Starts the background periodic recovery sweeper thread.
    void start(std::vector<domain::DeviceId> candidate_devices = {});

    /// Signals the background sweeper thread to stop and joins it.
    void stop();

    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] const DeliveryRecoveryConfig& config() const noexcept { return config_; }

  private:
    void background_worker_loop();

    std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<BoundedDeliveryScheduler> scheduler_;
    std::shared_ptr<IDeviceConnectionRegistry> connection_registry_;
    DeliveryRecoveryConfig config_;

    std::atomic<bool> running_{false};
    std::thread worker_thread_;
    std::mutex cv_mutex_;
    std::condition_variable cv_;
    std::vector<domain::DeviceId> background_candidate_devices_;
};

} // namespace securecloud::messaging::delivery
