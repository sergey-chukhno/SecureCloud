#pragma once

#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/connection_lifecycle_manager.hpp"
#include "delivery/device_connection_registry_interface.hpp"
#include "domain/delivery_types.hpp"
#include "repository/delivery_state_repository_interface.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <string>

namespace securecloud::messaging::delivery {

struct RealtimeDeliveryAcceleratorConfig {
    size_t max_fast_track_batch{50};
    std::chrono::milliseconds max_delivery_ttl{std::chrono::hours(24 * 7)};
};

/// Realtime Delivery Accelerator implementing the Reconnect Fast-Track Hook (ADR-007, MSG-010).
/// When an offline device reconnects, immediately queries ScyllaDB for pending undelivered envelopes
/// and schedules them directly into BoundedDeliveryScheduler, slashing delivery resumption latency
/// from poll intervals down to sub-millisecond execution.
///
/// Invariants & Protections:
/// - Drop-to-durable backpressure: respects scheduler capacity and halts on queue full.
/// - Fairness burst bounding: caps the immediate fast-track sweep to max_fast_track_batch (default 50).
/// - Non-conflation: does NOT mark messages as DELIVERED; relies strictly on client affirmative ACKs.
/// - Ephemeral zero-plaintext safety: passes only encrypted ciphertext envelopes.
class RealtimeDeliveryAccelerator {
  public:
    using Config = RealtimeDeliveryAcceleratorConfig;

    RealtimeDeliveryAccelerator(std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                                std::shared_ptr<BoundedDeliveryScheduler> scheduler,
                                std::shared_ptr<IDeviceConnectionRegistry> connection_registry = nullptr,
                                Config config = {});

    ~RealtimeDeliveryAccelerator() = default;

    RealtimeDeliveryAccelerator(const RealtimeDeliveryAccelerator&) = delete;
    RealtimeDeliveryAccelerator& operator=(const RealtimeDeliveryAccelerator&) = delete;
    RealtimeDeliveryAccelerator(RealtimeDeliveryAccelerator&&) = delete;
    RealtimeDeliveryAccelerator& operator=(RealtimeDeliveryAccelerator&&) = delete;

    /// Triggers the fast-track sweep for a reconnected device.
    /// If delivery_bucket is empty, uses the current UTC monthly bucket (YYYYMM).
    /// Returns the number of tasks successfully enqueued into the scheduler.
    size_t on_device_connected(const domain::DeviceId& device_id, const domain::UserId& user_id = domain::UserId(""),
                               const std::string& delivery_bucket = "");

    /// Convenience listener registration: attaches this accelerator's on_device_connected
    /// callback to the given ConnectionLifecycleManager.
    void attach_to_lifecycle_manager(ConnectionLifecycleManager& lifecycle_manager);

    /// Total count of tasks accelerated across all reconnection events.
    [[nodiscard]] size_t total_accelerated_count() const noexcept;

    /// Config inspection.
    [[nodiscard]] const Config& config() const noexcept { return config_; }

  private:
    std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<BoundedDeliveryScheduler> scheduler_;
    std::shared_ptr<IDeviceConnectionRegistry> connection_registry_;
    const Config config_;

    std::atomic<size_t> total_accelerated_{0};
};

} // namespace securecloud::messaging::delivery
