#pragma once

#include "delivery/device_delivery_channel_interface.hpp"
#include "domain/message_types.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <vector>

namespace securecloud::messaging::delivery {

/// Callback function invoked when a connected device disconnects or has its channel evicted.
using DisconnectCallback = std::function<void(const domain::DeviceId&)>;

/// Abstract interface for tracking active connected client device channels.
/// Provides O(1) online presence checks, multi-device fan-out filtering,
/// and transport channel retrieval for asynchronous delivery.
class IDeviceConnectionRegistry {
  public:
    virtual ~IDeviceConnectionRegistry() = default;

    /// Registers or updates an active delivery channel for a device.
    /// If a channel already exists for this device, it is atomically superseded.
    virtual void register_channel(std::shared_ptr<IDeviceDeliveryChannel> channel) = 0;

    /// Unregisters an active device channel, marking the device offline.
    virtual void unregister_channel(const domain::DeviceId& device_id) = 0;

    /// Retrieves the active channel for a device if connected, or nullptr if offline.
    [[nodiscard]] virtual std::shared_ptr<IDeviceDeliveryChannel>
    get_channel(const domain::DeviceId& device_id) const = 0;

    /// Checks if a device currently has an active, non-expired connection channel.
    [[nodiscard]] virtual bool is_online(const domain::DeviceId& device_id) const = 0;

    /// Filters a collection of candidate device IDs, returning only those currently online.
    [[nodiscard]] virtual std::vector<domain::DeviceId>
    filter_online_devices(const std::vector<domain::DeviceId>& device_ids) const = 0;

    /// Total count of actively connected devices on this node.
    [[nodiscard]] virtual size_t connected_device_count() const noexcept = 0;

    /// Updates the liveness timestamp / heartbeat for an active device connection.
    /// Returns true if the device was found and refreshed, false if offline.
    virtual bool touch_channel(const domain::DeviceId& device_id) = 0;

    /// Scans registered channels and unregisters those that have exceeded max_idle duration.
    /// Returns the number of evicted channels.
    virtual size_t evict_stale_channels(std::chrono::milliseconds max_idle) = 0;

    /// Registers a callback to be invoked whenever a device disconnects or is evicted.
    virtual void register_disconnect_callback(DisconnectCallback callback) = 0;
};

} // namespace securecloud::messaging::delivery
