#pragma once

#include "delivery/device_connection_registry_interface.hpp"

#include <chrono>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::delivery {

/// Configuration options controlling device and user connection capacity boundaries.
struct ConnectionCapacityConfig {
    size_t max_devices_per_user{10};
    size_t max_global_connections{100'000};
    std::chrono::milliseconds default_lease_timeout{std::chrono::seconds(60)};
};

/// Exception thrown when registering a device breaches configured per-user or global connection capacity.
class ConnectionLimitExceededException : public std::runtime_error {
  public:
    explicit ConnectionLimitExceededException(const std::string& message) : std::runtime_error(message) {}
};

/// Production implementation of IDeviceConnectionRegistry.
/// Provides thread-safe, high-concurrency tracking of connected client devices
/// using std::mutex synchronization.
class DeviceConnectionRegistry final : public IDeviceConnectionRegistry {
  public:
    explicit DeviceConnectionRegistry(std::chrono::milliseconds default_lease_timeout = std::chrono::seconds(60));
    explicit DeviceConnectionRegistry(ConnectionCapacityConfig config);
    ~DeviceConnectionRegistry() override = default;

    // Non-copyable, non-movable (owns synchronization primitives)
    DeviceConnectionRegistry(const DeviceConnectionRegistry&) = delete;
    DeviceConnectionRegistry& operator=(const DeviceConnectionRegistry&) = delete;
    DeviceConnectionRegistry(DeviceConnectionRegistry&&) = delete;
    DeviceConnectionRegistry& operator=(DeviceConnectionRegistry&&) = delete;

    void register_channel(std::shared_ptr<IDeviceDeliveryChannel> channel) override;

    void unregister_channel(const domain::DeviceId& device_id) override;

    [[nodiscard]] std::shared_ptr<IDeviceDeliveryChannel> get_channel(const domain::DeviceId& device_id) const override;

    [[nodiscard]] bool is_online(const domain::DeviceId& device_id) const override;

    [[nodiscard]] std::vector<domain::DeviceId>
    filter_online_devices(const std::vector<domain::DeviceId>& device_ids) const override;

    [[nodiscard]] size_t connected_device_count() const noexcept override;

    bool touch_channel(const domain::DeviceId& device_id) override;

    size_t evict_stale_channels(std::chrono::milliseconds max_idle) override;

    void register_disconnect_callback(DisconnectCallback callback) override;

    /// Configured default lease timeout for idle channels.
    [[nodiscard]] std::chrono::milliseconds default_lease_timeout() const noexcept {
        return config_.default_lease_timeout;
    }

    /// Configured capacity settings.
    [[nodiscard]] const ConnectionCapacityConfig& capacity_config() const noexcept { return config_; }

    /// Returns the number of currently active connected devices for a given user.
    [[nodiscard]] size_t user_device_count(const domain::UserId& user_id) const noexcept;

  private:
    struct ChannelEntry {
        std::shared_ptr<IDeviceDeliveryChannel> channel;
        std::chrono::steady_clock::time_point last_active_at;
    };

    void notify_disconnect(const domain::DeviceId& device_id);

    ConnectionCapacityConfig config_;
    mutable std::mutex mutex_;
    std::unordered_map<domain::DeviceId, ChannelEntry> channels_;
    std::unordered_map<domain::UserId, std::vector<domain::DeviceId>> user_to_devices_;

    mutable std::mutex callback_mutex_;
    std::vector<DisconnectCallback> disconnect_callbacks_;
};

} // namespace securecloud::messaging::delivery
