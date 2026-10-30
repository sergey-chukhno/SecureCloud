#pragma once

#include "delivery/device_connection_registry_interface.hpp"
#include "domain/connection_session.hpp"
#include "service/presence_coordinator_interface.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::delivery {

/// High-level coordinator managing client connection lifecycles, active session contexts,
/// heartbeat liveness tracking, and background stale socket eviction (reaping).
/// Enforces invariants:
/// - Maximum 1 active channel per DeviceId (atomic superseding).
/// - Thread-safe session tracking.
/// - Periodic eviction of stale connections exceeding configured lease timeout.
/// - Coordinated notification of PresenceCoordinator upon connect, disconnect, and heartbeat.
class ConnectionLifecycleManager {
  public:
    ConnectionLifecycleManager(std::shared_ptr<IDeviceConnectionRegistry> registry,
                               std::shared_ptr<service::IPresenceCoordinator> presence_coordinator,
                               std::chrono::milliseconds reaper_interval = std::chrono::seconds(15),
                               std::chrono::milliseconds lease_timeout = std::chrono::seconds(60));

    ~ConnectionLifecycleManager();

    ConnectionLifecycleManager(const ConnectionLifecycleManager&) = delete;
    ConnectionLifecycleManager& operator=(const ConnectionLifecycleManager&) = delete;
    ConnectionLifecycleManager(ConnectionLifecycleManager&&) = delete;
    ConnectionLifecycleManager& operator=(ConnectionLifecycleManager&&) = delete;

    /// Starts the background reaper thread.
    void start();

    /// Stops the background reaper thread cleanly and waits for termination.
    void stop();

    /// Returns true if the background reaper thread is actively running.
    [[nodiscard]] bool is_running() const noexcept;

    /// Establishes or supersedes a device connection with rich session metadata.
    /// Registers the channel in the underlying registry and notifies the PresenceCoordinator.
    domain::ConnectionSession establish_connection(std::shared_ptr<IDeviceDeliveryChannel> channel,
                                                   std::string client_ip = "", std::string user_agent = "",
                                                   uint32_t protocol_version = 1);

    /// Gracefully terminates an active connection by device ID.
    void terminate_connection(const domain::DeviceId& device_id);

    /// Records client liveness / heartbeat, refreshing the underlying channel lease
    /// and updating session timestamps and PresenceCoordinator.
    /// Returns true if the device session was active and refreshed, false otherwise.
    bool record_heartbeat(const domain::DeviceId& device_id);

    /// Retrieves an active connection session by device ID.
    [[nodiscard]] std::optional<domain::ConnectionSession> get_session(const domain::DeviceId& device_id) const;

    /// Total count of actively tracked connection sessions.
    [[nodiscard]] size_t active_session_count() const noexcept;

    /// Configured reaper interval.
    [[nodiscard]] std::chrono::milliseconds reaper_interval() const noexcept { return reaper_interval_; }

    /// Configured connection lease timeout.
    [[nodiscard]] std::chrono::milliseconds lease_timeout() const noexcept { return lease_timeout_; }

    /// Manually triggers a single sweep of the stale connection reaper.
    /// Returns the number of evicted channels.
    size_t sweep_stale_connections();

    /// Reconnection event callback hook invoked when a device channel is successfully established.
    using DeviceConnectedCallback = std::function<void(const domain::DeviceId&, const domain::UserId&)>;

    /// Registers a listener for device connection establishment (e.g. RealtimeDeliveryAccelerator).
    void register_connected_callback(DeviceConnectedCallback cb);

  private:
    void reaper_loop();
    void on_registry_disconnect(const domain::DeviceId& device_id);

    std::shared_ptr<IDeviceConnectionRegistry> registry_;
    std::shared_ptr<service::IPresenceCoordinator> presence_coordinator_;
    const std::chrono::milliseconds reaper_interval_;
    const std::chrono::milliseconds lease_timeout_;

    std::atomic<bool> running_{false};
    std::thread reaper_thread_;
    mutable std::mutex cv_mutex_;
    std::condition_variable cv_;

    mutable std::mutex session_mutex_;
    std::unordered_map<domain::DeviceId, domain::ConnectionSession> sessions_;

    mutable std::mutex callback_mutex_;
    std::vector<DeviceConnectedCallback> connected_callbacks_;

    static constexpr size_t kNumStripes = 64;
    mutable std::array<std::mutex, kNumStripes> lifecycle_stripes_;
};

} // namespace securecloud::messaging::delivery
