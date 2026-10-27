#pragma once

#include "service/presence_coordinator_interface.hpp"

#include <chrono>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace securecloud::messaging::service {

/// Production implementation of IPresenceCoordinator.
/// Provides thread-safe, high-concurrency multi-device aggregation and ephemeral leased presence tracking
/// using std::shared_mutex synchronization (ADR-007, ADR-010).
class PresenceCoordinator final : public IPresenceCoordinator {
  public:
    explicit PresenceCoordinator(std::chrono::milliseconds default_lease_timeout = std::chrono::seconds(60));
    ~PresenceCoordinator() override = default;

    PresenceCoordinator(const PresenceCoordinator&) = delete;
    PresenceCoordinator& operator=(const PresenceCoordinator&) = delete;
    PresenceCoordinator(PresenceCoordinator&&) = delete;
    PresenceCoordinator& operator=(PresenceCoordinator&&) = delete;

    [[nodiscard]] domain::UserPresence get_user_presence(const domain::UserId& user_id) const override;

    [[nodiscard]] std::vector<domain::UserPresence>
    batch_get_presence(const std::vector<domain::UserId>& user_ids) const override;

    void set_user_override(const domain::UserId& user_id, domain::PresenceStatus status,
                           const std::string& custom_message) override;

    void clear_user_override(const domain::UserId& user_id) override;

    void on_device_connected(const domain::UserId& user_id, const domain::DeviceId& device_id) override;

    void on_device_disconnected(const domain::UserId& user_id, const domain::DeviceId& device_id) override;

    void on_device_heartbeat(const domain::UserId& user_id, const domain::DeviceId& device_id) override;

    [[nodiscard]] std::chrono::milliseconds lease_timeout() const noexcept override { return lease_timeout_; }

    /// Operational inspection helpers
    [[nodiscard]] size_t tracked_users_count() const noexcept;
    [[nodiscard]] size_t tracked_devices_count() const noexcept;
    [[nodiscard]] size_t online_users_count() const noexcept;

  private:
    struct DeviceEntry {
        domain::UserId user_id;
        std::chrono::steady_clock::time_point last_active_steady;
        std::chrono::system_clock::time_point last_active_system;
    };

    struct UserOverride {
        domain::PresenceStatus status{domain::PresenceStatus::Online};
        std::string custom_message{};
        std::chrono::system_clock::time_point updated_at{};
    };

    [[nodiscard]] domain::UserPresence
    evaluate_user_presence_locked(const domain::UserId& user_id,
                                  std::chrono::steady_clock::time_point now_steady) const;

    const std::chrono::milliseconds lease_timeout_;
    mutable std::shared_mutex mutex_;

    // user_id -> set of registered device_ids
    std::unordered_map<domain::UserId, std::unordered_set<domain::DeviceId>> user_devices_;

    // device_id -> device entry (owning user_id, activity timestamps)
    std::unordered_map<domain::DeviceId, DeviceEntry> device_states_;

    // user_id -> explicit user-selected status override
    std::unordered_map<domain::UserId, UserOverride> user_overrides_;

    // user_id -> last observed active timestamp before disconnecting / going offline
    std::unordered_map<domain::UserId, std::chrono::system_clock::time_point> user_last_seen_;
};

} // namespace securecloud::messaging::service
