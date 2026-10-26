#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_types.hpp"
#include "domain/presence_types.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::service {

/// Abstract port interface for the multi-device in-memory presence coordinator (ADR-007, ADR-010).
class IPresenceCoordinator {
  public:
    virtual ~IPresenceCoordinator() = default;

    /// Evaluates and returns current presence for a specific user.
    [[nodiscard]] virtual domain::UserPresence get_user_presence(const domain::UserId& user_id) const = 0;

    /// Evaluates and returns current presence for a batch of users.
    [[nodiscard]] virtual std::vector<domain::UserPresence>
    batch_get_presence(const std::vector<domain::UserId>& user_ids) const = 0;

    /// Sets an explicit user status override (e.g. Away or Busy with custom status note).
    virtual void set_user_override(const domain::UserId& user_id, domain::PresenceStatus status,
                                   const std::string& custom_message) = 0;

    /// Clears an explicit user status override, reverting to natural device connectivity status.
    virtual void clear_user_override(const domain::UserId& user_id) = 0;

    /// Lifecycle hook: notified when a client device establishes an active transport channel.
    virtual void on_device_connected(const domain::UserId& user_id, const domain::DeviceId& device_id) = 0;

    /// Lifecycle hook: notified when a client device disconnects or is evicted.
    virtual void on_device_disconnected(const domain::UserId& user_id, const domain::DeviceId& device_id) = 0;

    /// Lifecycle hook: notified when a client device sends a keepalive heartbeat / activity touch.
    virtual void on_device_heartbeat(const domain::UserId& user_id, const domain::DeviceId& device_id) = 0;

    /// Configured lease timeout for idle device connections.
    [[nodiscard]] virtual std::chrono::milliseconds lease_timeout() const noexcept = 0;
};

} // namespace securecloud::messaging::service
