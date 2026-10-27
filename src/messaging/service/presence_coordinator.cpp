#include "service/presence_coordinator.hpp"

#include <algorithm>
#include <mutex>

namespace securecloud::messaging::service {

PresenceCoordinator::PresenceCoordinator(std::chrono::milliseconds default_lease_timeout)
    : lease_timeout_(default_lease_timeout) {}

void PresenceCoordinator::on_device_connected(const domain::UserId& user_id, const domain::DeviceId& device_id) {
    if (user_id.empty() || device_id.empty()) {
        return;
    }

    const auto now_steady = std::chrono::steady_clock::now();
    const auto now_sys = std::chrono::system_clock::now();

    const std::unique_lock<std::shared_mutex> lock(mutex_);
    user_devices_[user_id].insert(device_id);
    device_states_[device_id] = DeviceEntry{user_id, now_steady, now_sys};
    user_last_seen_[user_id] = now_sys;
}

void PresenceCoordinator::on_device_disconnected(const domain::UserId& user_id, const domain::DeviceId& device_id) {
    if (user_id.empty() || device_id.empty()) {
        return;
    }

    const auto now_sys = std::chrono::system_clock::now();

    const std::unique_lock<std::shared_mutex> lock(mutex_);
    user_last_seen_[user_id] = now_sys;
    device_states_.erase(device_id);

    auto it = user_devices_.find(user_id);
    if (it != user_devices_.end()) {
        it->second.erase(device_id);
        if (it->second.empty()) {
            user_devices_.erase(it);
        }
    }
}

void PresenceCoordinator::on_device_heartbeat(const domain::UserId& user_id, const domain::DeviceId& device_id) {
    if (user_id.empty() || device_id.empty()) {
        return;
    }

    const auto now_steady = std::chrono::steady_clock::now();
    const auto now_sys = std::chrono::system_clock::now();

    const std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = device_states_.find(device_id);
    if (it != device_states_.end()) {
        it->second.last_active_steady = now_steady;
        it->second.last_active_system = now_sys;
        user_last_seen_[user_id] = now_sys;
    } else {
        user_devices_[user_id].insert(device_id);
        device_states_[device_id] = DeviceEntry{user_id, now_steady, now_sys};
        user_last_seen_[user_id] = now_sys;
    }
}

void PresenceCoordinator::set_user_override(const domain::UserId& user_id, domain::PresenceStatus status,
                                            const std::string& custom_message) {
    if (user_id.empty()) {
        return;
    }

    const auto now_sys = std::chrono::system_clock::now();
    const auto sanitized_message = domain::sanitize_status_message(custom_message);

    const std::unique_lock<std::shared_mutex> lock(mutex_);
    user_overrides_[user_id] = UserOverride{status, sanitized_message, now_sys};
}

void PresenceCoordinator::clear_user_override(const domain::UserId& user_id) {
    if (user_id.empty()) {
        return;
    }

    const std::unique_lock<std::shared_mutex> lock(mutex_);
    user_overrides_.erase(user_id);
}

domain::UserPresence PresenceCoordinator::get_user_presence(const domain::UserId& user_id) const {
    const auto now_steady = std::chrono::steady_clock::now();
    const std::shared_lock<std::shared_mutex> lock(mutex_);
    return evaluate_user_presence_locked(user_id, now_steady);
}

std::vector<domain::UserPresence>
PresenceCoordinator::batch_get_presence(const std::vector<domain::UserId>& user_ids) const {
    const auto now_steady = std::chrono::steady_clock::now();
    std::vector<domain::UserPresence> results;
    results.reserve(user_ids.size());

    const std::shared_lock<std::shared_mutex> lock(mutex_);
    for (const auto& uid : user_ids) {
        results.push_back(evaluate_user_presence_locked(uid, now_steady));
    }
    return results;
}

domain::UserPresence
PresenceCoordinator::evaluate_user_presence_locked(const domain::UserId& user_id,
                                                   std::chrono::steady_clock::time_point now_steady) const {
    domain::UserPresence presence;
    presence.user_id = user_id;

    size_t active_count = 0;
    std::chrono::system_clock::time_point max_sys_time{};

    auto dev_it = user_devices_.find(user_id);
    if (dev_it != user_devices_.end()) {
        for (const auto& dev_id : dev_it->second) {
            auto d_state_it = device_states_.find(dev_id);
            if (d_state_it != device_states_.end()) {
                const auto idle_dur = now_steady - d_state_it->second.last_active_steady;
                if (lease_timeout_.count() <= 0 || idle_dur <= lease_timeout_) {
                    active_count++;
                    if (d_state_it->second.last_active_system > max_sys_time) {
                        max_sys_time = d_state_it->second.last_active_system;
                    }
                }
            }
        }
    }

    presence.active_device_count = active_count;

    if (active_count > 0) {
        presence.last_active_at = max_sys_time;
        auto override_it = user_overrides_.find(user_id);
        if (override_it != user_overrides_.end() && override_it->second.status != domain::PresenceStatus::Unspecified) {
            presence.status = override_it->second.status;
            presence.custom_status_message = override_it->second.custom_message;
        } else {
            presence.status = domain::PresenceStatus::Online;
        }
    } else {
        auto seen_it = user_last_seen_.find(user_id);
        if (seen_it != user_last_seen_.end()) {
            presence.status = domain::PresenceStatus::Offline;
            presence.last_active_at = seen_it->second;
        } else {
            presence.status = domain::PresenceStatus::Unspecified;
            presence.last_active_at = std::chrono::system_clock::time_point{};
        }
    }

    return presence;
}

size_t PresenceCoordinator::tracked_users_count() const noexcept {
    const std::shared_lock<std::shared_mutex> lock(mutex_);
    return user_last_seen_.size();
}

size_t PresenceCoordinator::tracked_devices_count() const noexcept {
    const std::shared_lock<std::shared_mutex> lock(mutex_);
    return device_states_.size();
}

size_t PresenceCoordinator::online_users_count() const noexcept {
    const auto now_steady = std::chrono::steady_clock::now();
    size_t online = 0;
    const std::shared_lock<std::shared_mutex> lock(mutex_);
    for (const auto& [user_id, devices] : user_devices_) {
        for (const auto& dev_id : devices) {
            auto d_it = device_states_.find(dev_id);
            if (d_it != device_states_.end()) {
                const auto idle = now_steady - d_it->second.last_active_steady;
                if (lease_timeout_.count() <= 0 || idle <= lease_timeout_) {
                    online++;
                    break;
                }
            }
        }
    }
    return online;
}

} // namespace securecloud::messaging::service
