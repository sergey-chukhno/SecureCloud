#include "delivery/device_connection_registry.hpp"

#include <algorithm>

namespace securecloud::messaging::delivery {

DeviceConnectionRegistry::DeviceConnectionRegistry(std::chrono::milliseconds default_lease_timeout)
    : config_{.default_lease_timeout = default_lease_timeout} {}

DeviceConnectionRegistry::DeviceConnectionRegistry(ConnectionCapacityConfig config) : config_(config) {}

void DeviceConnectionRegistry::register_channel(std::shared_ptr<IDeviceDeliveryChannel> channel) {
    if (!channel) {
        return;
    }

    const auto id = channel->device_id();
    const auto uid = channel->user_id();
    bool is_superseding = false;

    {
        const std::lock_guard<std::mutex> lock(mutex_);

        auto it = channels_.find(id);
        if (it != channels_.end()) {
            // Atomic superseding: device already registered. Old channel will be replaced.
            is_superseding = true;
            const auto old_uid = it->second.channel ? it->second.channel->user_id() : uid;
            if (old_uid != uid) {
                // If device user changed, remove from old user mapping
                auto& old_user_devs = user_to_devices_[old_uid];
                std::erase(old_user_devs, id);
                if (old_user_devs.empty()) {
                    user_to_devices_.erase(old_uid);
                }
            }
        } else {
            // New device connection: check global capacity
            if (config_.max_global_connections > 0 && channels_.size() >= config_.max_global_connections) {
                throw ConnectionLimitExceededException("Global connection capacity reached: maximum " +
                                                       std::to_string(config_.max_global_connections) +
                                                       " concurrent connections");
            }

            // Check per-user device capacity
            auto& user_devs = user_to_devices_[uid];
            if (config_.max_devices_per_user > 0 && user_devs.size() >= config_.max_devices_per_user) {
                throw ConnectionLimitExceededException("User device limit exceeded for user " + uid.str() +
                                                       ": maximum " + std::to_string(config_.max_devices_per_user) +
                                                       " active devices");
            }
        }

        channels_[id] = ChannelEntry{channel, std::chrono::steady_clock::now()};

        // Maintain user_to_devices_
        auto& user_devs = user_to_devices_[uid];
        if (std::find(user_devs.begin(), user_devs.end(), id) == user_devs.end()) {
            user_devs.push_back(id);
        }
    }

    if (is_superseding) {
        // Notify disconnect for the superseded channel so external observers (and reaper) are aware
        notify_disconnect(id);
    }
}

void DeviceConnectionRegistry::unregister_channel(const domain::DeviceId& device_id) {
    bool found = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(device_id);
        if (it != channels_.end()) {
            if (it->second.channel) {
                const auto uid = it->second.channel->user_id();
                auto u_it = user_to_devices_.find(uid);
                if (u_it != user_to_devices_.end()) {
                    std::erase(u_it->second, device_id);
                    if (u_it->second.empty()) {
                        user_to_devices_.erase(u_it);
                    }
                }
            }
            channels_.erase(it);
            found = true;
        }
    }

    if (found) {
        notify_disconnect(device_id);
    }
}

size_t DeviceConnectionRegistry::user_device_count(const domain::UserId& user_id) const noexcept {
    const std::lock_guard<std::mutex> lock(mutex_);
    auto it = user_to_devices_.find(user_id);
    if (it != user_to_devices_.end()) {
        return it->second.size();
    }
    return 0;
}

std::shared_ptr<IDeviceDeliveryChannel> DeviceConnectionRegistry::get_channel(const domain::DeviceId& device_id) const {
    const auto now = std::chrono::steady_clock::now();
    const std::lock_guard<std::mutex> lock(mutex_);

    auto it = channels_.find(device_id);
    if (it == channels_.end()) {
        return nullptr;
    }

    if (!it->second.channel || !it->second.channel->is_active()) {
        return nullptr;
    }

    if (config_.default_lease_timeout.count() > 0 &&
        (now - it->second.last_active_at) > config_.default_lease_timeout) {
        return nullptr;
    }

    return it->second.channel;
}

bool DeviceConnectionRegistry::is_online(const domain::DeviceId& device_id) const {
    return get_channel(device_id) != nullptr;
}

std::vector<domain::DeviceId>
DeviceConnectionRegistry::filter_online_devices(const std::vector<domain::DeviceId>& device_ids) const {
    if (device_ids.empty()) {
        return {};
    }

    const auto now = std::chrono::steady_clock::now();
    std::vector<domain::DeviceId> online;
    online.reserve(device_ids.size());

    const std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& id : device_ids) {
        auto it = channels_.find(id);
        if (it != channels_.end() && it->second.channel && it->second.channel->is_active()) {
            if (config_.default_lease_timeout.count() <= 0 ||
                (now - it->second.last_active_at) <= config_.default_lease_timeout) {
                online.push_back(id);
            }
        }
    }

    return online;
}

size_t DeviceConnectionRegistry::connected_device_count() const noexcept {
    const std::lock_guard<std::mutex> lock(mutex_);
    return channels_.size();
}

bool DeviceConnectionRegistry::touch_channel(const domain::DeviceId& device_id) {
    const std::lock_guard<std::mutex> lock(mutex_);
    auto it = channels_.find(device_id);
    if (it != channels_.end() && it->second.channel && it->second.channel->is_active()) {
        it->second.last_active_at = std::chrono::steady_clock::now();
        return true;
    }
    return false;
}

size_t DeviceConnectionRegistry::evict_stale_channels(std::chrono::milliseconds max_idle) {
    const auto now = std::chrono::steady_clock::now();
    const auto limit = (max_idle.count() > 0) ? max_idle : config_.default_lease_timeout;
    std::vector<domain::DeviceId> evicted_ids;

    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = channels_.begin(); it != channels_.end();) {
            const bool inactive = !it->second.channel || !it->second.channel->is_active();
            const bool timed_out = (limit.count() > 0) && ((now - it->second.last_active_at) > limit);

            if (inactive || timed_out) {
                const auto dev_id = it->first;
                if (it->second.channel) {
                    const auto uid = it->second.channel->user_id();
                    auto u_it = user_to_devices_.find(uid);
                    if (u_it != user_to_devices_.end()) {
                        std::erase(u_it->second, dev_id);
                        if (u_it->second.empty()) {
                            user_to_devices_.erase(u_it);
                        }
                    }
                }
                evicted_ids.push_back(dev_id);
                it = channels_.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (const auto& id : evicted_ids) {
        notify_disconnect(id);
    }

    return evicted_ids.size();
}

void DeviceConnectionRegistry::register_disconnect_callback(DisconnectCallback callback) {
    if (!callback) {
        return;
    }
    std::lock_guard<std::mutex> lock(callback_mutex_);
    disconnect_callbacks_.push_back(std::move(callback));
}

void DeviceConnectionRegistry::notify_disconnect(const domain::DeviceId& device_id) {
    std::vector<DisconnectCallback> callbacks_copy;
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        callbacks_copy = disconnect_callbacks_;
    }

    for (const auto& cb : callbacks_copy) {
        if (cb) {
            cb(device_id);
        }
    }
}

} // namespace securecloud::messaging::delivery
