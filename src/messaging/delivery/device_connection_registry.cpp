#include "delivery/device_connection_registry.hpp"

namespace securecloud::messaging::delivery {

DeviceConnectionRegistry::DeviceConnectionRegistry(std::chrono::milliseconds default_lease_timeout)
    : default_lease_timeout_(default_lease_timeout) {}

void DeviceConnectionRegistry::register_channel(std::shared_ptr<IDeviceDeliveryChannel> channel) {
    if (!channel) {
        return;
    }

    const auto id = channel->device_id();
    const std::lock_guard<std::mutex> lock(mutex_);
    channels_[id] = ChannelEntry{std::move(channel), std::chrono::steady_clock::now()};
}

void DeviceConnectionRegistry::unregister_channel(const domain::DeviceId& device_id) {
    bool found = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(device_id);
        if (it != channels_.end()) {
            channels_.erase(it);
            found = true;
        }
    }

    if (found) {
        notify_disconnect(device_id);
    }
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

    if (default_lease_timeout_.count() > 0 && (now - it->second.last_active_at) > default_lease_timeout_) {
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
            if (default_lease_timeout_.count() <= 0 || (now - it->second.last_active_at) <= default_lease_timeout_) {
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
    const auto limit = (max_idle.count() > 0) ? max_idle : default_lease_timeout_;
    std::vector<domain::DeviceId> evicted_ids;

    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = channels_.begin(); it != channels_.end();) {
            const bool inactive = !it->second.channel || !it->second.channel->is_active();
            const bool timed_out = (limit.count() > 0) && ((now - it->second.last_active_at) > limit);

            if (inactive || timed_out) {
                evicted_ids.push_back(it->first);
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
