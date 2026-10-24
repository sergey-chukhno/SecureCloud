#include "delivery/connection_lifecycle_manager.hpp"

#include <iostream>
#include <random>
#include <sstream>

namespace securecloud::messaging::delivery {

namespace {

/// Generates a random hexadecimal string for synthetic connection ID creation.
std::string generate_random_connection_id() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    uint64_t high = dist(rng);
    uint64_t low = dist(rng);

    std::stringstream ss;
    ss << std::hex << high << low;
    return ss.str();
}

} // namespace

ConnectionLifecycleManager::ConnectionLifecycleManager(
    std::shared_ptr<IDeviceConnectionRegistry> registry,
    std::shared_ptr<service::IPresenceCoordinator> presence_coordinator, std::chrono::milliseconds reaper_interval,
    std::chrono::milliseconds lease_timeout)
    : registry_(std::move(registry)), presence_coordinator_(std::move(presence_coordinator)),
      reaper_interval_(reaper_interval), lease_timeout_(lease_timeout) {
    if (registry_) {
        registry_->register_disconnect_callback(
            [this](const domain::DeviceId& device_id) { on_registry_disconnect(device_id); });
    }
}

ConnectionLifecycleManager::~ConnectionLifecycleManager() {
    stop();
}

void ConnectionLifecycleManager::start() {
    bool expected = false;
    if (running_.compare_exchange_strong(expected, true)) {
        reaper_thread_ = std::thread(&ConnectionLifecycleManager::reaper_loop, this);
    }
}

void ConnectionLifecycleManager::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        {
            std::lock_guard<std::mutex> lock(cv_mutex_);
            cv_.notify_all();
        }
        if (reaper_thread_.joinable()) {
            reaper_thread_.join();
        }
    }
}

bool ConnectionLifecycleManager::is_running() const noexcept {
    return running_.load(std::memory_order_relaxed);
}

domain::ConnectionSession
ConnectionLifecycleManager::establish_connection(std::shared_ptr<IDeviceDeliveryChannel> channel, std::string client_ip,
                                                 std::string user_agent, uint32_t protocol_version) {
    if (!channel) {
        throw std::invalid_argument("Cannot establish connection with null delivery channel");
    }

    const auto dev_id = channel->device_id();
    const auto uid = channel->user_id();
    const auto now = std::chrono::steady_clock::now();

    // 1. Register channel in underlying registry (enforces capacity limits & atomic superseding)
    if (registry_) {
        registry_->register_channel(channel);
    }

    // 2. Track / update rich connection session
    domain::ConnectionSession session{
        .connection_id = generate_random_connection_id(),
        .device_id = dev_id,
        .user_id = uid,
        .client_ip = std::move(client_ip),
        .user_agent = std::move(user_agent),
        .protocol_version = protocol_version,
        .state = domain::ConnectionState::Active,
        .connected_at = now,
        .last_heartbeat_at = now,
    };

    {
        std::lock_guard<std::mutex> lock(session_mutex_);
        sessions_[dev_id] = session;
    }

    // 3. Notify presence coordinator of active connection
    if (presence_coordinator_) {
        presence_coordinator_->on_device_connected(uid, dev_id);
    }

    // 4. Notify registered connected callbacks (e.g. RealtimeDeliveryAccelerator)
    {
        std::vector<DeviceConnectedCallback> callbacks;
        {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            callbacks = connected_callbacks_;
        }
        for (const auto& cb : callbacks) {
            if (cb) {
                cb(dev_id, uid);
            }
        }
    }

    return session;
}

void ConnectionLifecycleManager::terminate_connection(const domain::DeviceId& device_id) {
    if (registry_) {
        registry_->unregister_channel(device_id);
    }
}

bool ConnectionLifecycleManager::record_heartbeat(const domain::DeviceId& device_id) {
    const auto now = std::chrono::steady_clock::now();
    domain::UserId uid;
    bool found = false;

    {
        std::lock_guard<std::mutex> lock(session_mutex_);
        auto it = sessions_.find(device_id);
        if (it != sessions_.end()) {
            it->second.last_heartbeat_at = now;
            it->second.state = domain::ConnectionState::Active;
            uid = it->second.user_id;
            found = true;
        }
    }

    if (!found) {
        return false;
    }

    if (registry_) {
        registry_->touch_channel(device_id);
    }

    if (presence_coordinator_) {
        presence_coordinator_->on_device_heartbeat(uid, device_id);
    }

    return true;
}

std::optional<domain::ConnectionSession>
ConnectionLifecycleManager::get_session(const domain::DeviceId& device_id) const {
    std::lock_guard<std::mutex> lock(session_mutex_);
    auto it = sessions_.find(device_id);
    if (it != sessions_.end()) {
        return it->second;
    }
    return std::nullopt;
}

size_t ConnectionLifecycleManager::active_session_count() const noexcept {
    std::lock_guard<std::mutex> lock(session_mutex_);
    return sessions_.size();
}

size_t ConnectionLifecycleManager::sweep_stale_connections() {
    if (!registry_) {
        return 0;
    }
    return registry_->evict_stale_channels(lease_timeout_);
}

void ConnectionLifecycleManager::reaper_loop() {
    while (running_.load(std::memory_order_relaxed)) {
        {
            std::unique_lock<std::mutex> lock(cv_mutex_);
            cv_.wait_for(lock, reaper_interval_, [this] { return !running_.load(std::memory_order_relaxed); });
        }

        if (!running_.load(std::memory_order_relaxed)) {
            break;
        }

        try {
            sweep_stale_connections();
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [ConnectionLifecycleManager] Exception in reaper loop: " << ex.what() << "\n";
        }
    }
}

void ConnectionLifecycleManager::on_registry_disconnect(const domain::DeviceId& device_id) {
    domain::UserId uid;
    bool had_session = false;

    {
        std::lock_guard<std::mutex> lock(session_mutex_);
        auto it = sessions_.find(device_id);
        if (it != sessions_.end()) {
            uid = it->second.user_id;
            sessions_.erase(it);
            had_session = true;
        }
    }

    if (had_session && presence_coordinator_) {
        presence_coordinator_->on_device_disconnected(uid, device_id);
    }
}

void ConnectionLifecycleManager::register_connected_callback(DeviceConnectedCallback cb) {
    if (!cb) {
        return;
    }
    std::lock_guard<std::mutex> lock(callback_mutex_);
    connected_callbacks_.push_back(std::move(cb));
}

} // namespace securecloud::messaging::delivery
