#pragma once

#include "application/client_config.hpp"
#include "application/client_error.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "domain/conversation_id.hpp"
#include "domain/device_id.hpp"

#include <atomic>
#include <cstdint>
#include <unordered_map>

namespace securecloud::client::application::managers {

class MessagingManager;

class SyncManager {
  public:
    SyncManager(interfaces::IGatewayClient& gateway, const ClientConfig& config);
    ~SyncManager() = default;

    SyncManager(const SyncManager&) = delete;
    SyncManager& operator=(const SyncManager&) = delete;

    void set_messaging_manager(MessagingManager* messaging_manager) noexcept;
    ClientResult<void> start_sync();
    ClientResult<void> stop_sync();
    [[nodiscard]] bool is_syncing() const noexcept { return is_syncing_.load(); }
    [[nodiscard]] const ClientConfig& config() const noexcept { return config_; }

    ClientResult<std::size_t> poll_sync();
    ClientResult<std::size_t> poll_realtime_updates(const domain::DeviceId& local_device_id);
    [[nodiscard]] uint64_t conversation_cursor(const domain::ConversationId& conversation_id) const;

  private:
    interfaces::IGatewayClient& gateway_;
    const ClientConfig& config_;
    MessagingManager* messaging_manager_{nullptr};
    std::atomic<bool> is_syncing_{false};
    std::unordered_map<domain::ConversationId, uint64_t> conversation_cursors_;
};

} // namespace securecloud::client::application::managers
