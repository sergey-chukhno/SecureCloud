#pragma once

#include "application/client_config.hpp"
#include "application/client_error.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "domain/conversation_id.hpp"
#include "domain/device_id.hpp"
#include "domain/offline_sync_models.hpp"
#include "domain/user_id.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>

namespace securecloud::client::application::managers {

class ContactManager;
class FileManager;
class MessagingManager;

class SyncManager {
  public:
    using ConnectivityStateCallback = std::function<void(domain::ConnectivityState)>;

    SyncManager(interfaces::IGatewayClient& gateway, const ClientConfig& config);
    ~SyncManager() = default;

    SyncManager(const SyncManager&) = delete;
    SyncManager& operator=(const SyncManager&) = delete;

    void set_local_store(interfaces::ILocalStore* local_store) noexcept;
    void set_messaging_manager(MessagingManager* messaging_manager) noexcept;
    void set_contact_manager(ContactManager* contact_manager) noexcept;
    void set_file_manager(FileManager* file_manager) noexcept;
    void set_local_identity(const domain::UserId& user_id, const domain::DeviceId& device_id);

    ClientResult<void> start_sync();
    ClientResult<void> stop_sync();
    [[nodiscard]] bool is_syncing() const noexcept { return is_syncing_.load(); }
    [[nodiscard]] const ClientConfig& config() const noexcept { return config_; }

    // Connectivity Observer & State Machine (CLIENT-012-T04)
    [[nodiscard]] domain::ConnectivityState connectivity_state() const noexcept;
    [[nodiscard]] bool is_simulated_offline() const noexcept { return simulated_offline_.load(); }
    uint64_t subscribe_connectivity_state(ConnectivityStateCallback callback);
    void unsubscribe_connectivity_state(uint64_t subscription_id);
    ClientResult<domain::ConnectivityState> set_simulated_offline(bool offline);
    ClientResult<domain::ConnectivityState> check_connectivity();

    // 4-Phase Catch-Up Synchronization & Reconciliation (CLIENT-012-T04)
    ClientResult<domain::CatchUpSyncReport> execute_catch_up_sync(const domain::UserId& local_user_id = {},
                                                                  const domain::DeviceId& local_device_id = {},
                                                                  std::size_t page_limit = 50,
                                                                  std::size_t max_pages_per_conversation = 100);

    ClientResult<std::size_t> poll_sync();
    ClientResult<std::size_t> poll_realtime_updates(const domain::DeviceId& local_device_id);
    [[nodiscard]] uint64_t conversation_cursor(const domain::ConversationId& conversation_id) const;

  private:
    bool transition_connectivity_state(domain::ConnectivityState next_state);
    void hydrate_local_cursors(const domain::DeviceId& device_id);
    void persist_local_cursor(const domain::DeviceId& device_id, const domain::ConversationId& conversation_id,
                              uint64_t sequence);

    interfaces::IGatewayClient& gateway_;
    const ClientConfig& config_;
    interfaces::ILocalStore* local_store_{nullptr};
    MessagingManager* messaging_manager_{nullptr};
    ContactManager* contact_manager_{nullptr};
    FileManager* file_manager_{nullptr};

    mutable std::mutex state_mutex_;
    domain::UserId local_user_id_;
    domain::DeviceId local_device_id_;
    domain::ConnectivityState connectivity_state_{domain::ConnectivityState::Online};
    std::atomic<bool> is_syncing_{false};
    std::atomic<bool> simulated_offline_{false};
    uint64_t next_connectivity_sub_id_{1};
    std::unordered_map<uint64_t, ConnectivityStateCallback> connectivity_subscribers_;
    std::unordered_map<domain::ConversationId, uint64_t> conversation_cursors_;
};

} // namespace securecloud::client::application::managers
