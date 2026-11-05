#pragma once

#include "application/client_config.hpp"
#include "application/client_error.hpp"
#include "application/interfaces/i_gateway_client.hpp"

#include <atomic>

namespace securecloud::client::application::managers {

class SyncManager {
  public:
    SyncManager(interfaces::IGatewayClient& gateway, const ClientConfig& config);
    ~SyncManager() = default;

    SyncManager(const SyncManager&) = delete;
    SyncManager& operator=(const SyncManager&) = delete;

    ClientResult<void> start_sync();
    ClientResult<void> stop_sync();
    [[nodiscard]] bool is_syncing() const noexcept { return is_syncing_.load(); }
    [[nodiscard]] const ClientConfig& config() const noexcept { return config_; }

    ClientResult<std::size_t> poll_sync();

  private:
    interfaces::IGatewayClient& gateway_;
    const ClientConfig& config_;
    std::atomic<bool> is_syncing_{false};
};

} // namespace securecloud::client::application::managers
