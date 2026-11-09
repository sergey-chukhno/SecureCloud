#include "application/managers/sync_manager.hpp"

namespace securecloud::client::application::managers {

SyncManager::SyncManager(interfaces::IGatewayClient& gateway, const ClientConfig& config)
    : gateway_(gateway), config_(config) {}

ClientResult<void> SyncManager::start_sync() {
    is_syncing_.store(true);
    return ClientResult<void>::ok();
}

ClientResult<void> SyncManager::stop_sync() {
    is_syncing_.store(false);
    return ClientResult<void>::ok();
}

ClientResult<std::size_t> SyncManager::poll_sync() {
    if (!is_syncing_.load()) {
        return ClientResult<std::size_t>::ok(0);
    }
    const auto sync_res = gateway_.sync_messages("");
    if (sync_res.is_error()) {
        return ClientResult<std::size_t>::error(sync_res.error());
    }
    return ClientResult<std::size_t>::ok(sync_res.value().size());
}

} // namespace securecloud::client::application::managers
