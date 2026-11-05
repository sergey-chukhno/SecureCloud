#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "application/interfaces/i_secure_storage.hpp"

namespace securecloud::client::application::managers {

class EmergencyManager {
  public:
    EmergencyManager(interfaces::ILocalStore& local_store, interfaces::ISecureStorage& secure_storage);
    ~EmergencyManager() = default;

    EmergencyManager(const EmergencyManager&) = delete;
    EmergencyManager& operator=(const EmergencyManager&) = delete;

    ClientResult<void> trigger_emergency_wipe();
    [[nodiscard]] bool is_wiped() const noexcept { return is_wiped_; }

  private:
    interfaces::ILocalStore& local_store_;
    interfaces::ISecureStorage& secure_storage_;
    bool is_wiped_{false};
};

} // namespace securecloud::client::application::managers
