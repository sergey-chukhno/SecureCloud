#include "application/managers/emergency_manager.hpp"

namespace securecloud::client::application::managers {

EmergencyManager::EmergencyManager(interfaces::ILocalStore& local_store, interfaces::ISecureStorage& secure_storage)
    : local_store_(local_store), secure_storage_(secure_storage) {}

ClientResult<void> EmergencyManager::trigger_emergency_wipe() {
    is_wiped_ = true;
    (void)local_store_.close();
    (void)secure_storage_.delete_secret("session_auth_token");
    (void)secure_storage_.delete_secret("device_private_identity_key");
    return ClientResult<void>::ok();
}

} // namespace securecloud::client::application::managers
