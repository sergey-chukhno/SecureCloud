#include "application/managers/device_manager.hpp"

namespace securecloud::client::application::managers {

DeviceManager::DeviceManager(interfaces::IGatewayClient& gateway, interfaces::ISecureStorage& secure_storage)
    : gateway_(gateway), secure_storage_(secure_storage) {}

ClientResult<std::vector<domain::Device>> DeviceManager::list_devices() {
    const auto probe_res = gateway_.probe_gateway("/health");
    if (probe_res.is_error()) {
        return ClientResult<std::vector<domain::Device>>::error(probe_res.error());
    }
    return ClientResult<std::vector<domain::Device>>::ok(std::vector<domain::Device>{});
}

ClientResult<void> DeviceManager::revoke_device(const domain::DeviceId& device_id) {
    if (device_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Device ID cannot be empty"));
    }
    return ClientResult<void>::ok();
}

} // namespace securecloud::client::application::managers
