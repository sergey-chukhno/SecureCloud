#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/device.hpp"
#include "domain/device_id.hpp"

#include <vector>

namespace securecloud::client::application::managers {

class DeviceManager {
  public:
    DeviceManager(interfaces::IGatewayClient& gateway, interfaces::ISecureStorage& secure_storage);
    ~DeviceManager() = default;

    DeviceManager(const DeviceManager&) = delete;
    DeviceManager& operator=(const DeviceManager&) = delete;

    ClientResult<std::vector<domain::Device>> list_devices();
    ClientResult<void> revoke_device(const domain::DeviceId& device_id);

    [[nodiscard]] interfaces::ISecureStorage& secure_storage() noexcept { return secure_storage_; }

  private:
    interfaces::IGatewayClient& gateway_;
    interfaces::ISecureStorage& secure_storage_;
};

} // namespace securecloud::client::application::managers
