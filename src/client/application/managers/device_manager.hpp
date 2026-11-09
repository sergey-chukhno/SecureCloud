#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "application/managers/prekey_lifecycle_coordinator.hpp"
#include "domain/device.hpp"
#include "domain/device_id.hpp"
#include "domain/user_id.hpp"

#include <optional>
#include <string_view>
#include <vector>

namespace securecloud::client::application::managers {

class DeviceManager {
  public:
    DeviceManager(interfaces::IGatewayClient& gateway, interfaces::ISecureStorage& secure_storage,
                  interfaces::ICryptoProvider& crypto_provider);
    ~DeviceManager() = default;

    DeviceManager(const DeviceManager&) = delete;
    DeviceManager& operator=(const DeviceManager&) = delete;

    ClientResult<domain::Device> initialize_or_load_device(const domain::UserId& user_id,
                                                           std::string_view display_name = "");

    ClientResult<domain::Device> register_device(const domain::UserId& user_id,
                                                 std::string_view display_name = "");

    [[nodiscard]] ClientResult<domain::Device> get_local_device() const;

    ClientResult<domain::PrekeyInventoryStatus> check_prekey_inventory();

    ClientResult<std::size_t> replenish_prekeys(
        std::size_t batch_size = domain::PrekeyPolicy::kReplenishmentBatchSize);

    ClientResult<void> rotate_signed_prekey();

    ClientResult<bool> reconcile_prekeys();

    ClientResult<std::vector<domain::Device>> list_devices();

    ClientResult<void> revoke_device(const domain::DeviceId& device_id);

    [[nodiscard]] interfaces::ISecureStorage& secure_storage() noexcept { return secure_storage_; }
    [[nodiscard]] interfaces::ICryptoProvider& crypto_provider() noexcept { return crypto_provider_; }
    [[nodiscard]] PrekeyLifecycleCoordinator& prekey_coordinator() noexcept { return coordinator_; }

  private:
    interfaces::IGatewayClient& gateway_;
    interfaces::ISecureStorage& secure_storage_;
    interfaces::ICryptoProvider& crypto_provider_;
    PrekeyLifecycleCoordinator coordinator_;

    std::optional<domain::Device> local_device_;
};

} // namespace securecloud::client::application::managers
