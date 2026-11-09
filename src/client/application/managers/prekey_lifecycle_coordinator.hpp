#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/device_id.hpp"
#include "domain/prekey_inventory_status.hpp"
#include "domain/prekey_policy.hpp"

namespace securecloud::client::application::managers {

class PrekeyLifecycleCoordinator {
  public:
    PrekeyLifecycleCoordinator(interfaces::IGatewayClient& gateway, interfaces::ISecureStorage& secure_storage,
                               interfaces::ICryptoProvider& crypto_provider);
    ~PrekeyLifecycleCoordinator() = default;

    PrekeyLifecycleCoordinator(const PrekeyLifecycleCoordinator&) = delete;
    PrekeyLifecycleCoordinator& operator=(const PrekeyLifecycleCoordinator&) = delete;

    ClientResult<domain::PrekeyInventoryStatus> check_inventory(const domain::DeviceId& device_id);

    ClientResult<std::size_t> replenish_one_time_prekeys(
        const domain::DeviceId& device_id,
        std::size_t batch_size = domain::PrekeyPolicy::kReplenishmentBatchSize);

    ClientResult<void> rotate_signed_prekey(const domain::DeviceId& device_id);

    ClientResult<bool> reconcile_prekeys(const domain::DeviceId& device_id);

  private:
    interfaces::IGatewayClient& gateway_;
    interfaces::ISecureStorage& secure_storage_;
    interfaces::ICryptoProvider& crypto_provider_;
};

} // namespace securecloud::client::application::managers

