#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/device_id.hpp"
#include "domain/device_private_bundle.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <string>
#include <string_view>

namespace securecloud::client::infrastructure::adapters {

class KeyStorageHelper {
  public:
    static std::string make_storage_key(const domain::DeviceId& device_id);

    static application::ClientResult<securecloud::common::configuration::SecretString>
    serialize(const domain::DevicePrivateBundle& bundle);

    static application::ClientResult<domain::DevicePrivateBundle>
    deserialize(const securecloud::common::configuration::SecretString& serialized_data);

    static application::ClientResult<void> save_bundle(application::interfaces::ISecureStorage& storage,
                                                       const domain::DevicePrivateBundle& bundle);

    static application::ClientResult<domain::DevicePrivateBundle>
    load_bundle(application::interfaces::ISecureStorage& storage, const domain::DeviceId& device_id);

    static application::ClientResult<bool> has_bundle(application::interfaces::ISecureStorage& storage,
                                                      const domain::DeviceId& device_id);

    static application::ClientResult<void> remove_one_time_prekey(application::interfaces::ISecureStorage& storage,
                                                                  const domain::DeviceId& device_id,
                                                                  std::string_view prekey_id);

    static application::ClientResult<void> wipe_device_keys(application::interfaces::ISecureStorage& storage,
                                                            const domain::DeviceId& device_id);
};

} // namespace securecloud::client::infrastructure::adapters
