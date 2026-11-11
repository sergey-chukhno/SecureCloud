#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "domain/crypto/x3dh_models.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/prekey_bundle.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace securecloud::client::domain::crypto {

class X3dhEngine {
  public:
    static constexpr std::string_view kX3dhInfoLabel = "SecureCloud-X3DH-v1";

    static application::ClientResult<X3dhInitiatorResult>
    initiate_handshake(application::interfaces::ICryptoProvider& crypto,
                       const domain::DevicePrivateBundle& local_bundle,
                       const application::interfaces::DeviceCryptoDirectoryEntry& peer_bundle);

    static application::ClientResult<X3dhInitiatorResult>
    initiate_handshake(application::interfaces::ICryptoProvider& crypto,
                       const domain::DevicePrivateBundle& local_bundle, const domain::PrekeyBundle& peer_bundle,
                       std::optional<std::string> chosen_otpk_id = std::nullopt);

    static application::ClientResult<X3dhResponderResult>
    process_handshake(application::interfaces::ICryptoProvider& crypto, domain::DevicePrivateBundle& local_bundle,
                      const X3dhHeader& header);
};

} // namespace securecloud::client::domain::crypto
