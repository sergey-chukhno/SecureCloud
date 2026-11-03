#pragma once

#include "application/client_error.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/device_id.hpp"

#include <string>
#include <string_view>

namespace securecloud::client::application::interfaces {

class ICryptoProvider {
  public:
    virtual ~ICryptoProvider() = default;

    virtual ClientResult<domain::CryptoIdentity> generate_device_identity() = 0;
    virtual ClientResult<std::string> encrypt_message(const domain::DeviceId& recipient_device,
                                                      std::string_view plaintext) = 0;
    virtual ClientResult<std::string> decrypt_message(const domain::DeviceId& sender_device,
                                                      std::string_view ciphertext) = 0;
    virtual ClientResult<bool> verify_identity_fingerprint(const domain::DeviceId& device,
                                                           std::string_view fingerprint) = 0;
};

} // namespace securecloud::client::application::interfaces
