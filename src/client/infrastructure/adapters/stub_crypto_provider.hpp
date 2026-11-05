#pragma once

#include "application/interfaces/i_crypto_provider.hpp"

namespace securecloud::client::infrastructure::adapters {

class StubCryptoProvider final : public application::interfaces::ICryptoProvider {
  public:
    StubCryptoProvider() = default;
    ~StubCryptoProvider() override = default;

    application::ClientResult<domain::CryptoIdentity> generate_device_identity() override;
    application::ClientResult<std::string> encrypt_message(const domain::DeviceId& recipient_device,
                                                           std::string_view plaintext) override;
    application::ClientResult<std::string> decrypt_message(const domain::DeviceId& sender_device,
                                                           std::string_view ciphertext) override;
    application::ClientResult<bool> verify_identity_fingerprint(const domain::DeviceId& device,
                                                                std::string_view fingerprint) override;
};

} // namespace securecloud::client::infrastructure::adapters
