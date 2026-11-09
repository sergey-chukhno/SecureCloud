#pragma once

#include "application/interfaces/i_crypto_provider.hpp"

namespace securecloud::client::infrastructure::adapters {

class OpenSslCryptoProvider final : public application::interfaces::ICryptoProvider {
  public:
    OpenSslCryptoProvider() = default;
    ~OpenSslCryptoProvider() override = default;

    OpenSslCryptoProvider(const OpenSslCryptoProvider&) = delete;
    OpenSslCryptoProvider& operator=(const OpenSslCryptoProvider&) = delete;

    application::ClientResult<application::interfaces::IdentityKeyPair> generate_identity_keypair() override;

    application::ClientResult<application::interfaces::SignedPrekeyResult>
    generate_signed_prekey(const securecloud::common::configuration::SecretString& identity_private_key) override;

    application::ClientResult<bool> verify_signed_prekey(std::span<const uint8_t> identity_public_key,
                                                         std::span<const uint8_t> signed_prekey_public_key,
                                                         std::span<const uint8_t> signature) override;

    application::ClientResult<std::vector<application::interfaces::OneTimePrekeyPair>>
    generate_one_time_prekeys(std::size_t count, std::size_t start_index = 1) override;

    application::ClientResult<std::string>
    compute_identity_fingerprint(std::span<const uint8_t> identity_public_key) override;

    application::ClientResult<domain::CryptoIdentity> generate_device_identity() override;

    application::ClientResult<std::string> encrypt_message(const domain::DeviceId& recipient_device,
                                                           std::string_view plaintext) override;

    application::ClientResult<std::string> decrypt_message(const domain::DeviceId& sender_device,
                                                           std::string_view ciphertext) override;

    application::ClientResult<bool> verify_identity_fingerprint(const domain::DeviceId& device,
                                                                std::string_view fingerprint) override;
};

} // namespace securecloud::client::infrastructure::adapters
