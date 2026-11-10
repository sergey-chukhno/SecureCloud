#pragma once

#include "application/interfaces/i_crypto_provider.hpp"

namespace securecloud::client::infrastructure::adapters {

class StubCryptoProvider final : public application::interfaces::ICryptoProvider {
  public:
    StubCryptoProvider() = default;
    ~StubCryptoProvider() override = default;

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

    application::ClientResult<application::interfaces::DhKeyPair> generate_dh_keypair() override;

    application::ClientResult<securecloud::common::configuration::SecretString>
    diffie_hellman(const securecloud::common::configuration::SecretString& our_private_key,
                   std::span<const uint8_t> peer_public_key) override;

    application::ClientResult<securecloud::common::configuration::SecretString>
    hkdf_extract(std::span<const uint8_t> salt, const securecloud::common::configuration::SecretString& ikm) override;

    application::ClientResult<securecloud::common::configuration::SecretString>
    hkdf_expand(const securecloud::common::configuration::SecretString& prk, std::span<const uint8_t> info,
                std::size_t length) override;

    application::ClientResult<securecloud::common::configuration::SecretString>
    hkdf_extract_and_expand(std::span<const uint8_t> salt, const securecloud::common::configuration::SecretString& ikm,
                            std::span<const uint8_t> info, std::size_t length) override;

    application::ClientResult<application::interfaces::AeadCiphertext>
    encrypt_aes_gcm(const securecloud::common::configuration::SecretString& key, std::span<const uint8_t> iv,
                    std::span<const uint8_t> plaintext, std::span<const uint8_t> associated_data = {}) override;

    application::ClientResult<securecloud::common::configuration::SecretString>
    decrypt_aes_gcm(const securecloud::common::configuration::SecretString& key, std::span<const uint8_t> iv,
                    std::span<const uint8_t> ciphertext, std::span<const uint8_t> auth_tag,
                    std::span<const uint8_t> associated_data = {}) override;

    application::ClientResult<std::string> compute_safety_number(const domain::UserId& local_user_id,
                                                                 std::span<const uint8_t> local_identity_key,
                                                                 const domain::UserId& peer_user_id,
                                                                 std::span<const uint8_t> peer_identity_key) override;

    application::ClientResult<application::interfaces::DhKeyPair> generate_dh_keypair() override;

    application::ClientResult<securecloud::common::configuration::SecretString>
    diffie_hellman(const securecloud::common::configuration::SecretString& our_private_key,
                   std::span<const uint8_t> peer_public_key) override;

    application::ClientResult<securecloud::common::configuration::SecretString>
    hkdf_extract(std::span<const uint8_t> salt,
                 const securecloud::common::configuration::SecretString& ikm) override;

    application::ClientResult<securecloud::common::configuration::SecretString>
    hkdf_expand(const securecloud::common::configuration::SecretString& prk,
                std::span<const uint8_t> info,
                std::size_t length) override;

    application::ClientResult<securecloud::common::configuration::SecretString>
    hkdf_extract_and_expand(std::span<const uint8_t> salt,
                            const securecloud::common::configuration::SecretString& ikm,
                            std::span<const uint8_t> info,
                            std::size_t length) override;

    application::ClientResult<application::interfaces::AeadCiphertext>
    encrypt_aes_gcm(const securecloud::common::configuration::SecretString& key,
                    std::span<const uint8_t> iv,
                    std::span<const uint8_t> plaintext,
                    std::span<const uint8_t> associated_data = {}) override;

    application::ClientResult<securecloud::common::configuration::SecretString>
    decrypt_aes_gcm(const securecloud::common::configuration::SecretString& key,
                    std::span<const uint8_t> iv,
                    std::span<const uint8_t> ciphertext,
                    std::span<const uint8_t> auth_tag,
                    std::span<const uint8_t> associated_data = {}) override;

    application::ClientResult<std::string>
    compute_safety_number(const domain::UserId& local_user_id,
                          std::span<const uint8_t> local_identity_key,
                          const domain::UserId& peer_user_id,
                          std::span<const uint8_t> peer_identity_key) override;
};

} // namespace securecloud::client::infrastructure::adapters
