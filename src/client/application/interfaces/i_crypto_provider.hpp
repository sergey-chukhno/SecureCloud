#pragma once

#include "application/client_error.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/device_id.hpp"
#include "domain/one_time_prekey_record.hpp"
#include "domain/user_id.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::application::interfaces {

struct IdentityKeyPair {
    std::vector<uint8_t> public_key;
    securecloud::common::configuration::SecretString private_key;
};

struct SignedPrekeyResult {
    std::vector<uint8_t> public_key;
    securecloud::common::configuration::SecretString private_key;
    std::vector<uint8_t> signature;
};

struct OneTimePrekeyPair {
    domain::OneTimePrekeyRecord record;
    securecloud::common::configuration::SecretString private_key;
};

struct DhKeyPair {
    std::vector<uint8_t> public_key;
    securecloud::common::configuration::SecretString private_key;
};

struct AeadCiphertext {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> auth_tag;
};

class ICryptoProvider {
  public:
    virtual ~ICryptoProvider() = default;

    virtual ClientResult<IdentityKeyPair> generate_identity_keypair() = 0;

    virtual ClientResult<SignedPrekeyResult>
    generate_signed_prekey(const securecloud::common::configuration::SecretString& identity_private_key) = 0;

    virtual ClientResult<bool> verify_signed_prekey(std::span<const uint8_t> identity_public_key,
                                                    std::span<const uint8_t> signed_prekey_public_key,
                                                    std::span<const uint8_t> signature) = 0;

    virtual ClientResult<std::vector<OneTimePrekeyPair>> generate_one_time_prekeys(std::size_t count,
                                                                                   std::size_t start_index = 1) = 0;

    virtual ClientResult<std::string> compute_identity_fingerprint(std::span<const uint8_t> identity_public_key) = 0;

    virtual ClientResult<domain::CryptoIdentity> generate_device_identity() = 0;

    virtual ClientResult<std::string> encrypt_message(const domain::DeviceId& recipient_device,
                                                      std::string_view plaintext) = 0;

    virtual ClientResult<std::string> decrypt_message(const domain::DeviceId& sender_device,
                                                      std::string_view ciphertext) = 0;

    virtual ClientResult<bool> verify_identity_fingerprint(const domain::DeviceId& device,
                                                           std::string_view fingerprint) = 0;

    virtual ClientResult<DhKeyPair> generate_dh_keypair() = 0;

    virtual ClientResult<securecloud::common::configuration::SecretString>
    diffie_hellman(const securecloud::common::configuration::SecretString& our_private_key,
                   std::span<const uint8_t> peer_public_key) = 0;

    virtual ClientResult<securecloud::common::configuration::SecretString>
    hkdf_extract(std::span<const uint8_t> salt, const securecloud::common::configuration::SecretString& ikm) = 0;

    virtual ClientResult<securecloud::common::configuration::SecretString>
    hkdf_expand(const securecloud::common::configuration::SecretString& prk, std::span<const uint8_t> info,
                std::size_t length) = 0;

    virtual ClientResult<securecloud::common::configuration::SecretString>
    hkdf_extract_and_expand(std::span<const uint8_t> salt, const securecloud::common::configuration::SecretString& ikm,
                            std::span<const uint8_t> info, std::size_t length) = 0;

    virtual ClientResult<AeadCiphertext> encrypt_aes_gcm(const securecloud::common::configuration::SecretString& key,
                                                         std::span<const uint8_t> iv,
                                                         std::span<const uint8_t> plaintext,
                                                         std::span<const uint8_t> associated_data = {}) = 0;

    virtual ClientResult<securecloud::common::configuration::SecretString>
    decrypt_aes_gcm(const securecloud::common::configuration::SecretString& key, std::span<const uint8_t> iv,
                    std::span<const uint8_t> ciphertext, std::span<const uint8_t> auth_tag,
                    std::span<const uint8_t> associated_data = {}) = 0;

    virtual ClientResult<std::string> compute_safety_number(const domain::UserId& local_user_id,
                                                            std::span<const uint8_t> local_identity_key,
                                                            const domain::UserId& peer_user_id,
                                                            std::span<const uint8_t> peer_identity_key) = 0;
};

} // namespace securecloud::client::application::interfaces
