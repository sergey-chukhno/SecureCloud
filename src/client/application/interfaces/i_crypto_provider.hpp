#pragma once

#include "application/client_error.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/device_id.hpp"
#include "domain/one_time_prekey_record.hpp"
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
};

} // namespace securecloud::client::application::interfaces
