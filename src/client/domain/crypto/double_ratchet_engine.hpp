#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/crypto/ratchet_state.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <span>
#include <string_view>

namespace securecloud::client::domain::crypto {

class DoubleRatchetEngine {
  public:
    static constexpr std::string_view kRootRatchetInfo = "SecureCloud-RootRatchet-v1";
    static constexpr std::string_view kChainRatchetInfo = "SecureCloud-MessageKey-v1";

    static application::ClientResult<RatchetState>
    initialize_alice(application::interfaces::ICryptoProvider& crypto,
                     const securecloud::common::configuration::SecretString& shared_secret,
                     std::span<const uint8_t> bob_dh_pub);

    static application::ClientResult<RatchetState>
    initialize_bob(application::interfaces::ICryptoProvider& crypto,
                   const securecloud::common::configuration::SecretString& shared_secret,
                   application::interfaces::DhKeyPair bob_dh_keypair);

    static application::ClientResult<DoubleRatchetMessage>
    ratchet_encrypt(application::interfaces::ICryptoProvider& crypto, RatchetState& state,
                    std::span<const uint8_t> plaintext);

    static application::ClientResult<securecloud::common::configuration::SecretString>
    ratchet_decrypt(application::interfaces::ICryptoProvider& crypto, RatchetState& state,
                    const DoubleRatchetMessage& message);
};

} // namespace securecloud::client::domain::crypto
