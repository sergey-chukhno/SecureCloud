#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "domain/crypto/sender_key_models.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstdint>
#include <span>
#include <string_view>

namespace securecloud::client::domain::crypto {

class SenderKeyEngine {
  public:
    static constexpr std::string_view kChainStepInfo = "SecureCloud-SenderKey-Step-v1";
    static constexpr uint32_t kMaxGroupSkip = 500;

    static application::ClientResult<SenderKeyState> create_sender_key(const SenderKeyId& id);

    static application::ClientResult<SenderKeyDistributionMessage>
    create_distribution_message(const SenderKeyState& state);

    static application::ClientResult<SenderKeyState>
    process_distribution_message(const SenderKeyDistributionMessage& distribution);

    static application::ClientResult<GroupEncryptedEnvelope> encrypt(application::interfaces::ICryptoProvider& crypto,
                                                                     SenderKeyState& state,
                                                                     std::span<const uint8_t> plaintext);

    static application::ClientResult<common::configuration::SecretString>
    decrypt(application::interfaces::ICryptoProvider& crypto, SenderKeyState& state,
            const GroupEncryptedEnvelope& envelope);
};

} // namespace securecloud::client::domain::crypto
