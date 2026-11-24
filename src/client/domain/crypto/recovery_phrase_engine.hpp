#pragma once

#include "application/client_error.hpp"
#include "domain/crypto/bip39_wordlist.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace securecloud::client::domain::crypto {

enum class RecoveryPhraseLength {
    Words12 = 128,
    Words24 = 256,
};

struct RecoveryVerificationChallenge {
    std::vector<std::size_t> word_indices{}; // 0-based, distinct, strictly ascending

    bool operator==(const RecoveryVerificationChallenge& other) const noexcept = default;
};

/// Endpoint-only BIP-39 mnemonic generator, validator, challenge verifier, and PBKDF2-HMAC-SHA512 seed deriver.
/// Lives inside `securecloud_client_domain` with zero network or storage dependencies (`ADR-008 §27, §28`).
class RecoveryPhraseEngine final {
  public:
    static constexpr std::size_t kEntropyBytes12 = 16U;
    static constexpr std::size_t kEntropyBytes24 = 32U;
    static constexpr std::size_t kWordCount12 = 12U;
    static constexpr std::size_t kWordCount24 = 24U;
    static constexpr std::size_t kSeedBytes = 64U;
    static constexpr int kBip39Pbkdf2Iterations = 2048;
    static constexpr uint32_t kVerifierPbkdf2Iterations = 100000U;
    static constexpr uint32_t kMaxVerifierPbkdf2Iterations = 5000000U;
    static constexpr std::size_t kVerifierSaltBytes = 16U;
    static constexpr std::size_t kVerifierDigestBytes = 32U;
    static constexpr std::string_view kVerifierPrefix = "sc-bip39-v1";

    [[nodiscard]] static application::ClientResult<common::configuration::SecretString>
    generate_mnemonic(RecoveryPhraseLength length = RecoveryPhraseLength::Words12);

    [[nodiscard]] static application::ClientResult<common::configuration::SecretString>
    entropy_to_mnemonic(std::span<const uint8_t> entropy);

    [[nodiscard]] static application::ClientResult<bool>
    validate_mnemonic(const common::configuration::SecretString& mnemonic);

    [[nodiscard]] static application::ClientResult<std::vector<uint8_t>> derive_recovery_seed(
        const common::configuration::SecretString& mnemonic,
        const common::configuration::SecretString& passphrase = common::configuration::SecretString(""));

    [[nodiscard]] static application::ClientResult<std::string>
    compute_salted_verification_digest(const common::configuration::SecretString& mnemonic);

    [[nodiscard]] static application::ClientResult<bool>
    verify_against_digest(const common::configuration::SecretString& mnemonic, std::string_view stored_digest);

    [[nodiscard]] static application::ClientResult<RecoveryVerificationChallenge>
    build_challenge(std::size_t word_count, std::size_t sample_count = 3U);

    [[nodiscard]] static application::ClientResult<bool>
    verify_challenge_words(const common::configuration::SecretString& mnemonic,
                           const std::vector<std::pair<std::size_t, std::string>>& answers);
};

} // namespace securecloud::client::domain::crypto
