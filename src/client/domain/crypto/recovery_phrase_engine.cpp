#include "domain/crypto/recovery_phrase_engine.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <set>

namespace securecloud::client::domain::crypto {
namespace {

using common::configuration::SecretString;

template <typename ByteContainer> class ByteCleanseGuard final {
  public:
    explicit ByteCleanseGuard(ByteContainer& target) noexcept : target_(target) {}
    ~ByteCleanseGuard() {
        if (!target_.empty()) {
            OPENSSL_cleanse(target_.data(), target_.size() * sizeof(typename ByteContainer::value_type));
        }
    }

    ByteCleanseGuard(const ByteCleanseGuard&) = delete;
    ByteCleanseGuard& operator=(const ByteCleanseGuard&) = delete;

  private:
    ByteContainer& target_;
};

class WordVectorCleanseGuard final {
  public:
    explicit WordVectorCleanseGuard(std::vector<std::string>& words) noexcept : words_(words) {}
    ~WordVectorCleanseGuard() {
        for (std::string& w : words_) {
            if (!w.empty()) {
                OPENSSL_cleanse(w.data(), w.size());
            }
        }
    }

    WordVectorCleanseGuard(const WordVectorCleanseGuard&) = delete;
    WordVectorCleanseGuard& operator=(const WordVectorCleanseGuard&) = delete;

  private:
    std::vector<std::string>& words_;
};

[[nodiscard]] bool is_ascii_whitespace(char ch) noexcept {
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

[[nodiscard]] std::string to_lower_trimmed_ascii(std::string_view input) {
    std::size_t start = 0U;
    std::size_t end = input.size();
    while (start < end && is_ascii_whitespace(input[start])) {
        ++start;
    }
    while (end > start && is_ascii_whitespace(input[end - 1U])) {
        --end;
    }

    std::string out;
    out.reserve(end - start);
    for (std::size_t i = start; i < end; ++i) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(input[i]))));
    }
    return out;
}

[[nodiscard]] bool split_normalized_words(const SecretString& mnemonic, std::vector<std::string>& out_words) {
    out_words.clear();
    const std::string& raw = mnemonic.expose_unredacted_secret();
    std::string current;
    ByteCleanseGuard<std::string> current_guard(current);

    for (const char ch : raw) {
        if (is_ascii_whitespace(ch)) {
            if (!current.empty()) {
                out_words.push_back(current);
                OPENSSL_cleanse(current.data(), current.size());
                current.clear();
            }
            continue;
        }
        const auto uch = static_cast<unsigned char>(ch);
        if (uch < 0x20U || uch == 0x7FU) {
            return false;
        }
        current.push_back(static_cast<char>(std::tolower(uch)));
    }
    if (!current.empty()) {
        out_words.push_back(current);
        OPENSSL_cleanse(current.data(), current.size());
        current.clear();
    }
    return true;
}

[[nodiscard]] std::string join_words(const std::vector<std::string>& words) {
    std::size_t total = words.empty() ? 0U : (words.size() - 1U);
    for (const std::string& w : words) {
        total += w.size();
    }
    std::string joined;
    joined.reserve(total);
    for (std::size_t i = 0U; i < words.size(); ++i) {
        if (i > 0U) {
            joined.push_back(' ');
        }
        joined.append(words[i]);
    }
    return joined;
}

[[nodiscard]] bool validate_and_normalize_phrase(const SecretString& mnemonic, std::vector<std::string>& out_words) {
    if (!split_normalized_words(mnemonic, out_words)) {
        return false;
    }

    const std::size_t word_count = out_words.size();
    if (word_count != RecoveryPhraseEngine::kWordCount12 && word_count != RecoveryPhraseEngine::kWordCount24) {
        return false;
    }

    const bool is_12 = (word_count == RecoveryPhraseEngine::kWordCount12);
    const std::size_t entropy_bytes =
        is_12 ? RecoveryPhraseEngine::kEntropyBytes12 : RecoveryPhraseEngine::kEntropyBytes24;
    const uint8_t checksum_mask = is_12 ? 0xF0U : 0xFFU;

    std::vector<uint16_t> indices;
    indices.reserve(word_count);
    ByteCleanseGuard<std::vector<uint16_t>> idx_guard(indices);

    for (const std::string& w : out_words) {
        const auto idx_opt = find_bip39_word_index(w);
        if (!idx_opt.has_value()) {
            return false;
        }
        indices.push_back(*idx_opt);
    }

    std::vector<uint8_t> entropy(entropy_bytes, 0U);
    ByteCleanseGuard<std::vector<uint8_t>> entropy_guard(entropy);
    uint8_t actual_cs = 0U;

    for (std::size_t w = 0U; w < word_count; ++w) {
        for (std::size_t bit = 0U; bit < 11U; ++bit) {
            const std::size_t abs_bit = w * 11U + bit;
            const std::size_t byte_idx = abs_bit / 8U;
            const std::size_t bit_in_byte = 7U - (abs_bit % 8U);
            const uint8_t bit_val = static_cast<uint8_t>((indices[w] >> (10U - bit)) & 0x01U);
            if (byte_idx < entropy.size()) {
                const auto shifted = static_cast<uint8_t>(bit_val << bit_in_byte);
                entropy[byte_idx] = static_cast<uint8_t>(entropy[byte_idx] | shifted);
            } else {
                actual_cs = static_cast<uint8_t>(actual_cs | static_cast<uint8_t>(bit_val << bit_in_byte));
            }
        }
    }

    std::array<uint8_t, EVP_MAX_MD_SIZE> hash{};
    ByteCleanseGuard<std::array<uint8_t, EVP_MAX_MD_SIZE>> hash_guard(hash);
    unsigned int hash_len = 0U;
    if (EVP_Digest(entropy.data(), entropy.size(), hash.data(), &hash_len, EVP_sha256(), nullptr) != 1 ||
        hash_len < 32U) {
        return false;
    }

    uint8_t expected_cs = static_cast<uint8_t>(hash[0] & checksum_mask);
    const bool matched = (CRYPTO_memcmp(&expected_cs, &actual_cs, 1U) == 0);
    OPENSSL_cleanse(&expected_cs, sizeof(expected_cs));
    OPENSSL_cleanse(&actual_cs, sizeof(actual_cs));
    return matched;
}

[[nodiscard]] std::string encode_hex_lower(std::span<const uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(bytes.size() * 2U);
    for (const uint8_t b : bytes) {
        hex.push_back(kHex[(b >> 4U) & 0x0FU]);
        hex.push_back(kHex[b & 0x0FU]);
    }
    return hex;
}

[[nodiscard]] std::optional<uint8_t> hex_nibble(char ch) noexcept {
    if (ch >= '0' && ch <= '9') {
        return static_cast<uint8_t>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return static_cast<uint8_t>(ch - 'a' + 10);
    }
    if (ch >= 'A' && ch <= 'F') {
        return static_cast<uint8_t>(ch - 'A' + 10);
    }
    return std::nullopt;
}

[[nodiscard]] bool decode_hex_exact(std::string_view hex, std::size_t expected_bytes, std::vector<uint8_t>& out) {
    if (hex.size() != expected_bytes * 2U) {
        return false;
    }
    out.assign(expected_bytes, 0U);
    for (std::size_t i = 0U; i < expected_bytes; ++i) {
        const auto hi = hex_nibble(hex[i * 2U]);
        const auto lo = hex_nibble(hex[i * 2U + 1U]);
        if (!hi.has_value() || !lo.has_value()) {
            return false;
        }
        out[i] = static_cast<uint8_t>((*hi << 4U) | *lo);
    }
    return true;
}

[[nodiscard]] bool csprng_uniform_u32(std::size_t upper_bound, std::size_t& out_value) noexcept {
    if (upper_bound == 0U || upper_bound > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    const auto bound = static_cast<uint32_t>(upper_bound);
    const uint32_t limit = std::numeric_limits<uint32_t>::max() - (std::numeric_limits<uint32_t>::max() % bound);

    while (true) {
        uint32_t candidate = 0U;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&candidate), sizeof(candidate)) != 1) {
            return false;
        }
        if (candidate < limit) {
            out_value = static_cast<std::size_t>(candidate % bound);
            return true;
        }
    }
}

[[nodiscard]] bool constant_time_equal_strings(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    if (lhs.empty()) {
        return true;
    }
    return CRYPTO_memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
}

} // namespace

application::ClientResult<SecretString> RecoveryPhraseEngine::generate_mnemonic(RecoveryPhraseLength length) {
    std::size_t entropy_len = 0U;
    switch (length) {
    case RecoveryPhraseLength::Words12:
        entropy_len = kEntropyBytes12;
        break;
    case RecoveryPhraseLength::Words24:
        entropy_len = kEntropyBytes24;
        break;
    default:
        return application::ClientResult<SecretString>::error(
            application::ClientError::validation("Unsupported BIP-39 recovery phrase length"));
    }

    std::vector<uint8_t> entropy(entropy_len, 0U);
    ByteCleanseGuard<std::vector<uint8_t>> entropy_guard(entropy);
    if (RAND_bytes(entropy.data(), static_cast<int>(entropy.size())) != 1) {
        return application::ClientResult<SecretString>::error(
            application::ClientError::crypto("OpenSSL RAND_bytes failed while generating recovery phrase entropy"));
    }

    return entropy_to_mnemonic(entropy);
}

application::ClientResult<SecretString> RecoveryPhraseEngine::entropy_to_mnemonic(std::span<const uint8_t> entropy) {
    if (entropy.size() != kEntropyBytes12 && entropy.size() != kEntropyBytes24) {
        return application::ClientResult<SecretString>::error(
            application::ClientError::validation("BIP-39 entropy must be 16 bytes (12 words) or 32 bytes (24 words)"));
    }

    std::array<uint8_t, EVP_MAX_MD_SIZE> hash{};
    ByteCleanseGuard<std::array<uint8_t, EVP_MAX_MD_SIZE>> hash_guard(hash);
    unsigned int hash_len = 0U;
    if (EVP_Digest(entropy.data(), entropy.size(), hash.data(), &hash_len, EVP_sha256(), nullptr) != 1 ||
        hash_len < 32U) {
        return application::ClientResult<SecretString>::error(
            application::ClientError::crypto("Failed to compute SHA-256 checksum for BIP-39 entropy"));
    }

    const std::size_t word_count = (entropy.size() == kEntropyBytes12) ? kWordCount12 : kWordCount24;
    std::vector<uint16_t> indices(word_count, 0U);
    ByteCleanseGuard<std::vector<uint16_t>> idx_guard(indices);

    for (std::size_t w = 0U; w < word_count; ++w) {
        uint16_t idx = 0U;
        for (std::size_t bit = 0U; bit < 11U; ++bit) {
            const std::size_t abs_bit = w * 11U + bit;
            const std::size_t byte_idx = abs_bit / 8U;
            const std::size_t bit_in_byte = 7U - (abs_bit % 8U);
            const uint8_t src_byte = (byte_idx < entropy.size()) ? entropy[byte_idx] : hash[0];
            const uint16_t bit_val = static_cast<uint16_t>((src_byte >> bit_in_byte) & 0x01U);
            idx = static_cast<uint16_t>((idx << 1U) | bit_val);
        }
        indices[w] = idx;
    }

    std::string joined;
    ByteCleanseGuard<std::string> joined_guard(joined);
    joined.reserve(word_count * 9U);
    for (std::size_t i = 0U; i < word_count; ++i) {
        if (i > 0U) {
            joined.push_back(' ');
        }
        joined.append(kBip39EnglishWords[indices[i]]);
    }

    SecretString secret(joined);
    return application::ClientResult<SecretString>::ok(std::move(secret));
}

application::ClientResult<bool> RecoveryPhraseEngine::validate_mnemonic(const SecretString& mnemonic) {
    std::vector<std::string> words;
    WordVectorCleanseGuard cleanup(words);
    return application::ClientResult<bool>::ok(validate_and_normalize_phrase(mnemonic, words));
}

application::ClientResult<std::vector<uint8_t>>
RecoveryPhraseEngine::derive_recovery_seed(const SecretString& mnemonic, const SecretString& passphrase) {
    std::vector<std::string> words;
    WordVectorCleanseGuard words_cleanup(words);
    if (!validate_and_normalize_phrase(mnemonic, words)) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::validation("Cannot derive seed from an invalid BIP-39 recovery phrase"));
    }

    std::string canonical_phrase = join_words(words);
    ByteCleanseGuard<std::string> phrase_guard(canonical_phrase);

    std::string salt = "mnemonic";
    salt.append(passphrase.expose_unredacted_secret());
    ByteCleanseGuard<std::string> salt_guard(salt);

    std::vector<uint8_t> seed(kSeedBytes, 0U);
    const int rc = PKCS5_PBKDF2_HMAC(canonical_phrase.data(), static_cast<int>(canonical_phrase.size()),
                                     reinterpret_cast<const unsigned char*>(salt.data()), static_cast<int>(salt.size()),
                                     kBip39Pbkdf2Iterations, EVP_sha512(), static_cast<int>(seed.size()), seed.data());
    if (rc != 1) {
        OPENSSL_cleanse(seed.data(), seed.size());
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::crypto("PBKDF2-HMAC-SHA512 recovery seed derivation failed"));
    }

    return application::ClientResult<std::vector<uint8_t>>::ok(std::move(seed));
}

application::ClientResult<std::string>
RecoveryPhraseEngine::compute_salted_verification_digest(const SecretString& mnemonic) {
    std::vector<std::string> words;
    WordVectorCleanseGuard words_cleanup(words);
    if (!validate_and_normalize_phrase(mnemonic, words)) {
        return application::ClientResult<std::string>::error(
            application::ClientError::validation("Cannot compute verification digest for an invalid BIP-39 mnemonic"));
    }

    std::string canonical_phrase = join_words(words);
    ByteCleanseGuard<std::string> phrase_guard(canonical_phrase);

    std::vector<uint8_t> salt(kVerifierSaltBytes, 0U);
    ByteCleanseGuard<std::vector<uint8_t>> salt_guard(salt);
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("OpenSSL RAND_bytes failed while generating verifier salt"));
    }

    std::vector<uint8_t> digest(kVerifierDigestBytes, 0U);
    ByteCleanseGuard<std::vector<uint8_t>> digest_guard(digest);
    const int rc = PKCS5_PBKDF2_HMAC(canonical_phrase.data(), static_cast<int>(canonical_phrase.size()), salt.data(),
                                     static_cast<int>(salt.size()), static_cast<int>(kVerifierPbkdf2Iterations),
                                     EVP_sha256(), static_cast<int>(digest.size()), digest.data());
    if (rc != 1) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("PBKDF2-HMAC-SHA256 verification digest computation failed"));
    }

    std::string encoded = std::string(kVerifierPrefix) + ":" + std::to_string(kVerifierPbkdf2Iterations) + ":" +
                          encode_hex_lower(salt) + ":" + encode_hex_lower(digest);
    return application::ClientResult<std::string>::ok(std::move(encoded));
}

application::ClientResult<bool> RecoveryPhraseEngine::verify_against_digest(const SecretString& mnemonic,
                                                                            std::string_view stored_digest) {
    std::vector<std::string> words;
    WordVectorCleanseGuard words_cleanup(words);
    if (!validate_and_normalize_phrase(mnemonic, words)) {
        return application::ClientResult<bool>::ok(false);
    }

    const std::size_t p1 = stored_digest.find(':');
    const std::size_t p2 = (p1 == std::string_view::npos) ? std::string_view::npos : stored_digest.find(':', p1 + 1U);
    const std::size_t p3 = (p2 == std::string_view::npos) ? std::string_view::npos : stored_digest.find(':', p2 + 1U);
    if (p1 == std::string_view::npos || p2 == std::string_view::npos || p3 == std::string_view::npos ||
        stored_digest.find(':', p3 + 1U) != std::string_view::npos) {
        return application::ClientResult<bool>::ok(false);
    }

    const std::string_view prefix = stored_digest.substr(0U, p1);
    const std::string_view iter_sv = stored_digest.substr(p1 + 1U, p2 - p1 - 1U);
    const std::string_view salt_hex = stored_digest.substr(p2 + 1U, p3 - p2 - 1U);
    const std::string_view expected_hex = stored_digest.substr(p3 + 1U);
    if (prefix != kVerifierPrefix || iter_sv.empty()) {
        return application::ClientResult<bool>::ok(false);
    }

    uint64_t parsed_iter = 0ULL;
    for (const char ch : iter_sv) {
        if (ch < '0' || ch > '9') {
            return application::ClientResult<bool>::ok(false);
        }
        parsed_iter = parsed_iter * 10ULL + static_cast<uint64_t>(ch - '0');
        if (parsed_iter > kMaxVerifierPbkdf2Iterations) {
            return application::ClientResult<bool>::ok(false);
        }
    }
    if (parsed_iter < kVerifierPbkdf2Iterations) {
        return application::ClientResult<bool>::ok(false);
    }

    std::vector<uint8_t> salt;
    std::vector<uint8_t> expected;
    ByteCleanseGuard<std::vector<uint8_t>> salt_guard(salt);
    ByteCleanseGuard<std::vector<uint8_t>> expected_guard(expected);
    if (!decode_hex_exact(salt_hex, kVerifierSaltBytes, salt) ||
        !decode_hex_exact(expected_hex, kVerifierDigestBytes, expected)) {
        return application::ClientResult<bool>::ok(false);
    }

    std::string canonical_phrase = join_words(words);
    ByteCleanseGuard<std::string> phrase_guard(canonical_phrase);

    std::vector<uint8_t> derived(kVerifierDigestBytes, 0U);
    ByteCleanseGuard<std::vector<uint8_t>> derived_guard(derived);
    const int rc = PKCS5_PBKDF2_HMAC(canonical_phrase.data(), static_cast<int>(canonical_phrase.size()), salt.data(),
                                     static_cast<int>(salt.size()), static_cast<int>(parsed_iter), EVP_sha256(),
                                     static_cast<int>(derived.size()), derived.data());
    if (rc != 1) {
        return application::ClientResult<bool>::error(
            application::ClientError::crypto("PBKDF2-HMAC-SHA256 verification digest derivation failed"));
    }

    const bool matched = (CRYPTO_memcmp(derived.data(), expected.data(), kVerifierDigestBytes) == 0);
    return application::ClientResult<bool>::ok(matched);
}

application::ClientResult<RecoveryVerificationChallenge>
RecoveryPhraseEngine::build_challenge(std::size_t word_count, std::size_t sample_count) {
    if (word_count != kWordCount12 && word_count != kWordCount24) {
        return application::ClientResult<RecoveryVerificationChallenge>::error(
            application::ClientError::validation("Challenge word_count must be 12 or 24"));
    }
    if (sample_count == 0U || sample_count > word_count) {
        return application::ClientResult<RecoveryVerificationChallenge>::error(
            application::ClientError::validation("Challenge sample_count must be between 1 and word_count"));
    }

    std::vector<std::size_t> pool(word_count);
    for (std::size_t i = 0U; i < word_count; ++i) {
        pool[i] = i;
    }

    for (std::size_t i = 0U; i < sample_count; ++i) {
        std::size_t offset = 0U;
        if (!csprng_uniform_u32(word_count - i, offset)) {
            return application::ClientResult<RecoveryVerificationChallenge>::error(
                application::ClientError::crypto("OpenSSL RAND_bytes failed while building verification challenge"));
        }
        std::swap(pool[i], pool[i + offset]);
    }

    RecoveryVerificationChallenge challenge;
    challenge.word_indices.assign(pool.begin(), pool.begin() + static_cast<std::ptrdiff_t>(sample_count));
    std::sort(challenge.word_indices.begin(), challenge.word_indices.end());
    return application::ClientResult<RecoveryVerificationChallenge>::ok(std::move(challenge));
}

application::ClientResult<bool>
RecoveryPhraseEngine::verify_challenge_words(const SecretString& mnemonic,
                                             const std::vector<std::pair<std::size_t, std::string>>& answers) {
    if (answers.empty()) {
        return application::ClientResult<bool>::error(
            application::ClientError::validation("Verification challenge answers cannot be empty"));
    }

    std::vector<std::string> words;
    WordVectorCleanseGuard words_cleanup(words);
    if (!validate_and_normalize_phrase(mnemonic, words)) {
        return application::ClientResult<bool>::ok(false);
    }

    std::set<std::size_t> seen_indices;
    for (const auto& [idx, _] : answers) {
        if (idx >= words.size()) {
            return application::ClientResult<bool>::error(
                application::ClientError::validation("Verification challenge index is out of range"));
        }
        if (!seen_indices.insert(idx).second) {
            return application::ClientResult<bool>::error(
                application::ClientError::validation("Verification challenge contains duplicate word indices"));
        }
    }

    bool all_matched = true;
    for (const auto& [idx, raw_answer] : answers) {
        std::string normalized = to_lower_trimmed_ascii(raw_answer);
        ByteCleanseGuard<std::string> norm_guard(normalized);
        if (!constant_time_equal_strings(normalized, words[idx])) {
            all_matched = false;
        }
    }

    return application::ClientResult<bool>::ok(all_matched);
}

} // namespace securecloud::client::domain::crypto
