#include "auth/crypto/recovery_code_generator.hpp"

#include <cctype>
#include <iomanip>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sstream>
#include <stdexcept>

namespace securecloud::auth::crypto {

namespace {

// Unambiguous 32-character Base32-like alphabet (excludes 0, O, 1, I, L)
constexpr char kRecoveryAlphabet[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
constexpr size_t kAlphabetSize = 32;

std::string generate_single_code() {
    uint8_t rand_bytes[8];
    if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1) {
        throw std::runtime_error("RecoveryCodeGenerator: RAND_bytes failed");
    }

    std::string code;
    code.reserve(9); // 4 + 1 + 4
    for (size_t i = 0; i < 4; ++i) {
        code.push_back(kRecoveryAlphabet[rand_bytes[i] % kAlphabetSize]);
    }
    code.push_back('-');
    for (size_t i = 4; i < 8; ++i) {
        code.push_back(kRecoveryAlphabet[rand_bytes[i] % kAlphabetSize]);
    }

    return code;
}

} // namespace

RecoveryCodeBatch RecoveryCodeGenerator::generate_batch(size_t count) {
    RecoveryCodeBatch batch;
    batch.plaintext_codes.reserve(count);
    batch.hashed_codes.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        std::string code = generate_single_code();
        std::string hash = hash_code(code);
        batch.plaintext_codes.push_back(std::move(code));
        batch.hashed_codes.push_back(std::move(hash));
    }

    return batch;
}

std::string RecoveryCodeGenerator::normalize_code(std::string_view code) {
    std::string normalized;
    normalized.reserve(code.size());

    for (const char c : code) {
        if (c == '-' || std::isspace(static_cast<unsigned char>(c))) {
            continue;
        }
        normalized.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }

    return normalized;
}

std::string RecoveryCodeGenerator::hash_code(std::string_view code) {
    const std::string normalized = normalize_code(code);

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(normalized.data()), normalized.size(), hash);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }

    return oss.str();
}

std::optional<size_t> RecoveryCodeGenerator::verify_and_consume(std::string_view raw_code,
                                                                const std::vector<std::string>& hashed_codes_pool) {
    if (raw_code.empty() || hashed_codes_pool.empty()) {
        return std::nullopt;
    }

    const std::string candidate_hash = hash_code(raw_code);

    for (size_t i = 0; i < hashed_codes_pool.size(); ++i) {
        const auto& target = hashed_codes_pool[i];
        if (candidate_hash.size() == target.size() &&
            CRYPTO_memcmp(candidate_hash.data(), target.data(), candidate_hash.size()) == 0) {
            return i;
        }
    }

    return std::nullopt;
}

} // namespace securecloud::auth::crypto
