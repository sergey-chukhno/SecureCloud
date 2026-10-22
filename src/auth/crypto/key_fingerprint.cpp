#include "auth/crypto/key_fingerprint.hpp"

#include <array>
#include <iomanip>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>

namespace securecloud::auth::crypto {

namespace {

constexpr char kHexCharsUpper[] = "0123456789ABCDEF";
constexpr char kHexCharsLower[] = "0123456789abcdef";

} // namespace

std::vector<uint8_t> KeyFingerprint::compute_raw_sha256(std::span<const uint8_t> key_bytes) {
    std::vector<uint8_t> digest(kDigestSize);
    unsigned int md_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("KeyFingerprint: Failed to allocate OpenSSL EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, key_bytes.data(), key_bytes.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest.data(), &md_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("KeyFingerprint: OpenSSL SHA-256 computation failed");
    }

    EVP_MD_CTX_free(ctx);
    digest.resize(md_len);
    return digest;
}

std::string KeyFingerprint::compute_sha256(std::span<const uint8_t> key_bytes) {
    const auto raw = compute_raw_sha256(key_bytes);

    // Formats into "SHA256:XX:XX:..."
    // "SHA256:" is 7 chars. 32 bytes * 2 hex chars + 31 colons = 95 chars. Total = 102 chars.
    std::string result;
    result.reserve(7 + (raw.size() * 3) - 1);
    result.append("SHA256:");

    for (std::size_t i = 0; i < raw.size(); ++i) {
        if (i > 0) {
            result.push_back(':');
        }
        result.push_back(kHexCharsUpper[(raw[i] >> 4) & 0x0F]);
        result.push_back(kHexCharsUpper[raw[i] & 0x0F]);
    }

    return result;
}

std::string KeyFingerprint::compute_hex_sha256(std::span<const uint8_t> key_bytes) {
    const auto raw = compute_raw_sha256(key_bytes);
    std::string result;
    result.reserve(raw.size() * 2);

    for (uint8_t b : raw) {
        result.push_back(kHexCharsLower[(b >> 4) & 0x0F]);
        result.push_back(kHexCharsLower[b & 0x0F]);
    }

    return result;
}

bool KeyFingerprint::constant_time_equals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace securecloud::auth::crypto
