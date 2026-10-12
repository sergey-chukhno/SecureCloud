#include "auth/crypto/prekey_validator.hpp"

#include "auth/crypto/device_key_validator.hpp"

#include <algorithm>
#include <openssl/evp.h>
#include <set>

namespace securecloud::auth::crypto {

namespace {

bool is_all_bytes(std::span<const uint8_t> buffer, uint8_t val) {
    return std::all_of(buffer.begin(), buffer.end(), [val](uint8_t b) { return b == val; });
}

} // namespace

bool PrekeyValidator::validate_single_prekey(std::span<const uint8_t> key_bytes, std::string* error_out) {
    if (key_bytes.size() != kX25519KeySize) {
        if (error_out) {
            *error_out = "One-time prekey must be exactly 32 bytes (X25519 public key), got " +
                         std::to_string(key_bytes.size()) + " bytes";
        }
        return false;
    }

    if (DeviceKeyValidator::contains_private_key_material(key_bytes)) {
        if (error_out) {
            *error_out = "One-time prekey contains private key material (Zero Private Key Invariant violated)";
        }
        return false;
    }

    if (is_all_bytes(key_bytes, 0x00)) {
        if (error_out) {
            *error_out = "One-time prekey cannot be all zeros (degenerate point)";
        }
        return false;
    }

    if (is_all_bytes(key_bytes, 0xFF)) {
        if (error_out) {
            *error_out = "One-time prekey cannot be all 0xFF (invalid point)";
        }
        return false;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, key_bytes.data(), key_bytes.size());
    if (!pkey) {
        if (error_out) {
            *error_out = "Invalid X25519 public key format";
        }
        return false;
    }
    EVP_PKEY_free(pkey);
    return true;
}

bool PrekeyValidator::validate_prekey_batch(const std::vector<std::vector<uint8_t>>& prekeys, std::string* error_out) {
    if (prekeys.size() < kMinBatchSize) {
        if (error_out) {
            *error_out = "Prekey batch must contain at least " + std::to_string(kMinBatchSize) + " key(s)";
        }
        return false;
    }

    if (prekeys.size() > kMaxBatchSize) {
        if (error_out) {
            *error_out = "Prekey batch exceeds maximum allowed limit of " + std::to_string(kMaxBatchSize) +
                         " keys, got " + std::to_string(prekeys.size());
        }
        return false;
    }

    std::set<std::vector<uint8_t>> seen_keys;

    for (std::size_t i = 0; i < prekeys.size(); ++i) {
        const auto& key = prekeys[i];
        if (!validate_single_prekey(key, error_out)) {
            if (error_out) {
                *error_out = "Key at index " + std::to_string(i) + " is invalid: " + *error_out;
            }
            return false;
        }

        auto [it, inserted] = seen_keys.insert(key);
        if (!inserted) {
            if (error_out) {
                *error_out = "Duplicate one-time prekey found within batch at index " + std::to_string(i);
            }
            return false;
        }
    }

    return true;
}

} // namespace securecloud::auth::crypto
