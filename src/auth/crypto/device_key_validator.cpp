#include "auth/crypto/device_key_validator.hpp"

#include <algorithm>
#include <cctype>
#include <openssl/evp.h>
#include <string_view>

namespace securecloud::auth::crypto {

namespace {

constexpr std::string_view kPrivateKeyMarkers[] = {
    "private key",
    "private_key",
    "begin private key",
    "begin ec private key",
    "begin rsa private key",
    "begin openssh private key",
    "begin ed25519 private key",
    "encrypted private key",
};

bool buffer_contains_ci_substring(std::span<const uint8_t> buffer, std::string_view needle) {
    if (buffer.size() < needle.size()) {
        return false;
    }
    const auto it = std::search(buffer.begin(), buffer.end(), needle.begin(), needle.end(), [](uint8_t a, char b) {
        return std::tolower(a) == std::tolower(static_cast<uint8_t>(b));
    });
    return it != buffer.end();
}

} // namespace

bool DeviceKeyValidator::contains_private_key_material(std::span<const uint8_t> buffer) noexcept {
    if (buffer.empty()) {
        return false;
    }

    for (const auto marker : kPrivateKeyMarkers) {
        if (buffer_contains_ci_substring(buffer, marker)) {
            return true;
        }
    }

    // ASN.1 PKCS#8 inspection: Sequence (0x30) followed by Version integer (0x02, 0x01, 0x00)
    if (buffer.size() >= 4 && buffer[0] == 0x30 && buffer[2] == 0x02 && buffer[3] == 0x01 && buffer[4] == 0x00) {
        return true;
    }

    return false;
}

bool DeviceKeyValidator::validate_identity_key(std::span<const uint8_t> identity_key, std::string* error_out) {
    if (identity_key.size() != kEd25519PublicKeySize) {
        if (error_out) {
            *error_out = "Identity key must be exactly 32 bytes (Ed25519 public key), got " +
                         std::to_string(identity_key.size()) + " bytes";
        }
        return false;
    }

    if (contains_private_key_material(identity_key)) {
        if (error_out) {
            *error_out = "Identity key contains private key material (Zero Private Key Invariant violated)";
        }
        return false;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, identity_key.data(), identity_key.size());
    if (!pkey) {
        if (error_out) {
            *error_out = "Invalid Ed25519 public key format";
        }
        return false;
    }
    EVP_PKEY_free(pkey);
    return true;
}

bool DeviceKeyValidator::validate_signed_prekey(std::span<const uint8_t> signed_prekey, std::string* error_out) {
    if (signed_prekey.size() != kX25519KeySize) {
        if (error_out) {
            *error_out = "Signed prekey must be exactly 32 bytes (X25519 public key), got " +
                         std::to_string(signed_prekey.size()) + " bytes";
        }
        return false;
    }

    if (contains_private_key_material(signed_prekey)) {
        if (error_out) {
            *error_out = "Signed prekey contains private key material (Zero Private Key Invariant violated)";
        }
        return false;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, signed_prekey.data(), signed_prekey.size());
    if (!pkey) {
        if (error_out) {
            *error_out = "Invalid X25519 public key format";
        }
        return false;
    }
    EVP_PKEY_free(pkey);
    return true;
}

bool DeviceKeyValidator::validate_signed_prekey_signature(std::span<const uint8_t> identity_key,
                                                          std::span<const uint8_t> signed_prekey,
                                                          std::span<const uint8_t> signature, std::string* error_out) {
    if (!validate_identity_key(identity_key, error_out)) {
        return false;
    }

    if (!validate_signed_prekey(signed_prekey, error_out)) {
        return false;
    }

    if (signature.size() != kEd25519SignatureSize) {
        if (error_out) {
            *error_out = "Signed prekey signature must be exactly 64 bytes (Ed25519 signature), got " +
                         std::to_string(signature.size()) + " bytes";
        }
        return false;
    }

    if (contains_private_key_material(signature)) {
        if (error_out) {
            *error_out = "Signature buffer contains private key material";
        }
        return false;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, identity_key.data(), identity_key.size());
    if (!pkey) {
        if (error_out) {
            *error_out = "Failed to load Ed25519 identity key for signature verification";
        }
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        if (error_out) {
            *error_out = "Failed to allocate OpenSSL EVP_MD_CTX";
        }
        return false;
    }

    bool verified = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        int ret = EVP_DigestVerify(ctx, signature.data(), signature.size(), signed_prekey.data(), signed_prekey.size());
        if (ret == 1) {
            verified = true;
        } else {
            if (error_out) {
                *error_out = "Cryptographic signature verification failed: signed prekey is not signed by identity key";
            }
        }
    } else {
        if (error_out) {
            *error_out = "OpenSSL EVP_DigestVerifyInit initialization failed";
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return verified;
}

bool DeviceKeyValidator::validate_one_time_prekeys(const std::vector<std::vector<uint8_t>>& prekeys,
                                                   std::string* error_out) {
    if (prekeys.size() > kMaxOneTimePrekeys) {
        if (error_out) {
            *error_out = "One-time prekeys batch exceeds limit of " + std::to_string(kMaxOneTimePrekeys) +
                         " keys (received " + std::to_string(prekeys.size()) + ")";
        }
        return false;
    }

    for (std::size_t i = 0; i < prekeys.size(); ++i) {
        std::string sub_err;
        if (!validate_signed_prekey(prekeys[i], &sub_err)) {
            if (error_out) {
                *error_out = "One-time prekey at index " + std::to_string(i) + " is invalid: " + sub_err;
            }
            return false;
        }
    }

    return true;
}

bool DeviceKeyValidator::validate_registration_bundle(std::span<const uint8_t> identity_key,
                                                      std::span<const uint8_t> signed_prekey,
                                                      std::span<const uint8_t> signature,
                                                      const std::vector<std::vector<uint8_t>>& one_time_prekeys,
                                                      std::string* error_out) {
    if (!validate_signed_prekey_signature(identity_key, signed_prekey, signature, error_out)) {
        return false;
    }

    if (!validate_one_time_prekeys(one_time_prekeys, error_out)) {
        return false;
    }

    return true;
}

} // namespace securecloud::auth::crypto
