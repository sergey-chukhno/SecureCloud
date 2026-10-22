#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace securecloud::auth::crypto {

/**
 * @brief Cryptographic validation engine for client device cryptographic material.
 *
 * Enforces strict sizing, curve validation, proof-of-possession signature verification,
 * and the Zero Private Key Invariant (preventing private key leakage into Auth).
 */
class DeviceKeyValidator {
  public:
    static constexpr std::size_t kEd25519PublicKeySize = 32;
    static constexpr std::size_t kX25519KeySize = 32;
    static constexpr std::size_t kEd25519SignatureSize = 64;
    static constexpr std::size_t kMaxOneTimePrekeys = 100;

    /**
     * @brief Validates an Ed25519 identity public key.
     * Checks exact 32-byte size, OpenSSL key validity, and absence of private key material.
     */
    [[nodiscard]] static bool validate_identity_key(std::span<const uint8_t> identity_key,
                                                    std::string* error_out = nullptr);

    /**
     * @brief Validates an X25519 signed prekey.
     * Checks exact 32-byte size, OpenSSL curve key validity, and absence of private key material.
     */
    [[nodiscard]] static bool validate_signed_prekey(std::span<const uint8_t> signed_prekey,
                                                     std::string* error_out = nullptr);

    /**
     * @brief Cryptographically verifies that the signed prekey is signed by the identity key.
     * Validates the 64-byte Ed25519 signature over the 32-byte signed prekey.
     */
    [[nodiscard]] static bool validate_signed_prekey_signature(std::span<const uint8_t> identity_key,
                                                               std::span<const uint8_t> signed_prekey,
                                                               std::span<const uint8_t> signature,
                                                               std::string* error_out = nullptr);

    /**
     * @brief Validates a collection of one-time prekeys (up to kMaxOneTimePrekeys, each 32 bytes X25519).
     */
    [[nodiscard]] static bool validate_one_time_prekeys(const std::vector<std::vector<uint8_t>>& prekeys,
                                                        std::string* error_out = nullptr);

    /**
     * @brief Validates a complete device registration cryptographic key bundle.
     */
    [[nodiscard]] static bool validate_registration_bundle(std::span<const uint8_t> identity_key,
                                                           std::span<const uint8_t> signed_prekey,
                                                           std::span<const uint8_t> signature,
                                                           const std::vector<std::vector<uint8_t>>& one_time_prekeys,
                                                           std::string* error_out = nullptr);

    /**
     * @brief Zero Private Key Invariant check: checks whether the buffer contains private key markers or structures.
     */
    [[nodiscard]] static bool contains_private_key_material(std::span<const uint8_t> buffer) noexcept;
};

} // namespace securecloud::auth::crypto
