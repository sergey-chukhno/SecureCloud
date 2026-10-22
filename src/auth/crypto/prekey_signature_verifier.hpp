#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace securecloud::auth::crypto {

/**
 * @brief Cryptographic verifier for X25519 signed prekey authenticity.
 *
 * Verifies that a signed prekey was signed by the registered Ed25519 identity key
 * of the device, ensuring prekeys cannot be forged or substituted by rogue parties.
 */
class PrekeySignatureVerifier {
  public:
    /**
     * @brief Cryptographically verifies Ed25519 signature over X25519 signed prekey.
     *
     * @param identity_key 32-byte Ed25519 identity public key.
     * @param signed_prekey 32-byte X25519 signed prekey.
     * @param signature 64-byte Ed25519 signature.
     * @param error_out Optional pointer to string receiving failure reason.
     * @return True if signature is valid, false otherwise.
     */
    [[nodiscard]] static bool verify(std::span<const uint8_t> identity_key, std::span<const uint8_t> signed_prekey,
                                     std::span<const uint8_t> signature, std::string* error_out = nullptr);
};

} // namespace securecloud::auth::crypto
