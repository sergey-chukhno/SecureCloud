#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::auth::crypto {

/**
 * @brief Canonical cryptographic key fingerprint engine.
 *
 * Computes cryptographically secure, standard SHA-256 digests over public key material
 * (e.g. Ed25519 identity public keys) to enable key change detection, MITM prevention,
 * and standard representation ("SHA256:XX:XX:...").
 */
class KeyFingerprint {
  public:
    static constexpr std::size_t kDigestSize = 32;

    /**
     * @brief Computes standard colon-separated uppercase hex fingerprint string.
     * Example: "SHA256:7A:3F:89:..."
     *
     * @param key_bytes The raw public key bytes.
     * @return Formatted fingerprint string prefixed with "SHA256:".
     */
    [[nodiscard]] static std::string compute_sha256(std::span<const uint8_t> key_bytes);

    /**
     * @brief Computes raw 32-byte SHA-256 digest of the key bytes.
     *
     * @param key_bytes The raw public key bytes.
     * @return 32-byte binary SHA-256 digest.
     */
    [[nodiscard]] static std::vector<uint8_t> compute_raw_sha256(std::span<const uint8_t> key_bytes);

    /**
     * @brief Computes continuous lowercase hex SHA-256 string (64 characters).
     *
     * @param key_bytes The raw public key bytes.
     * @return 64-character lowercase hex string.
     */
    [[nodiscard]] static std::string compute_hex_sha256(std::span<const uint8_t> key_bytes);

    /**
     * @brief Performs constant-time comparison of two fingerprint strings or hashes
     * to eliminate timing side-channel leakage.
     *
     * @param a First string.
     * @param b Second string.
     * @return True if strings are identical, false otherwise.
     */
    [[nodiscard]] static bool constant_time_equals(std::string_view a, std::string_view b) noexcept;
};

} // namespace securecloud::auth::crypto
