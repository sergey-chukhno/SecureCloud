#pragma once

#include "domain/envelope_types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::messaging::service {

/**
 * @brief Authoritative Security & Protocol Versioning Policy Engine (ADR-008, MSG-006).
 *
 * Enforces cryptographic constraints on incoming E2E message envelopes:
 * - Protocol version whitelisting to strictly reject deprecated, unapproved, or unknown protocol versions (fail
 * closed).
 * - AEAD algorithm verification (only approved XChaCha20-Poly1305 and AES-256-GCM).
 * - Minimum parameter sizes: IV (24B for XChaCha20, 12B for AES-GCM), Auth Tag (16B), Ephemeral Public Key (32B).
 * - Maximum ciphertext size limit (16MB, ADR-010).
 */
class ProtocolVersionPolicy {
  public:
    /// Maximum permitted ciphertext payload size in bytes (16 MB, ADR-010)
    static constexpr size_t k_max_ciphertext_bytes = 16 * 1024 * 1024;

    /// Minimum ephemeral public key size in bytes (32 bytes for X25519)
    static constexpr size_t k_min_ephemeral_key_bytes = 32;

    /// Minimum AEAD authentication tag size in bytes (16 bytes for Poly1305 / GCM)
    static constexpr size_t k_min_auth_tag_bytes = 16;

    /// Minimum IV size for XChaCha20-Poly1305 (24 bytes)
    static constexpr size_t k_min_xchacha20_iv_bytes = 24;

    /// Minimum IV size for AES-256-GCM (12 bytes)
    static constexpr size_t k_min_aes_gcm_iv_bytes = 12;

    /**
     * @brief Checks if a protocol version integer matches an approved E2E protocol version.
     */
    [[nodiscard]] static bool is_supported_protocol_version(int32_t version_raw) noexcept;

    /**
     * @brief Checks if a strongly-typed domain protocol version is approved.
     */
    [[nodiscard]] static bool is_supported_protocol_version(domain::E2EProtocolVersion version) noexcept;

    /**
     * @brief Checks if an algorithm name string is an approved AEAD cipher.
     */
    [[nodiscard]] static bool is_approved_algorithm(std::string_view algo_str) noexcept;

    /**
     * @brief Checks if a strongly-typed domain algorithm is an approved AEAD cipher.
     */
    [[nodiscard]] static bool is_approved_algorithm(domain::E2EAlgorithm algo) noexcept;

    /**
     * @brief Returns the minimum required IV size for the given algorithm.
     * @return Minimum byte count, or 0 if algorithm is not approved.
     */
    [[nodiscard]] static size_t get_minimum_iv_size(domain::E2EAlgorithm algo) noexcept;

    /**
     * @brief Returns the minimum required Authentication Tag size for the given algorithm.
     * @return Minimum byte count, or 0 if algorithm is not approved.
     */
    [[nodiscard]] static size_t get_minimum_auth_tag_size(domain::E2EAlgorithm algo) noexcept;

    /**
     * @brief Returns the minimum required Ephemeral Public Key size.
     */
    [[nodiscard]] static size_t get_minimum_ephemeral_key_size(domain::E2EAlgorithm algo) noexcept;

    /**
     * @brief Returns the canonical string representation of an approved algorithm.
     */
    [[nodiscard]] static std::string_view get_canonical_algorithm_name(domain::E2EAlgorithm algo) noexcept;

    /**
     * @brief Validates cryptographic parameter compliance of a per-device envelope.
     *
     * @param envelope The per-device envelope to validate.
     * @return std::nullopt if the envelope satisfies all security requirements,
     *         or a descriptive error string detailing the non-compliance.
     */
    [[nodiscard]] static std::optional<std::string>
    validate_envelope_security(const domain::PerDeviceEnvelope& envelope);
};

} // namespace securecloud::messaging::service
