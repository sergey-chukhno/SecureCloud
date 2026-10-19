#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_types.hpp"

#include <chrono>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::messaging::domain {

/**
 * @brief Authoritative End-to-End Encryption Protocol Versions.
 *
 * In accordance with ADR-008, SecureCloud supports the Signal Protocol family
 * (PQXDH and Double Ratchet). Unapproved, obsolete, or unknown protocol versions
 * are strictly rejected to eliminate cryptographic downgrade vulnerabilities.
 */
enum class E2EProtocolVersion : int32_t {
    Unspecified = 0,
    V1_Signal_PQXDH_DoubleRatchet = 1,
    V2_Hybrid_PostQuantum = 2,
};

[[nodiscard]] inline std::string to_string(E2EProtocolVersion version) {
    switch (version) {
    case E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet:
        return "V1_Signal_PQXDH_DoubleRatchet";
    case E2EProtocolVersion::V2_Hybrid_PostQuantum:
        return "V2_Hybrid_PostQuantum";
    case E2EProtocolVersion::Unspecified:
        return "UNSPECIFIED";
    }
    return "UNKNOWN";
}

[[nodiscard]] inline std::optional<E2EProtocolVersion> e2e_protocol_version_from_int(int32_t val) noexcept {
    switch (val) {
    case 1:
        return E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
    case 2:
        return E2EProtocolVersion::V2_Hybrid_PostQuantum;
    default:
        return std::nullopt;
    }
}

[[nodiscard]] inline std::optional<E2EProtocolVersion> e2e_protocol_version_from_string(std::string_view sv) noexcept {
    if (sv == "V1_Signal_PQXDH_DoubleRatchet" || sv == "1" || sv == "v1") {
        return E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
    }
    if (sv == "V2_Hybrid_PostQuantum" || sv == "2" || sv == "v2") {
        return E2EProtocolVersion::V2_Hybrid_PostQuantum;
    }
    return std::nullopt;
}

/**
 * @brief Approved Authenticated Encryption with Associated Data (AEAD) Algorithms (ADR-008).
 */
enum class E2EAlgorithm : uint8_t {
    Unspecified = 0,
    XChaCha20_Poly1305 = 1,
    AES_256_GCM = 2,
};

[[nodiscard]] inline std::string to_string(E2EAlgorithm algo) {
    switch (algo) {
    case E2EAlgorithm::XChaCha20_Poly1305:
        return "XChaCha20-Poly1305";
    case E2EAlgorithm::AES_256_GCM:
        return "AES-256-GCM";
    case E2EAlgorithm::Unspecified:
        return "UNSPECIFIED";
    }
    return "UNKNOWN";
}

[[nodiscard]] inline std::optional<E2EAlgorithm> e2e_algorithm_from_string(std::string_view sv) noexcept {
    if (sv == "XChaCha20-Poly1305" || sv == "xchacha20-poly1305" || sv == "XCHACHA20_POLY1305") {
        return E2EAlgorithm::XChaCha20_Poly1305;
    }
    if (sv == "AES-256-GCM" || sv == "aes-256-gcm" || sv == "AES_256_GCM") {
        return E2EAlgorithm::AES_256_GCM;
    }
    return std::nullopt;
}

/**
 * @brief Device-specific encrypted envelope targeted at an individual physical recipient device.
 *
 * In accordance with the recipient-device model (ADR-007, ADR-008), every physical recipient device
 * receives an independently encrypted envelope. The server persists and routes these envelopes
 * without inspecting or decrypting the ciphertext.
 */
struct PerDeviceEnvelope {
    UserId recipient_user_id{};
    DeviceId recipient_device_id{};
    E2EProtocolVersion protocol_version{E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet};
    E2EAlgorithm algorithm{E2EAlgorithm::XChaCha20_Poly1305};
    std::string ciphertext_blob{};
    std::vector<uint8_t> ephemeral_public_key{};
    std::vector<uint8_t> iv{};
    std::vector<uint8_t> auth_tag{};
    std::optional<std::string> one_time_prekey_id{std::nullopt};

    auto operator<=>(const PerDeviceEnvelope& other) const noexcept = default;
    bool operator==(const PerDeviceEnvelope& other) const noexcept = default;
};

/**
 * @brief Server-side E2E Message Envelope container.
 *
 * Preserves the canonical association between the logical message identifier and its
 * device-specific encrypted delivery targets without server-side decryption capability.
 */
struct E2EMessageEnvelope {
    MessageId message_id{};
    ConversationId conversation_id{};
    UserId sender_user_id{};
    DeviceId sender_device_id{};
    E2EProtocolVersion protocol_version{E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet};
    MessagePriority priority{MessagePriority::Normal};
    std::chrono::system_clock::time_point created_at{};
    std::optional<std::chrono::system_clock::time_point> expires_at{std::nullopt};
    std::vector<PerDeviceEnvelope> per_device_envelopes{};

    auto operator<=>(const E2EMessageEnvelope& other) const noexcept = default;
    bool operator==(const E2EMessageEnvelope& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
