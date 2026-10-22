#pragma once

#include "domain/conversation_types.hpp"
#include "domain/envelope_types.hpp"
#include "domain/message_types.hpp"

#include <chrono>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::messaging::domain {

/// Operational delivery status for a recipient device (aligned with proto v1::DeliveryState).
enum class DeliveryState : uint8_t {
    Queued = 1,
    Delivering = 2,
    Delivered = 3,
    Read = 4,
    RetryWait = 5,
    Expired = 6,

    // Backward-compatible alias for existing code
    Pending = Queued,
};

[[nodiscard]] inline std::string to_string(DeliveryState state) {
    switch (state) {
    case DeliveryState::Queued:
        return "QUEUED";
    case DeliveryState::Delivering:
        return "DELIVERING";
    case DeliveryState::Delivered:
        return "DELIVERED";
    case DeliveryState::Read:
        return "READ";
    case DeliveryState::RetryWait:
        return "RETRY_WAIT";
    case DeliveryState::Expired:
        return "EXPIRED";
    }
    return "QUEUED";
}

[[nodiscard]] inline std::optional<DeliveryState> delivery_state_from_string(std::string_view sv) noexcept {
    if (sv == "QUEUED" || sv == "PENDING") {
        return DeliveryState::Queued;
    }
    if (sv == "DELIVERING") {
        return DeliveryState::Delivering;
    }
    if (sv == "DELIVERED") {
        return DeliveryState::Delivered;
    }
    if (sv == "READ") {
        return DeliveryState::Read;
    }
    if (sv == "RETRY_WAIT") {
        return DeliveryState::RetryWait;
    }
    if (sv == "EXPIRED") {
        return DeliveryState::Expired;
    }
    return std::nullopt;
}

/// Outcome of a delivery dispatch attempt to a recipient device.
enum class DeliveryAttemptResult : uint8_t {
    Success = 1,          // Recipient device accepted envelope and provided ACK
    RecipientOffline = 2, // Recipient device is not currently connected to any gateway node
    TransientFailure = 3, // Network reset, socket timeout, or temporary transport failure
    TerminalFailure = 4   // Device revoked, protocol mismatch, invalid envelope payload
};

[[nodiscard]] inline std::string to_string(DeliveryAttemptResult result) {
    switch (result) {
    case DeliveryAttemptResult::Success:
        return "SUCCESS";
    case DeliveryAttemptResult::RecipientOffline:
        return "RECIPIENT_OFFLINE";
    case DeliveryAttemptResult::TransientFailure:
        return "TRANSIENT_FAILURE";
    case DeliveryAttemptResult::TerminalFailure:
        return "TERMINAL_FAILURE";
    }
    return "TRANSIENT_FAILURE";
}

[[nodiscard]] inline std::optional<DeliveryAttemptResult>
delivery_attempt_result_from_string(std::string_view sv) noexcept {
    if (sv == "SUCCESS") {
        return DeliveryAttemptResult::Success;
    }
    if (sv == "RECIPIENT_OFFLINE") {
        return DeliveryAttemptResult::RecipientOffline;
    }
    if (sv == "TRANSIENT_FAILURE") {
        return DeliveryAttemptResult::TransientFailure;
    }
    if (sv == "TERMINAL_FAILURE") {
        return DeliveryAttemptResult::TerminalFailure;
    }
    return std::nullopt;
}

/// Unit of delivery work scheduled for dispatch to a recipient device (Zero Plaintext - ADR-008).
struct DeliveryTask {
    MessageId message_id;
    ConversationId conversation_id;
    DeviceId recipient_device_id;
    UserId recipient_user_id;
    MessagePriority priority{MessagePriority::Normal};
    int32_t attempt_count{0};
    std::chrono::system_clock::time_point accepted_at;
    std::chrono::system_clock::time_point scheduled_at;
    std::optional<std::chrono::system_clock::time_point> expires_at{std::nullopt};

    // Opaque Encrypted Envelope
    PerDeviceEnvelope envelope{};

    auto operator<=>(const DeliveryTask& other) const noexcept = default;
    bool operator==(const DeliveryTask& other) const noexcept = default;
};

/// Represents an item in a device's active delivery queue (pending_deliveries_by_device).
/// - Partition Key: ((device_id, delivery_bucket))
/// - Clustering Key: accepted_at ASC, message_id ASC
struct DeviceDeliveryRecord {
    DeviceId device_id;
    std::string delivery_bucket;
    std::chrono::system_clock::time_point accepted_at;
    MessageId message_id;
    ConversationId conversation_id;
    MessageSequence message_sequence{0};
    MessagePriority message_priority{MessagePriority::Normal};
    DeliveryState delivery_state{DeliveryState::Pending};
    int32_t attempt_count{0};
    std::optional<std::chrono::system_clock::time_point> next_retry_at{std::nullopt};

    // E2E Encrypted Envelope fields (ADR-008, MSG-006)
    std::string ciphertext_blob{};
    std::vector<uint8_t> ephemeral_public_key{};
    std::vector<uint8_t> iv{};
    std::vector<uint8_t> auth_tag{};
    E2EAlgorithm algorithm{E2EAlgorithm::XChaCha20_Poly1305};
    E2EProtocolVersion protocol_version{E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet};
    std::optional<std::string> one_time_prekey_id{std::nullopt};

    void set_envelope(const PerDeviceEnvelope& env) {
        ciphertext_blob = env.ciphertext_blob;
        ephemeral_public_key = env.ephemeral_public_key;
        iv = env.iv;
        auth_tag = env.auth_tag;
        algorithm = env.algorithm;
        protocol_version = env.protocol_version;
        one_time_prekey_id = env.one_time_prekey_id;
    }

    auto operator<=>(const DeviceDeliveryRecord& other) const noexcept = default;
    bool operator==(const DeviceDeliveryRecord& other) const noexcept = default;
};

/// Tracks delivery fan-out status for a message across recipient devices (delivery_state_by_message).
/// - Partition Key: message_id
/// - Clustering Key: recipient_device_id ASC
struct RecipientDeliveryState {
    MessageId message_id;
    DeviceId recipient_device_id;
    UserId recipient_user_id;
    DeliveryState delivery_state{DeliveryState::Pending};
    std::optional<std::chrono::system_clock::time_point> delivered_at{std::nullopt};
    std::optional<std::chrono::system_clock::time_point> read_at{std::nullopt};

    auto operator<=>(const RecipientDeliveryState& other) const noexcept = default;
    bool operator==(const RecipientDeliveryState& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
