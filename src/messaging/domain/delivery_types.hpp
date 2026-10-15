#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_types.hpp"

#include <chrono>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::messaging::domain {

/// Operational delivery status for a recipient device.
enum class DeliveryState : uint8_t {
    Pending = 1,
    Delivered = 2,
    Read = 3,
    RetryWait = 4,
    Expired = 5,
};

[[nodiscard]] inline std::string to_string(DeliveryState state) {
    switch (state) {
    case DeliveryState::Pending:
        return "PENDING";
    case DeliveryState::Delivered:
        return "DELIVERED";
    case DeliveryState::Read:
        return "READ";
    case DeliveryState::RetryWait:
        return "RETRY_WAIT";
    case DeliveryState::Expired:
        return "EXPIRED";
    }
    return "PENDING";
}

[[nodiscard]] inline std::optional<DeliveryState> delivery_state_from_string(std::string_view sv) noexcept {
    if (sv == "PENDING") {
        return DeliveryState::Pending;
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
