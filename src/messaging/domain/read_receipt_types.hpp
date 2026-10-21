#pragma once

#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_types.hpp"

#include <chrono>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::messaging::domain {

/// User-facing logical read state (Presence != Delivery != Read != Sync).
/// Deliberately decoupled from per-device DeliveryState.
enum class ReadState : uint8_t {
    Unread = 1,
    Read = 2,
};

[[nodiscard]] inline std::string to_string(ReadState state) {
    switch (state) {
    case ReadState::Unread:
        return "UNREAD";
    case ReadState::Read:
        return "READ";
    }
    return "UNREAD";
}

[[nodiscard]] inline std::optional<ReadState> read_state_from_string(std::string_view sv) noexcept {
    if (sv == "UNREAD") {
        return ReadState::Unread;
    }
    if (sv == "READ") {
        return ReadState::Read;
    }
    return std::nullopt;
}

/// Read receipt state for an individual logical recipient user in a conversation.
/// Group conversations track read state per logical recipient user (never globally read).
struct LogicalRecipientReadStatus {
    UserId user_id;
    ReadState read_state{ReadState::Unread};
    std::optional<std::chrono::system_clock::time_point> read_at{std::nullopt};
    std::optional<DeviceId> reader_device_id{std::nullopt};

    auto operator<=>(const LogicalRecipientReadStatus& other) const noexcept = default;
    bool operator==(const LogicalRecipientReadStatus& other) const noexcept = default;
};

/// Delivery state for an individual target device of a recipient user.
/// Delivery state is strictly device-specific (ADR-007).
struct DeviceDeliveryStatus {
    DeviceId device_id;
    UserId recipient_user_id;
    DeliveryState delivery_state{DeliveryState::Queued};
    std::optional<std::chrono::system_clock::time_point> accepted_at{std::nullopt};
    std::optional<std::chrono::system_clock::time_point> delivered_at{std::nullopt};
    int32_t attempt_count{0};

    auto operator<=>(const DeviceDeliveryStatus& other) const noexcept = default;
    bool operator==(const DeviceDeliveryStatus& other) const noexcept = default;
};

/// High-level delivery and read status summary for an entire message across all targets.
struct MessageDeliverySummary {
    MessageId message_id;
    ConversationId conversation_id;
    uint32_t total_targets{0};
    uint32_t delivered_targets{0};
    uint32_t pending_targets{0};
    uint32_t expired_targets{0};
    std::vector<DeviceDeliveryStatus> device_statuses;
    std::vector<LogicalRecipientReadStatus> recipient_read_statuses;

    auto operator<=>(const MessageDeliverySummary& other) const noexcept = default;
    bool operator==(const MessageDeliverySummary& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
