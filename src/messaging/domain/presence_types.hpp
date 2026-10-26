#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_types.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"

#include <chrono>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::messaging::domain {

/// User online/active presence state (ephemeral operational status).
/// Distinct from durable delivery state (ADR-007, ADR-008).
enum class PresenceStatus : uint8_t {
    Unspecified = 0,
    Online = 1,
    Away = 2,
    Busy = 3,
    Offline = 4,
};

/// Maximum permissible length for custom status messages to prevent DoS/memory bloat.
inline constexpr size_t k_max_custom_status_length = 140;

/// Sanitizes custom status string, trimming excess whitespace and bounding to k_max_custom_status_length.
[[nodiscard]] inline std::string sanitize_status_message(std::string_view message,
                                                         size_t max_len = k_max_custom_status_length) noexcept {
    // Trim leading whitespace
    while (!message.empty() &&
           (message.front() == ' ' || message.front() == '\t' || message.front() == '\r' || message.front() == '\n')) {
        message.remove_prefix(1);
    }
    // Trim trailing whitespace
    while (!message.empty() &&
           (message.back() == ' ' || message.back() == '\t' || message.back() == '\r' || message.back() == '\n')) {
        message.remove_suffix(1);
    }
    if (message.size() > max_len) {
        message = message.substr(0, max_len);
    }
    return std::string(message);
}

/// Converts domain PresenceStatus to canonical string representation.
[[nodiscard]] constexpr std::string_view to_string(PresenceStatus status) noexcept {
    switch (status) {
    case PresenceStatus::Unspecified:
        return "UNSPECIFIED";
    case PresenceStatus::Online:
        return "ONLINE";
    case PresenceStatus::Away:
        return "AWAY";
    case PresenceStatus::Busy:
        return "BUSY";
    case PresenceStatus::Offline:
        return "OFFLINE";
    }
    return "UNSPECIFIED";
}

/// Parses canonical string to domain PresenceStatus.
[[nodiscard]] inline std::optional<PresenceStatus> parse_presence_status(std::string_view sv) noexcept {
    if (sv == "ONLINE" || sv == "online") {
        return PresenceStatus::Online;
    }
    if (sv == "AWAY" || sv == "away") {
        return PresenceStatus::Away;
    }
    if (sv == "BUSY" || sv == "busy") {
        return PresenceStatus::Busy;
    }
    if (sv == "OFFLINE" || sv == "offline") {
        return PresenceStatus::Offline;
    }
    if (sv == "UNSPECIFIED" || sv == "unspecified" || sv == "UNKNOWN" || sv == "unknown") {
        return PresenceStatus::Unspecified;
    }
    return std::nullopt;
}

/// Converts domain PresenceStatus to Protobuf PresenceStatus.
[[nodiscard]] constexpr securecloud::messaging::v1::PresenceStatus to_proto(PresenceStatus status) noexcept {
    switch (status) {
    case PresenceStatus::Unspecified:
        return securecloud::messaging::v1::PRESENCE_STATUS_UNSPECIFIED;
    case PresenceStatus::Online:
        return securecloud::messaging::v1::PRESENCE_STATUS_ONLINE;
    case PresenceStatus::Away:
        return securecloud::messaging::v1::PRESENCE_STATUS_AWAY;
    case PresenceStatus::Busy:
        return securecloud::messaging::v1::PRESENCE_STATUS_BUSY;
    case PresenceStatus::Offline:
        return securecloud::messaging::v1::PRESENCE_STATUS_OFFLINE;
    }
    return securecloud::messaging::v1::PRESENCE_STATUS_UNSPECIFIED;
}

/// Converts Protobuf PresenceStatus to domain PresenceStatus.
[[nodiscard]] constexpr PresenceStatus from_proto(securecloud::messaging::v1::PresenceStatus proto_status) noexcept {
    switch (proto_status) {
    case securecloud::messaging::v1::PRESENCE_STATUS_ONLINE:
        return PresenceStatus::Online;
    case securecloud::messaging::v1::PRESENCE_STATUS_AWAY:
        return PresenceStatus::Away;
    case securecloud::messaging::v1::PRESENCE_STATUS_BUSY:
        return PresenceStatus::Busy;
    case securecloud::messaging::v1::PRESENCE_STATUS_OFFLINE:
        return PresenceStatus::Offline;
    case securecloud::messaging::v1::PRESENCE_STATUS_UNSPECIFIED:
    default:
        return PresenceStatus::Unspecified;
    }
}

/// Ephemeral operational presence state for an authenticated user.
struct UserPresence {
    UserId user_id{};
    PresenceStatus status{PresenceStatus::Unspecified};
    std::chrono::system_clock::time_point last_active_at{};
    std::string custom_status_message{};
    size_t active_device_count{0};

    [[nodiscard]] bool is_online() const noexcept {
        return status == PresenceStatus::Online || status == PresenceStatus::Away || status == PresenceStatus::Busy;
    }

    auto operator<=>(const UserPresence& other) const noexcept = default;
    bool operator==(const UserPresence& other) const noexcept = default;
};

/// Converts domain UserPresence to Protobuf UserPresence message.
[[nodiscard]] inline securecloud::messaging::v1::UserPresence to_proto(const UserPresence& domain_presence) {
    securecloud::messaging::v1::UserPresence proto;
    proto.set_user_id(domain_presence.user_id.str());
    proto.set_status(to_proto(domain_presence.status));
    const auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(domain_presence.last_active_at.time_since_epoch())
            .count();
    proto.set_last_active_unix_ms(ms);
    proto.set_custom_status_message(domain_presence.custom_status_message);
    return proto;
}

/// Converts Protobuf UserPresence to domain UserPresence.
[[nodiscard]] inline UserPresence from_proto(const securecloud::messaging::v1::UserPresence& proto) {
    UserPresence domain;
    if (auto uid = UserId::from_string(proto.user_id()); uid.has_value()) {
        domain.user_id = *uid;
    } else {
        domain.user_id = UserId(proto.user_id());
    }
    domain.status = from_proto(proto.status());
    domain.last_active_at =
        std::chrono::system_clock::time_point(std::chrono::milliseconds(proto.last_active_unix_ms()));
    domain.custom_status_message = sanitize_status_message(proto.custom_status_message());
    return domain;
}

/// Command value object for user-initiated presence updates.
struct UpdatePresenceCommand {
    UserId user_id{};
    PresenceStatus status{PresenceStatus::Online};
    std::string custom_status_message{};
    std::chrono::system_clock::time_point updated_at{std::chrono::system_clock::now()};

    [[nodiscard]] bool is_valid() const noexcept { return !user_id.empty() && status != PresenceStatus::Unspecified; }
};

} // namespace securecloud::messaging::domain
