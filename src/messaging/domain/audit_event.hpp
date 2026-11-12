#pragma once

#include "domain/message_types.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::messaging::domain {

/// Canonical audit event taxonomy owned by the Messaging Service (AUDIT-014 / AUDIT-002).
enum class MessagingAuditEventType : uint8_t {
    MessageSubmitted = 1,
    MessageDelivered = 2,
    MessageRead = 3,
    MessageDeliveryFailed = 4,
    ConversationCreated = 5,
    ConversationMembershipChanged = 6,
    ConversationClosed = 7,
    SecurityAuthorizationDenied = 8,
    EmergencyActivated = 9,
    RateLimitExceeded = 10,
};

/// Canonical severity classification aligned with securecloud.audit.v1.SeverityProto.
enum class MessagingAuditSeverity : uint8_t {
    Info = 1,
    Warning = 2,
    Security = 3,
    Critical = 4,
};

[[nodiscard]] std::string_view to_string(MessagingAuditEventType type) noexcept;

[[nodiscard]] std::optional<MessagingAuditEventType>
messaging_audit_event_type_from_string(std::string_view sv) noexcept;

[[nodiscard]] std::string_view to_string(MessagingAuditSeverity severity) noexcept;

[[nodiscard]] std::optional<MessagingAuditSeverity> messaging_audit_severity_from_string(std::string_view sv) noexcept;

/// Returns the default canonical severity for a given MessagingAuditEventType.
[[nodiscard]] MessagingAuditSeverity default_severity(MessagingAuditEventType type) noexcept;

/// Number of independent ScyllaDB outbox shards per hourly bucket (0..15).
inline constexpr int32_t kMessagingAuditOutboxShardCount = 16;

/// Formats a UTC timestamp into the hourly partition bucket `YYYYMMDDHH`.
[[nodiscard]] std::string compute_outbox_bucket_utc(std::chrono::system_clock::time_point tp);

/// Deterministically maps a routing key (e.g. conversation_id) to a shard in [0, 15].
[[nodiscard]] int32_t compute_outbox_shard_id(std::string_view routing_key) noexcept;

/// Canonical domain representation of a Messaging audit event prior to ScyllaDB outbox persistence.
struct MessagingAuditEvent {
    std::string event_id;
    MessagingAuditEventType event_type{MessagingAuditEventType::MessageSubmitted};
    MessagingAuditSeverity severity{MessagingAuditSeverity::Info};
    std::chrono::system_clock::time_point occurred_at{};
    UserId actor_user_id{};
    DeviceId actor_device_id{};
    std::string target_resource;
    std::string payload_json{"{}"};
    std::string correlation_id;

    auto operator<=>(const MessagingAuditEvent& other) const noexcept = default;
    bool operator==(const MessagingAuditEvent& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
