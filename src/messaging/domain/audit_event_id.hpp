#pragma once

#include "domain/audit_event.hpp"
#include "domain/message_types.hpp"

#include <string>
#include <string_view>

namespace securecloud::messaging::domain {

/// Generates a deterministic, retry-safe RFC 9562 UUIDv7 event_id derived from
/// a canonical MessageId and MessagingAuditEventType for idempotent forward recovery.
/// Preserves the original 48-bit millisecond timestamp of `msg_id`.
/// Throws std::invalid_argument if `msg_id` is nil.
[[nodiscard]] std::string generate_message_audit_event_id(const MessageId& msg_id, MessagingAuditEventType type);

/// Generates a fresh random RFC 9562 UUIDv7 string for non-message-scoped audit events.
[[nodiscard]] std::string generate_audit_event_id();

/// Validates whether `value` is a canonical lowercase/hex RFC 9562 UUIDv7 string.
[[nodiscard]] bool is_valid_audit_uuid_v7(std::string_view value) noexcept;

} // namespace securecloud::messaging::domain
