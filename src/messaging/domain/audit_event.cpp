#include "domain/audit_event.hpp"

#include <cstdio>
#include <ctime>

namespace securecloud::messaging::domain {

std::string_view to_string(MessagingAuditEventType type) noexcept {
    switch (type) {
    case MessagingAuditEventType::MessageSubmitted:
        return "message.submitted";
    case MessagingAuditEventType::MessageDelivered:
        return "message.delivered";
    case MessagingAuditEventType::MessageRead:
        return "message.read";
    case MessagingAuditEventType::MessageDeliveryFailed:
        return "message.delivery.failed";
    case MessagingAuditEventType::ConversationCreated:
        return "conversation.created";
    case MessagingAuditEventType::ConversationMembershipChanged:
        return "conversation.membership.changed";
    case MessagingAuditEventType::ConversationClosed:
        return "conversation.closed";
    case MessagingAuditEventType::SecurityAuthorizationDenied:
        return "security.authorization.denied";
    case MessagingAuditEventType::EmergencyActivated:
        return "emergency.activated";
    case MessagingAuditEventType::RateLimitExceeded:
        return "messaging.rate_limit.exceeded";
    }
    return "message.submitted";
}

std::optional<MessagingAuditEventType> messaging_audit_event_type_from_string(std::string_view sv) noexcept {
    if (sv == "message.submitted") {
        return MessagingAuditEventType::MessageSubmitted;
    }
    if (sv == "message.delivered") {
        return MessagingAuditEventType::MessageDelivered;
    }
    if (sv == "message.read") {
        return MessagingAuditEventType::MessageRead;
    }
    if (sv == "message.delivery.failed") {
        return MessagingAuditEventType::MessageDeliveryFailed;
    }
    if (sv == "conversation.created") {
        return MessagingAuditEventType::ConversationCreated;
    }
    if (sv == "conversation.membership.changed") {
        return MessagingAuditEventType::ConversationMembershipChanged;
    }
    if (sv == "conversation.closed") {
        return MessagingAuditEventType::ConversationClosed;
    }
    if (sv == "security.authorization.denied") {
        return MessagingAuditEventType::SecurityAuthorizationDenied;
    }
    if (sv == "emergency.activated") {
        return MessagingAuditEventType::EmergencyActivated;
    }
    if (sv == "messaging.rate_limit.exceeded") {
        return MessagingAuditEventType::RateLimitExceeded;
    }
    return std::nullopt;
}

std::string_view to_string(MessagingAuditSeverity severity) noexcept {
    switch (severity) {
    case MessagingAuditSeverity::Info:
        return "INFO";
    case MessagingAuditSeverity::Warning:
        return "WARNING";
    case MessagingAuditSeverity::Security:
        return "SECURITY";
    case MessagingAuditSeverity::Critical:
        return "CRITICAL";
    }
    return "INFO";
}

std::optional<MessagingAuditSeverity> messaging_audit_severity_from_string(std::string_view sv) noexcept {
    if (sv == "INFO") {
        return MessagingAuditSeverity::Info;
    }
    if (sv == "WARNING") {
        return MessagingAuditSeverity::Warning;
    }
    if (sv == "SECURITY") {
        return MessagingAuditSeverity::Security;
    }
    if (sv == "CRITICAL") {
        return MessagingAuditSeverity::Critical;
    }
    return std::nullopt;
}

MessagingAuditSeverity default_severity(MessagingAuditEventType type) noexcept {
    switch (type) {
    case MessagingAuditEventType::MessageSubmitted:
    case MessagingAuditEventType::MessageDelivered:
    case MessagingAuditEventType::MessageRead:
    case MessagingAuditEventType::ConversationCreated:
    case MessagingAuditEventType::ConversationMembershipChanged:
    case MessagingAuditEventType::ConversationClosed:
        return MessagingAuditSeverity::Info;
    case MessagingAuditEventType::MessageDeliveryFailed:
    case MessagingAuditEventType::RateLimitExceeded:
        return MessagingAuditSeverity::Warning;
    case MessagingAuditEventType::SecurityAuthorizationDenied:
        return MessagingAuditSeverity::Security;
    case MessagingAuditEventType::EmergencyActivated:
        return MessagingAuditSeverity::Critical;
    }
    return MessagingAuditSeverity::Info;
}

std::string compute_outbox_bucket_utc(std::chrono::system_clock::time_point tp) {
    const std::time_t raw_time = std::chrono::system_clock::to_time_t(tp);
    std::tm utc_tm{};
#if defined(_WIN32)
    gmtime_s(&utc_tm, &raw_time);
#else
    gmtime_r(&raw_time, &utc_tm);
#endif
    char buf[16]{};
    std::snprintf(buf, sizeof(buf), "%04d%02d%02d%02d", utc_tm.tm_year + 1900, utc_tm.tm_mon + 1, utc_tm.tm_mday,
                  utc_tm.tm_hour);
    return std::string(buf);
}

int32_t compute_outbox_shard_id(std::string_view routing_key) noexcept {
    // 64-bit FNV-1a deterministic hash for cross-platform consistent shard routing
    constexpr uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
    constexpr uint64_t kFnvPrime = 1099511628211ULL;

    uint64_t hash = kFnvOffsetBasis;
    for (unsigned char ch : routing_key) {
        hash ^= static_cast<uint64_t>(ch);
        hash *= kFnvPrime;
    }
    return static_cast<int32_t>(hash % static_cast<uint64_t>(kMessagingAuditOutboxShardCount));
}

} // namespace securecloud::messaging::domain
