#pragma once

#include "auth/domain/uuid.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::auth::domain {

enum class OutboxStatus {
    Pending,
    Published,
    Failed,
    Quarantined,
};

[[nodiscard]] constexpr std::string_view to_string(OutboxStatus status) noexcept {
    switch (status) {
    case OutboxStatus::Pending:
        return "PENDING";
    case OutboxStatus::Published:
        return "PUBLISHED";
    case OutboxStatus::Failed:
        return "FAILED";
    case OutboxStatus::Quarantined:
        return "QUARANTINED";
    }
    return "UNKNOWN";
}

[[nodiscard]] inline std::optional<OutboxStatus> parse_outbox_status(std::string_view str) noexcept {
    if (str == "PENDING" || str == "Pending") {
        return OutboxStatus::Pending;
    }
    if (str == "PUBLISHED" || str == "Published") {
        return OutboxStatus::Published;
    }
    if (str == "FAILED" || str == "Failed") {
        return OutboxStatus::Failed;
    }
    if (str == "QUARANTINED" || str == "Quarantined") {
        return OutboxStatus::Quarantined;
    }
    return std::nullopt;
}

enum class OutboxSeverity {
    Info,
    Warning,
    Security,
    Critical,
};

[[nodiscard]] constexpr std::string_view to_string(OutboxSeverity severity) noexcept {
    switch (severity) {
    case OutboxSeverity::Info:
        return "INFO";
    case OutboxSeverity::Warning:
        return "WARNING";
    case OutboxSeverity::Security:
        return "SECURITY";
    case OutboxSeverity::Critical:
        return "CRITICAL";
    }
    return "INFO";
}

[[nodiscard]] inline std::optional<OutboxSeverity> parse_outbox_severity(std::string_view str) noexcept {
    if (str == "INFO" || str == "Info") {
        return OutboxSeverity::Info;
    }
    if (str == "WARNING" || str == "Warning") {
        return OutboxSeverity::Warning;
    }
    if (str == "SECURITY" || str == "Security") {
        return OutboxSeverity::Security;
    }
    if (str == "CRITICAL" || str == "Critical") {
        return OutboxSeverity::Critical;
    }
    return std::nullopt;
}

struct AuthOutboxEntity {
    Uuid event_id;
    std::string aggregate_type;
    std::optional<Uuid> aggregate_id;
    std::string event_type;
    OutboxSeverity severity{OutboxSeverity::Info};
    std::string payload_json;
    OutboxStatus status{OutboxStatus::Pending};
    int32_t retry_count{0};
    std::chrono::system_clock::time_point created_at{std::chrono::system_clock::now()};
    std::optional<std::chrono::system_clock::time_point> processed_at{std::nullopt};
    std::optional<std::string> last_error{std::nullopt};
    std::optional<std::chrono::system_clock::time_point> leased_until{std::nullopt};
};

} // namespace securecloud::auth::domain
