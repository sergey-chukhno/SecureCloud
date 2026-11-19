#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace securecloud::files {

/// Authoritative status of transactional outbox events (`V002`)
enum class OutboxStatus { Pending, Published, Failed, Quarantined };

/// Canonical audit event severity levels aligned with `AUDIT-002` / `V002`
enum class OutboxSeverity { Info, Warning, Security, Critical };

[[nodiscard]] inline std::string to_string(OutboxSeverity severity) {
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
    throw std::invalid_argument("Unknown OutboxSeverity enum value: " + std::to_string(static_cast<int>(severity)));
}

[[nodiscard]] inline OutboxSeverity outbox_severity_from_string(std::string_view str) {
    if (str == "INFO") {
        return OutboxSeverity::Info;
    }
    if (str == "WARNING") {
        return OutboxSeverity::Warning;
    }
    if (str == "SECURITY") {
        return OutboxSeverity::Security;
    }
    if (str == "CRITICAL") {
        return OutboxSeverity::Critical;
    }
    throw std::invalid_argument("Invalid OutboxSeverity string: " + std::string(str));
}

/// Strongly typed C++20 domain entity for transactional outbox audit events.
/// Enforces the Transactional Outbox Pattern (ADR-005, ADR-007 §18-23, Files Design 6.22)
/// for atomic state changes, time-bounded row leasing, and quarantine isolation.
/// Maps 1:1 to the `files_outbox` PostgreSQL table (`V002`).
struct FilesOutboxEntity {
    std::string event_id{};
    std::string aggregate_type{"FILE"};
    std::optional<std::string> aggregate_id{std::nullopt};
    std::string event_type{};
    OutboxSeverity severity{OutboxSeverity::Info};
    std::string payload_json{};
    OutboxStatus status{OutboxStatus::Pending};
    int32_t retry_count{0};
    std::chrono::system_clock::time_point created_at{};
    std::optional<std::chrono::system_clock::time_point> processed_at{std::nullopt};
    std::optional<std::string> last_error{std::nullopt};
    std::optional<std::chrono::system_clock::time_point> leased_until{std::nullopt};

    bool operator==(const FilesOutboxEntity& other) const = default;
};

} // namespace securecloud::files
