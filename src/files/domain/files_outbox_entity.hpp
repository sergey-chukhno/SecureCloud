#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace securecloud::files {

/// Authoritative status of transactional outbox events
enum class OutboxStatus { Pending, Published, Failed };

/// Strongly typed C++20 domain entity for transactional outbox audit events.
/// Enforces the Transactional Outbox Pattern (ADR-005, Files Design 6.22) for
/// atomic state changes and guaranteed at-least-once audit dispatch.
/// Maps 1:1 to the `files_outbox` PostgreSQL table.
struct FilesOutboxEntity {
    std::string event_id{};
    std::string aggregate_type{"FILE"};
    std::string aggregate_id{};
    std::string event_type{};
    std::string payload_json{};
    OutboxStatus status{OutboxStatus::Pending};
    int32_t retry_count{0};
    std::chrono::system_clock::time_point created_at{};
    std::optional<std::chrono::system_clock::time_point> processed_at{std::nullopt};

    bool operator==(const FilesOutboxEntity& other) const = default;
};

} // namespace securecloud::files
