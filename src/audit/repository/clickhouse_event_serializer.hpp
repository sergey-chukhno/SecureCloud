#pragma once

#include "domain/audit_event.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::audit::repository {

    /// High-throughput serialization and deserialization engine for ClickHouse.
    /// Handles TabSeparated formatting with strict escape sequence support for batch inserts,
    /// as well as stream parsing for query response evaluation.
    class ClickHouseEventSerializer {
    public:
        /// Serializes a batch of audit events into ClickHouse TabSeparated format for bulk insertion.
        /// Expected column ordering:
        /// event_id, occurred_at, received_at, event_type, severity, producer_service,
        /// producer_instance, actor_type, actor_id, target_type, target_id,
        /// correlation_id, causation_id, event_data
        [[nodiscard]] static std::string serialize_for_insert(const std::vector<domain::AuditEvent>& events);

        /// Deserializes ClickHouse TabSeparated response streams into canonical domain::AuditEvent objects.
        [[nodiscard]] static std::vector<domain::AuditEvent> deserialize_from_query(const std::string& response_body);

        /// Escapes a string_view according to ClickHouse TabSeparated protocol rules (\n, \t, \\).
        [[nodiscard]] static std::string escape_tab_separated(std::string_view input);

        /// Formats a system_clock::time_point into "YYYY-MM-DD HH:MM:SS.mmm" (UTC).
        [[nodiscard]] static std::string format_timestamp_ms(std::chrono::system_clock::time_point tp);

        /// Parses an ISO-8601 or ClickHouse formatted timestamp string into a system_clock::time_point.
        [[nodiscard]] static std::chrono::system_clock::time_point parse_timestamp_ms(const std::string& str);
    };

} // namespace securecloud::audit::repository