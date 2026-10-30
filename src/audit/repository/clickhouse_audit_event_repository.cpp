#include "clickhouse_audit_event_repository.hpp"

#include "clickhouse_event_serializer.hpp"
#include "domain/audit_event.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace securecloud::audit::repository {

ClickHouseAuditEventRepository::ClickHouseAuditEventRepository(std::shared_ptr<ClickHouseClient> client)
    : client_(std::move(client)) {}

uint32_t ClickHouseAuditEventRepository::clamp_limit(uint32_t limit) const noexcept {
    if (limit == 0)
        return kMaxQueryLimit;
    return std::min(limit, kMaxQueryLimit);
}

std::string ClickHouseAuditEventRepository::escape_sql_string(const std::string& str) {
    std::string escaped;
    escaped.reserve(str.size());
    for (char c : str) {
        if (c == '\'')
            escaped += "\\'";
        else if (c == '\\')
            escaped += "\\\\";
        else
            escaped += c;
    }
    return escaped;
}

bool ClickHouseAuditEventRepository::insert_batch(const std::vector<domain::AuditEvent>& events) {
    if (events.empty())
        return true;

    std::string body_data = ClickHouseEventSerializer::serialize_for_insert(events);
    std::string query = "INSERT INTO audit_events FORMAT TabSeparated";

    return client_->execute_insert(query, body_data);
}

std::vector<domain::AuditEvent>
ClickHouseAuditEventRepository::query_by_time_range(std::chrono::system_clock::time_point start,
                                                    std::chrono::system_clock::time_point end, uint32_t limit) {

    uint32_t clamped_limit = clamp_limit(limit);
    std::string start_str = ClickHouseEventSerializer::format_timestamp_ms(start);
    std::string end_str = ClickHouseEventSerializer::format_timestamp_ms(end);

    std::ostringstream ss;
    ss << "SELECT * FROM audit_events WHERE occurred_at >= toDateTime64('" << start_str
       << "', 3, 'UTC') AND occurred_at <= toDateTime64('" << end_str
       << "', 3, 'UTC') ORDER BY occurred_at DESC, producer_service, event_type, event_id LIMIT " << clamped_limit
       << " FORMAT TabSeparated";

    std::string response;
    if (!client_->execute_query(ss.str(), &response)) {
        return {};
    }

    return ClickHouseEventSerializer::deserialize_from_query(response);
}

std::vector<domain::AuditEvent>
ClickHouseAuditEventRepository::query_by_producer(const std::string& producer_service,
                                                  std::chrono::system_clock::time_point start,
                                                  std::chrono::system_clock::time_point end, uint32_t limit) {

    uint32_t clamped_limit = clamp_limit(limit);
    std::string start_str = ClickHouseEventSerializer::format_timestamp_ms(start);
    std::string end_str = ClickHouseEventSerializer::format_timestamp_ms(end);

    std::string lower_producer = producer_service;
    std::transform(lower_producer.begin(), lower_producer.end(), lower_producer.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::string normalized_producer = lower_producer;
    if (auto prod_opt = domain::producer_from_string(lower_producer)) {
        normalized_producer = domain::to_string(*prod_opt);
    } else if (auto prod_opt_orig = domain::producer_from_string(producer_service)) {
        normalized_producer = domain::to_string(*prod_opt_orig);
    }
    std::string escaped_producer = escape_sql_string(normalized_producer);

    std::ostringstream ss;
    ss << "SELECT * FROM audit_events WHERE producer_service = '" << escaped_producer
       << "' AND occurred_at >= toDateTime64('" << start_str << "', 3, 'UTC') AND occurred_at <= toDateTime64('"
       << end_str << "', 3, 'UTC') ORDER BY occurred_at DESC, producer_service, event_type, event_id LIMIT "
       << clamped_limit << " FORMAT TabSeparated";

    std::string response;
    if (!client_->execute_query(ss.str(), &response)) {
        return {};
    }

    return ClickHouseEventSerializer::deserialize_from_query(response);
}

std::vector<domain::AuditEvent>
ClickHouseAuditEventRepository::query_by_correlation_id(const std::string& correlation_id, uint32_t limit) {

    uint32_t clamped_limit = clamp_limit(limit);
    std::string escaped_corr_id = escape_sql_string(correlation_id);

    std::ostringstream ss;
    ss << "SELECT * FROM audit_events WHERE correlation_id = '" << escaped_corr_id
       << "' ORDER BY occurred_at DESC, producer_service, event_type, event_id LIMIT " << clamped_limit
       << " FORMAT TabSeparated";

    std::string response;
    if (!client_->execute_query(ss.str(), &response)) {
        return {};
    }

    return ClickHouseEventSerializer::deserialize_from_query(response);
}

std::optional<domain::AuditEvent> ClickHouseAuditEventRepository::find_by_event_id(const domain::EventId& event_id) {

    std::ostringstream ss;
    ss << "SELECT * FROM audit_events WHERE event_id = '" << event_id.to_string() << "' LIMIT 1 FORMAT TabSeparated";

    std::string response;
    if (!client_->execute_query(ss.str(), &response)) {
        return std::nullopt;
    }

    auto events = ClickHouseEventSerializer::deserialize_from_query(response);
    if (events.empty()) {
        return std::nullopt;
    }

    return events.front();
}

} // namespace securecloud::audit::repository