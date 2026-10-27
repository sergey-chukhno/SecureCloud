#include "clickhouse_event_serializer.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace securecloud::audit::repository {

std::string ClickHouseEventSerializer::escape_tab_separated(std::string_view input) {
    std::string escaped;
    escaped.reserve(input.size());

    for (char c : input) {
        switch (c) {
            case '\t': escaped += "\\t"; break;
            case '\n': escaped += "\\n"; break;
            case '\\': escaped += "\\\\"; break;
            case '\0': escaped += "\\0"; break;
            default:   escaped += c; break;
        }
    }
    return escaped;
}

std::string ClickHouseEventSerializer::format_timestamp_ms(std::chrono::system_clock::time_point tp) {
    auto duration = tp.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration) % 1000;
    std::time_t timer = std::chrono::system_clock::to_time_t(tp);

    std::tm gmt{};
#if defined(_WIN32)
    gmtime_s(&gmt, &timer);
#else
    gmtime_r(&timer, &gmt);
#endif

    std::ostringstream ss;
    ss << std::put_time(&gmt, "%Y-%m-%d %H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << millis.count();
    return ss.str();
}

std::chrono::system_clock::time_point ClickHouseEventSerializer::parse_timestamp_ms(const std::string& str) {
    if (str.empty() || str == "\\N") {
        return std::chrono::system_clock::time_point{};
    }

    std::tm tm{};
    int millis = 0;
    std::istringstream ss(str);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");

    if (ss.peek() == '.') {
        ss.ignore();
        ss >> millis;
    }

    std::time_t time_sec;
#if defined(_WIN32)
    time_sec = _mkgmtime(&tm);
#else
    time_sec = timegm(&tm);
#endif

    auto tp = std::chrono::system_clock::from_time_t(time_sec);
    return tp + std::chrono::milliseconds(millis);
}

std::string ClickHouseEventSerializer::serialize_for_insert(const std::vector<domain::AuditEvent>& events) {
    std::string buffer;
    buffer.reserve(events.size() * 256); // Estimated 256 bytes per record

    for (const auto& ev : events) {
        // 1. event_id (UUID string)
        buffer += ev.event_id.to_string();
        buffer += '\t';

        // 2. occurred_at
        buffer += format_timestamp_ms(ev.occurred_at);
        buffer += '\t';

        // 3. received_at (Fallback to current time if nullopt)
        if (ev.received_at.has_value()) {
            buffer += format_timestamp_ms(ev.received_at.value());
        } else {
            buffer += format_timestamp_ms(std::chrono::system_clock::now());
        }
        buffer += '\t';

        // 4. event_type
        buffer += escape_tab_separated(ev.event_type);
        buffer += '\t';

        // 5. severity (Enum string_view to string via escape_tab_separated)
        buffer += escape_tab_separated(domain::to_string(ev.severity));
        buffer += '\t';

        // 6. producer_service
        buffer += escape_tab_separated(domain::to_string(ev.producer_service));
        buffer += '\t';

        // 7. producer_instance
        buffer += escape_tab_separated(ev.producer_instance);
        buffer += '\t';

        // 8. actor_type
        buffer += escape_tab_separated(domain::to_string(ev.actor_type));
        buffer += '\t';

        // 9. actor_id
        buffer += escape_tab_separated(ev.actor_id);
        buffer += '\t';

        // 10. target_type
        buffer += escape_tab_separated(domain::to_string(ev.target_type));
        buffer += '\t';

        // 11. target_id
        buffer += escape_tab_separated(ev.target_id);
        buffer += '\t';

        // 12. correlation_id
        buffer += escape_tab_separated(ev.correlation_id);
        buffer += '\t';

        // 13. causation_id
        if (ev.causation_id.has_value()) {
            buffer += escape_tab_separated(ev.causation_id.value());
        } else {
            buffer += "00000000-0000-0000-0000-000000000000";
        }
        buffer += '\t';

        // 14. event_data (metadata map serialized as JSON string)
        nlohmann::json j_meta = ev.metadata;
        buffer += escape_tab_separated(j_meta.dump());
        buffer += '\n';
    }

    return buffer;
}

std::vector<domain::AuditEvent> ClickHouseEventSerializer::deserialize_from_query(const std::string& response_body) {
    std::vector<domain::AuditEvent> events;
    if (response_body.empty()) return events;

    std::istringstream stream(response_body);
    std::string line;

    while (std::getline(stream, line)) {
        if (line.empty()) continue;

        std::vector<std::string> fields;
        std::string current_field;
        bool in_escape = false;

        for (size_t i = 0; i < line.size(); ++i) {
            char c = line[i];
            if (in_escape) {
                switch (c) {
                    case 't': current_field += '\t'; break;
                    case 'n': current_field += '\n'; break;
                    case '\\': current_field += '\\'; break;
                    case '0': current_field += '\0'; break;
                    default: current_field += c; break;
                }
                in_escape = false;
            } else if (c == '\\') {
                in_escape = true;
            } else if (c == '\t') {
                fields.push_back(current_field);
                current_field.clear();
            } else {
                current_field += c;
            }
        }
        fields.push_back(current_field);

        if (fields.size() < 14) continue; // Skip incomplete lines

        domain::AuditEvent ev;
        if (auto parsed_id = domain::EventId::from_string(fields[0])) {
            ev.event_id = *parsed_id;
        }

        ev.occurred_at = parse_timestamp_ms(fields[1]);
        if (fields[2] != "\\N" && !fields[2].empty()) {
            ev.received_at = parse_timestamp_ms(fields[2]);
        }

        ev.event_type = fields[3];
        ev.severity = domain::severity_from_string(fields[4]).value_or(domain::Severity::Info);
        ev.producer_service = domain::producer_from_string(fields[5]).value_or(domain::ProducerService::Audit);
        ev.producer_instance = fields[6];
        ev.actor_type = domain::actor_type_from_string(fields[7]).value_or(domain::ActorType::Unknown);
        ev.actor_id = fields[8];
        ev.target_type = domain::target_type_from_string(fields[9]).value_or(domain::TargetType::Unknown);
        ev.target_id = fields[10];
        ev.correlation_id = fields[11];

        if (fields[12] != "00000000-0000-0000-0000-000000000000" && !fields[12].empty()) {
            ev.causation_id = fields[12];
        }

        if (!fields[13].empty() && fields[13] != "{}") {
            try {
                auto j = nlohmann::json::parse(fields[13]);
                ev.metadata = j.get<std::unordered_map<std::string, std::string>>();
            } catch (...) {
                // Keep empty metadata on parse exception
            }
        }

        events.push_back(ev);
    }

    return events;
}

} // namespace securecloud::audit::repository