#include "repository/clickhouse_event_serializer.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#if defined(_WIN32)
#include <time.h>
#endif

namespace securecloud::audit::repository {

namespace {

std::string unescape_tab_separated(std::string_view input) {
    std::string result;
    result.reserve(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '\\' && i + 1 < input.size()) {
            switch (input[i + 1]) {
            case 't':
                result += '\t';
                ++i;
                break;
            case 'n':
                result += '\n';
                ++i;
                break;
            case '0':
                result += '\0';
                ++i;
                break;
            case '\\':
                result += '\\';
                ++i;
                break;
            default:
                result += input[i];
                break;
            }
        } else {
            result += input[i];
        }
    }
    return result;
}

std::string format_metadata_map(const std::unordered_map<std::string, std::string>& metadata) {
    if (metadata.empty()) {
        return "{}";
    }
    std::ostringstream ss;
    ss << "{";
    bool first = true;
    for (const auto& [k, v] : metadata) {
        if (!first)
            ss << ",";
        ss << "'" << ClickHouseEventSerializer::escape_tab_separated(k) << "':'"
           << ClickHouseEventSerializer::escape_tab_separated(v) << "'";
        first = false;
    }
    ss << "}";
    return ss.str();
}

} // namespace

std::string ClickHouseEventSerializer::escape_tab_separated(std::string_view input) {
    std::string escaped;
    escaped.reserve(input.size());
    for (char c : input) {
        switch (c) {
        case '\t':
            escaped += "\\t";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\0':
            escaped += "\\0";
            break;
        default:
            escaped += c;
            break;
        }
    }
    return escaped;
}

std::string ClickHouseEventSerializer::format_timestamp_ms(std::chrono::system_clock::time_point tp) {
    using namespace std::chrono;
    auto ms = duration_cast<milliseconds>(tp.time_since_epoch()) % 1000;
    auto timer = system_clock::to_time_t(tp);
    std::tm bt = *std::gmtime(&timer);

    std::ostringstream ss;
    ss << std::put_time(&bt, "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::chrono::system_clock::time_point ClickHouseEventSerializer::parse_timestamp_ms(const std::string& str) {
    if (str.empty())
        return {};
    std::tm tm_buf{};
    int ms = 0;
    std::istringstream ss(str);
    ss >> std::get_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    if (ss.peek() == '.') {
        ss.ignore();
        ss >> ms;
    }
#if defined(_WIN32)
    std::time_t t = _mkgmtime(&tm_buf);
#else
    std::time_t t = timegm(&tm_buf);
#endif
    return std::chrono::system_clock::from_time_t(t) + std::chrono::milliseconds(ms);
}

std::string ClickHouseEventSerializer::serialize_for_insert(const std::vector<domain::AuditEvent>& events) {
    if (events.empty())
        return "";

    std::ostringstream ss;
    for (const auto& ev : events) {
        std::string corr = ev.correlation_id.empty() ? "\\N" : escape_tab_separated(ev.correlation_id);
        std::string cause =
            (!ev.causation_id.has_value() || ev.causation_id->empty()) ? "\\N" : escape_tab_separated(*ev.causation_id);

        ss << ev.event_id.to_string() << "\t" << format_timestamp_ms(ev.occurred_at) << "\t"
           << format_timestamp_ms(ev.received_at.value_or(ev.occurred_at)) << "\t"
           << escape_tab_separated(ev.event_type) << "\t" << domain::to_string(ev.severity) << "\t"
           << domain::to_string(ev.producer_service) << "\t" << escape_tab_separated(ev.producer_instance) << "\t"
           << domain::to_string(ev.actor_type) << "\t" << escape_tab_separated(ev.actor_id) << "\t"
           << domain::to_string(ev.target_type) << "\t" << escape_tab_separated(ev.target_id) << "\t" << corr << "\t"
           << cause << "\t" << format_metadata_map(ev.metadata) << "\n";
    }
    return ss.str();
}

std::vector<domain::AuditEvent> ClickHouseEventSerializer::deserialize_from_query(const std::string& input) {
    std::vector<domain::AuditEvent> events;
    if (input.empty())
        return events;

    std::istringstream line_stream(input);
    std::string line;
    while (std::getline(line_stream, line)) {
        if (line.empty())
            continue;
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream token_stream(line);
        while (std::getline(token_stream, token, '\t')) {
            tokens.push_back(token);
        }
        if (tokens.size() < 14)
            continue;

        domain::AuditEvent ev{};
        if (auto id_opt = domain::EventId::from_string(tokens[0])) {
            ev.event_id = *id_opt;
        }
        ev.occurred_at = parse_timestamp_ms(tokens[1]);
        ev.received_at = parse_timestamp_ms(tokens[2]);
        ev.event_type = unescape_tab_separated(tokens[3]);
        ev.severity = domain::severity_from_string(tokens[4]).value_or(domain::Severity::Info);
        ev.producer_service = domain::producer_from_string(tokens[5]).value_or(domain::ProducerService::Audit);
        ev.producer_instance = unescape_tab_separated(tokens[6]);
        ev.actor_type = domain::actor_type_from_string(tokens[7]).value_or(domain::ActorType::User);
        ev.actor_id = unescape_tab_separated(tokens[8]);
        ev.target_type = domain::target_type_from_string(tokens[9]).value_or(domain::TargetType::Unknown);
        ev.target_id = unescape_tab_separated(tokens[10]);

        if (tokens[11] != "\\N" && !tokens[11].empty()) {
            ev.correlation_id = unescape_tab_separated(tokens[11]);
        }
        if (tokens[12] != "\\N" && !tokens[12].empty()) {
            ev.causation_id = unescape_tab_separated(tokens[12]);
        }

        std::string meta_str = tokens[13];
        if (meta_str.size() >= 2 && meta_str.front() == '{' && meta_str.back() == '}') {
            meta_str = meta_str.substr(1, meta_str.size() - 2);
            std::istringstream meta_stream(meta_str);
            std::string pair;
            while (std::getline(meta_stream, pair, ',')) {
                auto colon = pair.find(':');
                if (colon != std::string::npos) {
                    std::string k = pair.substr(0, colon);
                    std::string v = pair.substr(colon + 1);
                    if (k.size() >= 2 && k.front() == '\'' && k.back() == '\'')
                        k = k.substr(1, k.size() - 2);
                    if (v.size() >= 2 && v.front() == '\'' && v.back() == '\'')
                        v = v.substr(1, v.size() - 2);
                    ev.metadata[unescape_tab_separated(k)] = unescape_tab_separated(v);
                }
            }
        }

        events.push_back(ev);
    }
    return events;
}

} // namespace securecloud::audit::repository