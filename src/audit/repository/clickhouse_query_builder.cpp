#include "repository/clickhouse_query_builder.hpp"

#include <chrono>
#include <sstream>

namespace securecloud::audit::repository {

ParameterizedClickHouseQuery ClickHouseQueryBuilder::build_filter_query(
    const query::AuditQueryFilter& filter,
    const std::optional<query::AuditPageCursor>& cursor) {

    ParameterizedClickHouseQuery query;
    std::ostringstream sql;

    sql << "SELECT event_id, occurred_at, received_at, event_type, severity, producer_service, "
           "producer_instance, actor_type, actor_id, target_type, target_id, correlation_id, "
           "causation_id, metadata FROM securecloud_audit.audit_events WHERE ";

    // 1. Mandatory time window bounds
    sql << "occurred_at >= fromUnixTimestamp64Milli({start_ms:Int64}) AND occurred_at < fromUnixTimestamp64Milli({end_ms:Int64})";

    int64_t start_ms = filter.start_occurred_at.has_value()
        ? std::chrono::duration_cast<std::chrono::milliseconds>(filter.start_occurred_at->time_since_epoch()).count()
        : 0;
    int64_t end_ms = filter.end_occurred_at.has_value()
        ? std::chrono::duration_cast<std::chrono::milliseconds>(filter.end_occurred_at->time_since_epoch()).count()
        : 0;

    query.bind_params["start_ms"] = std::to_string(start_ms);
    query.bind_params["end_ms"] = std::to_string(end_ms);

    // 2. Producer service filter
    if (!filter.producer_services.empty()) {
        if (filter.producer_services.size() == 1) {
            sql << " AND producer_service = {producer_0:String}";
            query.bind_params["producer_0"] = domain::to_string(filter.producer_services[0]);
        } else {
            sql << " AND producer_service IN (";
            for (size_t i = 0; i < filter.producer_services.size(); ++i) {
                std::string key = "producer_" + std::to_string(i);
                if (i > 0) sql << ", ";
                sql << "{" << key << ":String}";
                query.bind_params[key] = domain::to_string(filter.producer_services[i]);
            }
            sql << ")";
        }
    }

    // 3. Event types filter
    if (!filter.event_types.empty()) {
        if (filter.event_types.size() == 1) {
            sql << " AND event_type = {event_type_0:String}";
            query.bind_params["event_type_0"] = filter.event_types[0];
        } else {
            sql << " AND event_type IN (";
            for (size_t i = 0; i < filter.event_types.size(); ++i) {
                std::string key = "event_type_" + std::to_string(i);
                if (i > 0) sql << ", ";
                sql << "{" << key << ":String}";
                query.bind_params[key] = filter.event_types[i];
            }
            sql << ")";
        }
    }

    // 4. Severities filter
    if (!filter.severities.empty()) {
        sql << " AND severity IN (";
        for (size_t i = 0; i < filter.severities.size(); ++i) {
            std::string key = "severity_" + std::to_string(i);
            if (i > 0) sql << ", ";
            sql << "{" << key << ":String}";
            query.bind_params[key] = domain::to_string(filter.severities[i]);
        }
        sql << ")";
    }

    // 5. Actor identity
    if (filter.actor_type.has_value() && filter.actor_id.has_value()) {
        sql << " AND actor_type = {actor_type:String} AND actor_id = {actor_id:String}";
        query.bind_params["actor_type"] = domain::to_string(*filter.actor_type);
        query.bind_params["actor_id"] = *filter.actor_id;
    }

    // 6. Target identity
    if (filter.target_type.has_value() && filter.target_id.has_value()) {
        sql << " AND target_type = {target_type:String} AND target_id = {target_id:String}";
        query.bind_params["target_type"] = domain::to_string(*filter.target_type);
        query.bind_params["target_id"] = *filter.target_id;
    }

    // 7. Correlation ID
    if (filter.correlation_id.has_value()) {
        sql << " AND correlation_id = {correlation_id:String}";
        query.bind_params["correlation_id"] = *filter.correlation_id;
    }

    // 8. Keyset Cursor Tuple Predicate
    if (cursor.has_value()) {
        std::string comp = (filter.sort_order == query::SortOrder::Descending) ? "<" : ">";
        sql << " AND (occurred_at, producer_service, event_type, event_id) " << comp
            << " (fromUnixTimestamp64Milli({cursor_ts:Int64}), {cursor_prod:String}, {cursor_type:String}, {cursor_id:UUID})";

        query.bind_params["cursor_ts"] = std::to_string(cursor->last_occurred_at_ms);
        query.bind_params["cursor_prod"] = cursor->last_producer_service;
        query.bind_params["cursor_type"] = cursor->last_event_type;
        query.bind_params["cursor_id"] = cursor->last_event_id.to_string();
    }

    // 9. Sort Order & Duplicate Suppression
    if (filter.sort_order == query::SortOrder::Descending) {
        sql << " ORDER BY occurred_at DESC, producer_service DESC, event_type DESC, event_id DESC";
    } else {
        sql << " ORDER BY occurred_at ASC, producer_service ASC, event_type ASC, event_id ASC";
    }

    // Deduplicate physical rows for the same event_id
    sql << " LIMIT 1 BY event_id";

    // Request page_size + 1 to evaluate has_more lookahead
    uint32_t fetch_limit = filter.page_size + 1;
    sql << " LIMIT {limit_plus_one:UInt32} FORMAT TabSeparated";
    query.bind_params["limit_plus_one"] = std::to_string(fetch_limit);

    query.sql_template = sql.str();
    return query;
}

ParameterizedClickHouseQuery ClickHouseQueryBuilder::build_get_by_id_query(const domain::EventId& event_id) {
    ParameterizedClickHouseQuery query;
    uint64_t ts_ms = event_id.timestamp_ms();

    // Partition pruning skew window: +/- 10 minutes (600,000 ms)
    constexpr uint64_t kSkewWindowMs = 600000;
    int64_t min_ts = static_cast<int64_t>(ts_ms > kSkewWindowMs ? ts_ms - kSkewWindowMs : 0);
    int64_t max_ts = static_cast<int64_t>(ts_ms + kSkewWindowMs);

    std::ostringstream sql;
    sql << "SELECT event_id, occurred_at, received_at, event_type, severity, producer_service, "
           "producer_instance, actor_type, actor_id, target_type, target_id, correlation_id, "
           "causation_id, metadata FROM securecloud_audit.audit_events "
           "WHERE occurred_at >= fromUnixTimestamp64Milli({uuid_ts_min:Int64}) "
           "AND occurred_at <= fromUnixTimestamp64Milli({uuid_ts_max:Int64}) "
           "AND event_id = {event_id:UUID} LIMIT 1 FORMAT TabSeparated";

    query.sql_template = sql.str();
    query.bind_params["uuid_ts_min"] = std::to_string(min_ts);
    query.bind_params["uuid_ts_max"] = std::to_string(max_ts);
    query.bind_params["event_id"] = event_id.to_string();

    return query;
}

} // namespace securecloud::audit::repository