#include "repository/schema_initializer.hpp"

#include <chrono>
#include <httplib.h>
#include <iostream>
#include <sstream>

namespace securecloud::audit::repository {

namespace {

constexpr const char* DDL_CREATE_DATABASE = "CREATE DATABASE IF NOT EXISTS securecloud_audit;";

constexpr const char* DDL_CREATE_TABLE = R"(
CREATE TABLE IF NOT EXISTS securecloud_audit.audit_events
(
    event_id UUID,
    occurred_at DateTime64(3, 'UTC'),
    received_at DateTime64(3, 'UTC'),
    event_type LowCardinality(String),
    severity LowCardinality(String),
    producer_service LowCardinality(String),
    producer_instance String,
    actor_type LowCardinality(String),
    actor_id String,
    target_type LowCardinality(String),
    target_id String,
    correlation_id UUID,
    causation_id UUID,
    event_data String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (occurred_at, producer_service, event_type, event_id)
TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE;
)";

constexpr const char* DDL_ALTER_TTL = R"(
ALTER TABLE securecloud_audit.audit_events MODIFY TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE;
)";

} // namespace

SchemaInitializer::SchemaInitializer(const ClickHouseConfig& config) : config_(config) {}

bool SchemaInitializer::execute_http_query(const std::string& query, std::string* out_response) const {
    httplib::Client client(config_.host, config_.port);

    const auto conn_sec = std::chrono::milliseconds(config_.connect_timeout_ms);
    const auto req_sec = std::chrono::milliseconds(config_.request_timeout_ms);
    client.set_connection_timeout(conn_sec);
    client.set_read_timeout(req_sec);
    client.set_write_timeout(req_sec);

    httplib::Headers headers = {{"X-ClickHouse-User", config_.user},
                                {"X-ClickHouse-Key", config_.password.expose_unredacted_secret()}};

    std::string path = "/";
    if (query.find("CREATE DATABASE") == std::string::npos && !config_.db_name.empty()) {
        path += "?database=" + config_.db_name;
    }

    auto res = client.Post(path.c_str(), headers, query, "text/plain");

    if (!res || res->status != 200) {
        return false;
    }

    if (out_response != nullptr) {
        *out_response = res->body;
    }

    return true;
}

SchemaInitResult SchemaInitializer::initialize_schema() const {
    if (!execute_http_query(DDL_CREATE_DATABASE)) {
        return SchemaInitResult::DatabaseConnectionFailed;
    }

    if (!execute_http_query(DDL_CREATE_TABLE)) {
        return SchemaInitResult::MigrationExecutionFailed;
    }

    if (!execute_http_query(DDL_ALTER_TTL)) {
        return SchemaInitResult::MigrationExecutionFailed;
    }

    if (!verify_schema_integrity()) {
        return SchemaInitResult::DatabaseVerificationFailed;
    }

    return SchemaInitResult::Success;
}

SchemaVerificationReport SchemaInitializer::verify_effective_schema() const {
    SchemaVerificationReport report;
    std::string response;

    const std::string inspection_query = "SELECT engine, partition_key, sorting_key, create_table_query "
                                         "FROM system.tables "
                                         "WHERE database = 'securecloud_audit' AND name = 'audit_events' "
                                         "FORMAT TabSeparated;";

    if (!execute_http_query(inspection_query, &response) || response.empty()) {
        report.violations.push_back("Failed to query system.tables or audit_events table does not exist.");
        report.is_valid = false;
        return report;
    }

    std::string line = response;
    if (!line.empty() && line.back() == '\n') {
        line.pop_back();
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    std::stringstream ss(line);
    std::getline(ss, report.engine, '\t');
    std::getline(ss, report.partition_key, '\t');
    std::getline(ss, report.sorting_key, '\t');
    std::getline(ss, report.create_table_query, '\t');

    if (report.engine != "MergeTree") {
        report.violations.push_back("Expected engine 'MergeTree', got '" + report.engine + "'");
    }

    if (report.partition_key != "toYYYYMM(occurred_at)") {
        report.violations.push_back("Expected partition_key 'toYYYYMM(occurred_at)', got '" + report.partition_key +
                                    "'");
    }

    if (report.sorting_key != "occurred_at, producer_service, event_type, event_id") {
        report.violations.push_back(
            "Expected sorting_key 'occurred_at, producer_service, event_type, event_id', got '" + report.sorting_key +
            "'");
    }

    const std::string& ddl = report.create_table_query;
    auto ttl_pos = ddl.find("TTL");
    if (ttl_pos == std::string::npos) {
        report.violations.push_back("create_table_query does not contain a TTL clause");
    } else {
        std::string ttl_clause = ddl.substr(ttl_pos);
        if (ttl_clause.find("occurred_at") == std::string::npos) {
            report.violations.push_back("TTL clause does not reference 'occurred_at'");
        }
        if (ttl_clause.find("36") == std::string::npos) {
            report.violations.push_back("TTL clause does not specify 36-month retention interval");
        }
        if (ttl_clause.find("received_at") != std::string::npos) {
            report.violations.push_back("TTL clause incorrectly references 'received_at' instead of 'occurred_at'");
        }
    }

    report.is_valid = report.violations.empty();
    return report;
}

bool SchemaInitializer::verify_schema_integrity() const {
    auto report = verify_effective_schema();
    return report.is_valid;
}

} // namespace securecloud::audit::repository