#include "repository/schema_initializer.hpp"

#include <httplib.h>

#include <chrono>
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
TTL occurred_at + INTERVAL 36 MONTH;
)";

} // namespace

SchemaInitializer::SchemaInitializer(const ClickHouseConfig& config)
    : config_(config) {}

bool SchemaInitializer::execute_http_query(const std::string& query, std::string* out_response) const {
    httplib::Client client(config_.host, config_.port);

    const auto conn_sec = std::chrono::milliseconds(config_.connect_timeout_ms);
    const auto req_sec = std::chrono::milliseconds(config_.request_timeout_ms);
    client.set_connection_timeout(conn_sec);
    client.set_read_timeout(req_sec);
    client.set_write_timeout(req_sec);

    httplib::Headers headers = {
        {"X-ClickHouse-User", config_.user},
        {"X-ClickHouse-Key", config_.password.expose_unredacted_secret()}
    };

    auto res = client.Post("/?database=" + config_.db_name, headers, query, "text/plain");

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

    if (!verify_schema_integrity()) {
        return SchemaInitResult::DatabaseVerificationFailed;
    }

    return SchemaInitResult::Success;
}

bool SchemaInitializer::verify_schema_integrity() const {
    std::string response;
    const std::string verification_query =
        "SELECT count() FROM system.tables WHERE database = 'securecloud_audit' AND name = 'audit_events';";

    if (!execute_http_query(verification_query, &response)) {
        return false;
    }

    // Response should be "1\n"
    return response.find('1') != std::string::npos;
}

} // namespace securecloud::audit::repository