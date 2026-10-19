#pragma once

#include "securecloud/configuration/common_service_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <cstdint>
#include <string>

namespace securecloud::audit {

struct ClickHouseConfig {
    std::string host{"clickhouse"};
    uint16_t port{8123}; // Default ClickHouse HTTP interface (SC-011)
    std::string db_name{"securecloud_audit"};
    std::string user{"audit_user"};
    common::configuration::SecretString password;
    uint32_t connect_timeout_ms{5000}; // [500, 30000]
    uint32_t request_timeout_ms{3000}; // [500, 30000]
    uint32_t max_connections{16};      // [1, 128]
};

struct IngestionConfig {
    uint32_t workers{8};                   // [1, 64]
    uint32_t max_queued_events{10000};     // [100, 100000]
    uint32_t batch_size{500};              // [1, 5000]
    uint32_t batch_flush_interval_ms{200}; // [10, 5000]
    uint32_t max_event_size_bytes{65536};  // [1024, 1048576] (64KB default, 1MB max)
};

struct QueryConfig {
    uint32_t workers{4};              // [1, 32]
    uint32_t max_page_limit{1000};    // [10, 10000]
    uint32_t default_page_limit{100}; // [1, max_page_limit]
    uint32_t query_timeout_ms{10000}; // [500, 60000]
};

struct RetentionConfig {
    uint32_t retention_days{90};             // [1, 3650]
    uint32_t shutdown_grace_period_ms{5000}; // [500, 30000]
};

/// Typed configuration model for Audit service.
/// Holds common service settings, ClickHouse database connection settings,
/// ingestion limits, query bounds, and data retention rules.
/// Strictly excludes Auth/Messaging/Files credentials.
struct AuditConfig {
    common::configuration::CommonServiceConfig common;
    ClickHouseConfig clickhouse;
    IngestionConfig ingestion;
    QueryConfig query;
    RetentionConfig retention;

    /// Loads and validates Audit configuration. Fails closed if required parameters are invalid or missing.
    static AuditConfig load(const common::configuration::ConfigurationSource& source,
                            common::configuration::ValidationResult& out_errors);
};

} // namespace securecloud::audit