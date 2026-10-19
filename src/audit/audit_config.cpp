#include "audit_config.hpp"

#include "securecloud/configuration/config_parser.hpp"

#include <string>

namespace securecloud::audit {

    namespace {

        constexpr uint16_t k_default_audit_port = 50055;
        constexpr uint16_t k_default_clickhouse_port = 8123;

        std::optional<uint32_t> parse_uint32_bounded(const std::string& key, std::string_view value,
                                                     common::configuration::ValidationResult& out_errors,
                                                     uint32_t min_val, uint32_t max_val) {
            try {
                std::size_t pos = 0;
                std::string s_val{value};
                unsigned long parsed = std::stoul(s_val, &pos);
                if (pos != s_val.size()) {
                    out_errors.add_error(key, "invalid integer format");
                    return std::nullopt;
                }
                if (parsed < min_val || parsed > max_val) {
                    out_errors.add_error(key, "value out of allowed range [" + std::to_string(min_val) + ", " +
                                                   std::to_string(max_val) + "]");
                    return std::nullopt;
                }
                return static_cast<uint32_t>(parsed);
            } catch (...) {
                out_errors.add_error(key, "invalid integer value or out of range");
                return std::nullopt;
            }
        }

    } // namespace

AuditConfig AuditConfig::load(const common::configuration::ConfigurationSource& source,
                              common::configuration::ValidationResult& out_errors) {
    AuditConfig config;
    config.common = common::configuration::CommonServiceConfig::load(source, "audit", "Audit Service",
                                                                     k_default_audit_port, out_errors);

    // --- ClickHouse Connectivity ---

    // SECURECLOUD_AUDIT_DB_HOST
    auto host_val = source.get("SECURECLOUD_AUDIT_DB_HOST");
    if (host_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_AUDIT_DB_HOST", host_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.clickhouse.host = parsed.value();
        }
    }

    // SECURECLOUD_AUDIT_DB_PORT
    auto port_val = source.get("SECURECLOUD_AUDIT_DB_PORT");
    if (port_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16("SECURECLOUD_AUDIT_DB_PORT", port_val.value(),
                                                                        out_errors);
        if (parsed.has_value()) {
            uint16_t port = parsed.value();
            if (port == 5432 || port == 5433) {
                out_errors.add_error("SECURECLOUD_AUDIT_DB_PORT",
                                     "Forbidden PostgreSQL port specified for ClickHouse (" + std::to_string(port) + ")");
            } else {
                config.clickhouse.port = port;
            }
        }
    } else {
        config.clickhouse.port = k_default_clickhouse_port;
    }

    // SECURECLOUD_AUDIT_DB_NAME
    auto name_val = source.get("SECURECLOUD_AUDIT_DB_NAME");
    if (name_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_AUDIT_DB_NAME", name_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.clickhouse.db_name = parsed.value();
        }
    }

    // SECURECLOUD_AUDIT_DB_USER
    auto user_val = source.get("SECURECLOUD_AUDIT_DB_USER");
    if (user_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_AUDIT_DB_USER", user_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.clickhouse.user = parsed.value();
        }
    }

    // SECURECLOUD_AUDIT_DB_PASSWORD
    auto pass_val = source.get("SECURECLOUD_AUDIT_DB_PASSWORD");
    if (!pass_val.has_value() || pass_val.value().empty()) {
        out_errors.add_error("SECURECLOUD_AUDIT_DB_PASSWORD", "required configuration is missing or empty");
    } else {
        config.clickhouse.password = common::configuration::SecretString(pass_val.value());
    }

    // SECURECLOUD_AUDIT_DB_CONNECT_TIMEOUT_MS [500, 30000]
    auto conn_timeout_val = source.get("SECURECLOUD_AUDIT_DB_CONNECT_TIMEOUT_MS");
    if (conn_timeout_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_duration_ms(
            "SECURECLOUD_AUDIT_DB_CONNECT_TIMEOUT_MS", conn_timeout_val.value(), out_errors, 500, 30000);
        if (parsed.has_value()) {
            config.clickhouse.connect_timeout_ms = static_cast<uint32_t>(parsed->count());
        }
    }

    // SECURECLOUD_AUDIT_DB_REQUEST_TIMEOUT_MS [500, 30000]
    auto req_timeout_val = source.get("SECURECLOUD_AUDIT_DB_REQUEST_TIMEOUT_MS");
    if (req_timeout_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_duration_ms(
            "SECURECLOUD_AUDIT_DB_REQUEST_TIMEOUT_MS", req_timeout_val.value(), out_errors, 500, 30000);
        if (parsed.has_value()) {
            config.clickhouse.request_timeout_ms = static_cast<uint32_t>(parsed->count());
        }
    }

    // SECURECLOUD_AUDIT_DB_MAX_CONNECTIONS [1, 128]
    auto max_conn_val = source.get("SECURECLOUD_AUDIT_DB_MAX_CONNECTIONS");
    if (max_conn_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16(
            "SECURECLOUD_AUDIT_DB_MAX_CONNECTIONS", max_conn_val.value(), out_errors, 1, 128);
        if (parsed.has_value()) {
            config.clickhouse.max_connections = static_cast<uint32_t>(parsed.value());
        }
    }

    // --- Ingestion Configuration ---

    // SECURECLOUD_AUDIT_INGESTION_WORKERS [1, 64]
    auto ing_workers_val = source.get("SECURECLOUD_AUDIT_INGESTION_WORKERS");
    if (ing_workers_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16(
            "SECURECLOUD_AUDIT_INGESTION_WORKERS", ing_workers_val.value(), out_errors, 1, 64);
        if (parsed.has_value()) {
            config.ingestion.workers = static_cast<uint32_t>(parsed.value());
        }
    }

    // SECURECLOUD_AUDIT_MAX_QUEUED_EVENTS [100, 100000]
    auto queue_val = source.get("SECURECLOUD_AUDIT_MAX_QUEUED_EVENTS");
    if (queue_val.has_value()) {
        auto parsed = parse_uint32_bounded("SECURECLOUD_AUDIT_MAX_QUEUED_EVENTS", queue_val.value(),
                                           out_errors, 100, 100000);
        if (parsed.has_value()) {
            config.ingestion.max_queued_events = parsed.value();
        }
    }

    // SECURECLOUD_AUDIT_BATCH_SIZE [1, 5000]
    auto batch_val = source.get("SECURECLOUD_AUDIT_BATCH_SIZE");
    if (batch_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16(
            "SECURECLOUD_AUDIT_BATCH_SIZE", batch_val.value(), out_errors, 1, 5000);
        if (parsed.has_value()) {
            config.ingestion.batch_size = static_cast<uint32_t>(parsed.value());
        }
    }

    // SECURECLOUD_AUDIT_BATCH_FLUSH_INTERVAL_MS [10, 5000]
    auto flush_val = source.get("SECURECLOUD_AUDIT_BATCH_FLUSH_INTERVAL_MS");
    if (flush_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_duration_ms(
            "SECURECLOUD_AUDIT_BATCH_FLUSH_INTERVAL_MS", flush_val.value(), out_errors, 10, 5000);
        if (parsed.has_value()) {
            config.ingestion.batch_flush_interval_ms = static_cast<uint32_t>(parsed->count());
        }
    }

    // SECURECLOUD_AUDIT_MAX_EVENT_SIZE_BYTES [1024, 1048576]
    auto max_evt_size_val = source.get("SECURECLOUD_AUDIT_MAX_EVENT_SIZE_BYTES");
    if (max_evt_size_val.has_value()) {
        auto parsed = parse_uint32_bounded("SECURECLOUD_AUDIT_MAX_EVENT_SIZE_BYTES", max_evt_size_val.value(),
                                           out_errors, 1024, 1048576);
        if (parsed.has_value()) {
            config.ingestion.max_event_size_bytes = parsed.value();
        }
    }

    // --- Query Configuration ---

    // SECURECLOUD_AUDIT_QUERY_WORKERS [1, 32]
    auto q_workers_val = source.get("SECURECLOUD_AUDIT_QUERY_WORKERS");
    if (q_workers_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16(
            "SECURECLOUD_AUDIT_QUERY_WORKERS", q_workers_val.value(), out_errors, 1, 32);
        if (parsed.has_value()) {
            config.query.workers = static_cast<uint32_t>(parsed.value());
        }
    }

    // SECURECLOUD_AUDIT_MAX_PAGE_LIMIT [10, 10000]
    auto max_limit_val = source.get("SECURECLOUD_AUDIT_MAX_PAGE_LIMIT");
    if (max_limit_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16(
            "SECURECLOUD_AUDIT_MAX_PAGE_LIMIT", max_limit_val.value(), out_errors, 10, 10000);
        if (parsed.has_value()) {
            config.query.max_page_limit = static_cast<uint32_t>(parsed.value());
        }
    }

    // SECURECLOUD_AUDIT_DEFAULT_PAGE_LIMIT [1, max_page_limit]
    auto def_limit_val = source.get("SECURECLOUD_AUDIT_DEFAULT_PAGE_LIMIT");
    if (def_limit_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16(
            "SECURECLOUD_AUDIT_DEFAULT_PAGE_LIMIT", def_limit_val.value(), out_errors, 1, 10000);
        if (parsed.has_value()) {
            config.query.default_page_limit = static_cast<uint32_t>(parsed.value());
        }
    }

    // SECURECLOUD_AUDIT_QUERY_TIMEOUT_MS [500, 60000]
    auto q_timeout_val = source.get("SECURECLOUD_AUDIT_QUERY_TIMEOUT_MS");
    if (q_timeout_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_duration_ms(
            "SECURECLOUD_AUDIT_QUERY_TIMEOUT_MS", q_timeout_val.value(), out_errors, 500, 60000);
        if (parsed.has_value()) {
            config.query.query_timeout_ms = static_cast<uint32_t>(parsed->count());
        }
    }

    // --- Retention Configuration ---

    // SECURECLOUD_AUDIT_RETENTION_DAYS [1, 3650]
    auto ret_days_val = source.get("SECURECLOUD_AUDIT_RETENTION_DAYS");
    if (ret_days_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16(
            "SECURECLOUD_AUDIT_RETENTION_DAYS", ret_days_val.value(), out_errors, 1, 3650);
        if (parsed.has_value()) {
            config.retention.retention_days = static_cast<uint32_t>(parsed.value());
        }
    }

    // SECURECLOUD_AUDIT_SHUTDOWN_GRACE_PERIOD_MS [500, 30000]
    auto grace_val = source.get("SECURECLOUD_AUDIT_SHUTDOWN_GRACE_PERIOD_MS");
    if (grace_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_duration_ms(
            "SECURECLOUD_AUDIT_SHUTDOWN_GRACE_PERIOD_MS", grace_val.value(), out_errors, 500, 30000);
        if (parsed.has_value()) {
            config.retention.shutdown_grace_period_ms = static_cast<uint32_t>(parsed->count());
        }
    }

    // --- Cross-Field Validations ---

    if (config.query.default_page_limit > config.query.max_page_limit) {
        out_errors.add_error("SECURECLOUD_AUDIT_DEFAULT_PAGE_LIMIT",
                             "default_page_limit cannot exceed max_page_limit (" +
                                 std::to_string(config.query.default_page_limit) + " > " +
                                 std::to_string(config.query.max_page_limit) + ")");
    }

    if (config.ingestion.batch_size > config.ingestion.max_queued_events) {
        out_errors.add_error("SECURECLOUD_AUDIT_BATCH_SIZE",
                             "batch_size cannot exceed max_queued_events (" +
                                 std::to_string(config.ingestion.batch_size) + " > " +
                                 std::to_string(config.ingestion.max_queued_events) + ")");
    }

    return config;
}

} // namespace securecloud::audit