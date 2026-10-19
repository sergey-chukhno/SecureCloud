#include "audit_config.hpp"

#include "securecloud/configuration/config_parser.hpp"

namespace securecloud::audit {

namespace {

constexpr uint16_t k_default_audit_port = 50055;
constexpr uint16_t k_default_clickhouse_port = 8123;

} // namespace

AuditConfig AuditConfig::load(const common::configuration::ConfigurationSource& source,
                              common::configuration::ValidationResult& out_errors) {
    AuditConfig config;
    config.common = common::configuration::CommonServiceConfig::load(source, "audit", "Audit Service",
                                                                     k_default_audit_port, out_errors);

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

    return config;
}

} // namespace securecloud::audit