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

    auto host_val = source.get("SECURECLOUD_AUDIT_DB_HOST");
    if (host_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_AUDIT_DB_HOST", host_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.db_host = parsed.value();
        }
    }

    auto port_val = source.get("SECURECLOUD_AUDIT_DB_PORT");
    if (port_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16("SECURECLOUD_AUDIT_DB_PORT", port_val.value(),
                                                                        out_errors);
        if (parsed.has_value()) {
            config.db_port = parsed.value();
        }
    } else {
        config.db_port = k_default_clickhouse_port;
    }

    auto name_val = source.get("SECURECLOUD_AUDIT_DB_NAME");
    if (name_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_AUDIT_DB_NAME", name_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.db_name = parsed.value();
        }
    }

    auto user_val = source.get("SECURECLOUD_AUDIT_DB_USER");
    if (user_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_AUDIT_DB_USER", user_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.db_user = parsed.value();
        }
    }

    auto pass_val = source.get("SECURECLOUD_AUDIT_DB_PASSWORD");
    if (!pass_val.has_value() || pass_val.value().empty()) {
        out_errors.add_error("SECURECLOUD_AUDIT_DB_PASSWORD", "required configuration is missing or empty");
    } else {
        config.db_password = common::configuration::SecretString(pass_val.value());
    }

    return config;
}

} // namespace securecloud::audit
