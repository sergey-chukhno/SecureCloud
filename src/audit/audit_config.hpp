#pragma once

#include "securecloud/configuration/common_service_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <cstdint>
#include <string>

namespace securecloud::audit {

/// Typed configuration model for Audit service.
/// Holds common service settings and ClickHouse database connection settings.
/// Strictly excludes Auth/Messaging/Files credentials.
struct AuditConfig {
    common::configuration::CommonServiceConfig common;

    std::string db_host{"clickhouse"};
    uint16_t db_port{8123};
    std::string db_name{"securecloud_audit"};
    std::string db_user{"audit_user"};
    common::configuration::SecretString db_password;

    /// Loads and validates Audit configuration. Fails closed if db_password is missing or empty.
    static AuditConfig load(const common::configuration::ConfigurationSource& source,
                            common::configuration::ValidationResult& out_errors);
};

} // namespace securecloud::audit
