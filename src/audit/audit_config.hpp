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

    /// Typed configuration model for Audit service.
    /// Holds common service settings and ClickHouse database connection settings.
    /// Strictly excludes Auth/Messaging/Files credentials.
    struct AuditConfig {
        common::configuration::CommonServiceConfig common;
        ClickHouseConfig clickhouse;

        /// Loads and validates Audit configuration. Fails closed if db_password is missing or empty.
        static AuditConfig load(const common::configuration::ConfigurationSource& source,
                                common::configuration::ValidationResult& out_errors);
    };

} // namespace securecloud::audit