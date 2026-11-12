#pragma once

#include "auth/audit/auth_outbox_relay_config.hpp"
#include "securecloud/configuration/common_service_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace securecloud::auth::db {
    class PostgresConnectionPool;
}

namespace securecloud::auth {

    /// Typed configuration model for Auth service.
    /// Holds common service settings, PostgreSQL connection configuration, producer instance identity,
    /// and Audit Service gRPC / transactional outbox relay parameters.
    /// Strictly excludes Files/Messaging credentials.
    struct AuthConfig {
        common::configuration::CommonServiceConfig common;

        std::string db_host{"postgres"};
        uint16_t db_port{5432};
        std::string db_name{"securecloud_auth"};
        std::string db_user{"auth_user"};
        common::configuration::SecretString db_password;
        std::string producer_instance{"auth-1"};

        // Audit gRPC client & Outbox relay configuration (AUDIT-013-T05)
        bool outbox_relay_enabled{true};
        std::string audit_endpoint{"audit:50055"};
        std::chrono::milliseconds audit_timeout{2000};
        std::string audit_expected_peer_san{"audit"};
        audit::AuthOutboxRelayConfig outbox_relay;

        /// Loads and validates Auth configuration. Fails closed if db_password is missing or empty.
        static AuthConfig load(const common::configuration::ConfigurationSource& source,
                               common::configuration::ValidationResult& out_errors);

        /// Creates and configures a shared PostgreSQL connection pool from current settings.
        [[nodiscard]] std::shared_ptr<db::PostgresConnectionPool> create_database_pool() const;
    };

} // namespace securecloud::auth
