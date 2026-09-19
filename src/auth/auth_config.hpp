#pragma once

#include "securecloud/configuration/common_service_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <cstdint>
#include <string>

namespace securecloud::auth {

/// Typed configuration model for Auth service.
/// Holds common service settings and PostgreSQL connection configuration.
/// Strictly excludes Files/Messaging/Audit credentials.
struct AuthConfig {
    common::configuration::CommonServiceConfig common;

    std::string db_host{"postgres"};
    uint16_t db_port{5432};
    std::string db_name{"securecloud_auth"};
    std::string db_user{"auth_user"};
    common::configuration::SecretString db_password;

    /// Loads and validates Auth configuration. Fails closed if db_password is missing or empty.
    static AuthConfig load(const common::configuration::ConfigurationSource& source,
                           common::configuration::ValidationResult& out_errors);
};

} // namespace securecloud::auth
