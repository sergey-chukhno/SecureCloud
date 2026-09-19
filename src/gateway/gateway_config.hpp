#pragma once

#include "securecloud/configuration/common_service_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <string>

namespace securecloud::gateway {

/// Typed configuration model for Gateway service.
/// Holds common service settings, downstream microservice endpoints, and peer probe settings.
/// Strictly excludes database or object storage configuration.
struct GatewayConfig {
    common::configuration::CommonServiceConfig common;

    std::string auth_endpoint{"auth:50052"};
    std::string messaging_endpoint{"messaging:50053"};
    std::string files_endpoint{"files:50054"};
    std::string audit_endpoint{"audit:50055"};

    std::string peer_probe_target;
    std::string peer_probe_name;

    /// Loads and validates Gateway configuration.
    static GatewayConfig load(const common::configuration::ConfigurationSource& source,
                              common::configuration::ValidationResult& out_errors);
};

} // namespace securecloud::gateway
