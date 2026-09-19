#pragma once

#include "securecloud/configuration/common_service_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <cstdint>
#include <string>

namespace securecloud::messaging {

/// Typed configuration model for Messaging service.
/// Holds common service settings and ScyllaDB cluster configuration.
/// Strictly excludes Auth/Files/Audit database credentials.
struct MessagingConfig {
    common::configuration::CommonServiceConfig common;

    std::string scylla_host{"scylladb"};
    uint16_t scylla_port{9042};
    std::string scylla_keyspace{"securecloud_messaging"};

    /// Loads and validates Messaging configuration.
    static MessagingConfig load(const common::configuration::ConfigurationSource& source,
                                common::configuration::ValidationResult& out_errors);
};

} // namespace securecloud::messaging
