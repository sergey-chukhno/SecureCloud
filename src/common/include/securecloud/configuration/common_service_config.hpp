#pragma once

#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

namespace securecloud::common::configuration {

/// Common runtime configuration model shared across all SecureCloud microservices.
struct CommonServiceConfig {
    std::string service_name;
    std::string service_display_name;
    std::string grpc_host{"0.0.0.0"};
    uint16_t grpc_port{0};
    security::SecurityCredentialsConfig tls_credentials;
    std::chrono::milliseconds shutdown_timeout{5000};

    /// Returns the combined listen address formatted as "<host>:<port>".
    [[nodiscard]] std::string listen_address() const;

    /// Loads common service configuration from the specified configuration source.
    ///
    /// Precedence for gRPC port:
    /// 1. SECURECLOUD_<SERVICE>_GRPC_PORT (Service-specific override, e.g. SECURECLOUD_AUTH_GRPC_PORT)
    /// 2. SECURECLOUD_GRPC_PORT (Transitional legacy fallback, emits non-sensitive deprecation notice)
    /// 3. default_port
    ///
    /// Precedence for gRPC host:
    /// 1. SECURECLOUD_<SERVICE>_GRPC_HOST (Service-specific override)
    /// 2. SECURECLOUD_GRPC_HOST (Global fallback)
    /// 3. "0.0.0.0" (Default)
    ///
    /// TLS Credential Paths:
    /// - SECURECLOUD_CA_CERT_PATH (defaults to "/etc/securecloud/certs/ca.crt")
    /// - SECURECLOUD_SERVICE_CERT_PATH (defaults to "/etc/securecloud/certs/service.crt")
    /// - SECURECLOUD_SERVICE_KEY_PATH (defaults to "/etc/securecloud/certs/service.key")
    ///
    /// Shutdown Timeout:
    /// - SECURECLOUD_SHUTDOWN_TIMEOUT_MS (defaults to 5000 ms)
    ///
    /// Returns a populated CommonServiceConfig; accumulates errors in out_errors upon invalid values.
    static CommonServiceConfig load(const ConfigurationSource& source, std::string_view service_name,
                                    std::string_view service_display_name, uint16_t default_port,
                                    ValidationResult& out_errors);
};

} // namespace securecloud::common::configuration
