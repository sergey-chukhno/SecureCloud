#pragma once

#include "securecloud/configuration/common_service_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace securecloud::gateway {

/// Typed configuration model for Gateway service (GW-001).
/// Holds HTTP server runtime settings, request limits, downstream microservice endpoints,
/// and common gRPC/mTLS service parameters.
/// Strictly excludes database or object storage configuration (ADR-005, Gateway Design 3.1).
struct GatewayConfig {
    common::configuration::CommonServiceConfig common;

    // HTTP Runtime Settings (GW-001-T02)
    std::string http_listen_address{"127.0.0.1"};
    uint16_t http_listen_port{8080};
    uint64_t max_payload_bytes{10485760}; // 10 MB default
    std::chrono::milliseconds request_timeout_ms{5000};
    uint32_t server_threads{4};

    // Downstream Microservice Endpoints
    std::string auth_endpoint{"auth:50052"};
    std::string messaging_endpoint{"messaging:50053"};
    std::string files_endpoint{"files:50054"};
    std::string audit_endpoint{"audit:50055"};

    // Peer Probe Settings
    std::string peer_probe_target;
    std::string peer_probe_name;

    /// Returns the combined HTTP listen endpoint formatted as "<http_listen_address>:<http_listen_port>".
    [[nodiscard]] std::string http_listen_endpoint() const;

    /// Loads and validates Gateway configuration.
    static GatewayConfig load(const common::configuration::ConfigurationSource& source,
                              common::configuration::ValidationResult& out_errors);
};

} // namespace securecloud::gateway
