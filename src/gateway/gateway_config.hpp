#pragma once

#include "securecloud/configuration/common_service_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace securecloud::gateway {

/// Typed configuration model for Gateway external TLS 1.3 listener (GW-002-T01).
struct GatewayTlsConfig {
    bool enabled{true};
    std::string cert_path{"/etc/securecloud/certs/gateway/gateway.crt"};
    std::string key_path{"/etc/securecloud/certs/gateway/gateway.key"};
    std::string ca_chain_path{"/etc/securecloud/certs/ca/ca.crt"};
    uint16_t https_listen_port{8443};
    std::string min_tls_version{"TLSv1.3"};
    std::string cipher_suites{"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"};
};

/// Typed configuration model for Gateway transport resource limits (GW-002-T01).
struct GatewayResourceLimitsConfig {
    size_t max_header_bytes{16384};  // 16 KB default
    size_t max_body_bytes{10485760}; // 10 MB default
    uint32_t read_timeout_ms{5000};  // 5 s default
    uint32_t write_timeout_ms{5000}; // 5 s default
    uint32_t idle_timeout_ms{30000}; // 30 s default
    size_t max_concurrent_connections{1024};
};

/// Typed configuration model for Gateway service (GW-001, GW-002).
/// Holds HTTP server runtime settings, TLS parameters, resource limits, downstream microservice endpoints,
/// and common gRPC/mTLS service parameters.
/// Strictly excludes database or object storage configuration (ADR-005, Gateway Design 3.1).
struct GatewayConfig {
    common::configuration::CommonServiceConfig common;

    // HTTP Runtime Settings (GW-001-T02)
    std::string http_listen_address{"127.0.0.1"};
    uint16_t http_listen_port{8080};
    uint64_t max_payload_bytes{10485760}; // 10 MB default (kept synchronized with limits.max_body_bytes)
    std::chrono::milliseconds request_timeout_ms{5000};
    uint32_t server_threads{4};

    // TLS & Transport Resource Settings (GW-002-T01)
    GatewayTlsConfig tls;
    GatewayResourceLimitsConfig limits;

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

    /// Returns the combined HTTPS listen endpoint formatted as "<http_listen_address>:<https_listen_port>".
    [[nodiscard]] std::string https_listen_endpoint() const;

    /// Validates whether configured TLS filesystem paths exist on disk.
    void validate_tls_paths(common::configuration::ValidationResult& out_errors) const;

    /// Loads and validates Gateway configuration.
    static GatewayConfig load(const common::configuration::ConfigurationSource& source,
                              common::configuration::ValidationResult& out_errors, bool validate_file_paths = false);
};

} // namespace securecloud::gateway
