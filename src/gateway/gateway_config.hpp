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

/// Typed configuration model for Gateway downstream service deadlines (ADR-009, GW-008-T02).
struct GatewayServiceDeadlinesConfig {
    uint32_t auth_timeout_ms{1000};           // 1 s default (Auth simple requests)
    uint32_t messaging_timeout_ms{2000};      // 2 s default (Messaging commands & queries)
    uint32_t files_metadata_timeout_ms{2000}; // 2 s default (Files metadata operations)
    uint32_t audit_timeout_ms{1000};          // 1 s default (Audit operations)
    uint32_t max_request_deadline_ms{10000};  // 10 s default upper clamp
    uint32_t min_request_deadline_ms{50};     // 50 ms minimum viable deadline floor
};

/// Typed configuration model for Gateway workload bulkhead concurrency partitioning (ADR-009 Section 9, GW-009-T01).
struct GatewayBulkheadConfig {
    uint32_t auth_max_concurrent{100};
    uint32_t messaging_max_concurrent{200};
    uint32_t files_max_concurrent{50};
    uint32_t emergency_reserved_slots{10}; // Reserved perimeter capacity for health/ops probes
};

/// Typed configuration model for Gateway token-bucket rate limiting (ADR-009, ADR-010, GW-009-T02).
struct GatewayRateLimitingConfig {
    bool enabled{true};
    double refill_rate_per_sec{50.0};
    uint32_t burst_capacity{100};
    size_t max_tracked_clients{10000};
    std::chrono::seconds client_ttl{300};
};

/// Typed configuration model for Gateway downstream circuit breaking (ADR-009, GW-009-T03).
struct GatewayCircuitBreakerConfig {
    bool enabled{true};
    uint32_t failure_threshold{5};      // 5 consecutive failures trips breaker
    uint32_t recovery_timeout_ms{5000}; // 5s recovery window before HALF_OPEN
    uint32_t half_open_probe_count{1};  // 1 probe request in HALF_OPEN
};

/// Typed configuration model for Gateway bounded streaming & backpressure (ADR-010, GW-010-T02).
struct GatewayStreamingConfig {
    size_t max_chunk_size_bytes{4194304};    // 4 MiB default
    size_t max_stream_buffer_bytes{8388608}; // 8 MiB default (2 chunks)
    uint32_t idle_timeout_ms{30000};         // 30 s default
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

    // Service Deadlines & Timeout Budgets (GW-008-T02)
    GatewayServiceDeadlinesConfig deadlines;

    // Workload Bulkheads (GW-009-T01)
    GatewayBulkheadConfig bulkhead;

    // Token-Bucket Rate Limiting (GW-009-T02)
    GatewayRateLimitingConfig rate_limiting;

    // Downstream Circuit Breaker Engine (GW-009-T03)
    GatewayCircuitBreakerConfig circuit_breaker;

    // Streaming & Backpressure Engine (GW-010-T02)
    GatewayStreamingConfig streaming;

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
