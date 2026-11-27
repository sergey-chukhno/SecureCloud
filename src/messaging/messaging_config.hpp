#pragma once

#include "securecloud/configuration/common_service_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <cstdint>
#include <string>

namespace securecloud::messaging {

/// Typed configuration model for ScyllaDB cluster settings.
struct ScyllaConfig {
    std::string host{"scylladb"};
    uint16_t port{9042};
    std::string keyspace{"securecloud_messaging"};
    uint32_t connect_timeout_ms{5000};
    uint32_t request_timeout_ms{2000};
    uint32_t connection_pool_size{16};
};

/// Typed configuration model for bounded worker pool concurrency (ADR-009, ADR-010).
struct WorkerPoolConfig {
    uint32_t submission_workers{8}; // [1, 128]
    uint32_t delivery_workers{16};  // [1, 256]
    uint32_t sync_workers{8};       // [1, 128]

    uint32_t max_queued_submissions{1024}; // [16, 65536]
    uint32_t max_queued_deliveries{4096};  // [16, 65536]
    uint32_t max_queued_syncs{1024};       // [16, 65536]
};

/// Central Audit producer configuration. Audit connectivity is deliberately optional at startup;
/// the durable outbox relay retries independently after Messaging becomes available.
struct MessagingAuditConfig {
    bool relay_enabled{true};
    std::string endpoint{"audit:50055"};
    std::string expected_peer_san{"audit"};
    std::string producer_instance{"messaging-1"};
    uint32_t worker_threads{4};
    uint32_t batch_size{100};
    uint32_t max_retries{5};
    uint32_t active_poll_interval_ms{50};
    uint32_t idle_poll_interval_ms{500};
    uint32_t lease_duration_sec{30};
    uint32_t rpc_timeout_ms{5000};
};

/// Auth service mTLS client config used by Messaging for recipient device key resolution.
struct MessagingAuthDirectoryConfig {
    std::string endpoint{"auth:50052"};
    std::string expected_peer_san{"auth"};
};

/// Typed configuration model for Messaging service.
/// Holds common service settings, ScyllaDB cluster configuration, and worker concurrency limits.
/// Strictly excludes Auth/Files/Audit database credentials.
struct MessagingConfig {
    common::configuration::CommonServiceConfig common;
    ScyllaConfig scylla;
    WorkerPoolConfig workers;
    MessagingAuditConfig audit;
    MessagingAuthDirectoryConfig auth;
    uint32_t shutdown_grace_period_ms{10000};

    // Direct compatibility fields matching earlier prototype call sites
    std::string scylla_host{"scylladb"};
    uint16_t scylla_port{9042};
    std::string scylla_keyspace{"securecloud_messaging"};

    /// Loads and validates Messaging configuration.
    static MessagingConfig load(const common::configuration::ConfigurationSource& source,
                                common::configuration::ValidationResult& out_errors);
};

} // namespace securecloud::messaging
