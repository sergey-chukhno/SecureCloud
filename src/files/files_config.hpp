#pragma once

#include "concurrency/resource_config.hpp"
#include "securecloud/configuration/common_service_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace securecloud::files {

struct FilesOutboxRelayConfig {
    std::chrono::milliseconds poll_interval{500};
    size_t batch_size{50};
    std::chrono::seconds lease_duration{30};
    std::chrono::milliseconds initial_backoff{250};
    std::chrono::milliseconds max_backoff{30000};
    double backoff_multiplier{2.0};
    double jitter_ratio{0.25};
    uint32_t max_retries{5};
    std::chrono::hours published_retention{24 * 7};
    std::chrono::seconds purge_interval{3600};
    size_t purge_batch_size{1000};
    std::chrono::milliseconds shutdown_drain_timeout{3000};
};

struct FilesAuditOutboxConfig {
    bool outbox_relay_enabled{true};
    std::string audit_endpoint{"audit:50055"};
    std::chrono::milliseconds audit_timeout{2000};
    std::string audit_expected_peer_san{"audit"};
    std::string producer_instance{"files-1"};
    FilesOutboxRelayConfig relay;
};

/// Typed configuration model for Files service.
/// Holds common service settings, PostgreSQL database connection settings, and MinIO S3 settings.
/// Strictly excludes Messaging/Audit credentials.
struct FilesConfig {
    common::configuration::CommonServiceConfig common;

    // PostgreSQL settings
    std::string db_host{"postgres"};
    uint16_t db_port{5432};
    std::string db_name{"securecloud_files"};
    std::string db_user{"files_user"};
    common::configuration::SecretString db_password;

    // MinIO S3 Object Storage settings
    std::string s3_endpoint{"http://minio:9000"};
    std::string s3_bucket{"securecloud-files-encrypted"};
    std::string s3_access_key{"files_minio_user"};
    common::configuration::SecretString s3_secret_key;

    // Resource & Concurrency Controls (FILES-009)
    FilesResourceConfig resources;

    FilesAuditOutboxConfig audit;

    /// Loads and validates Files configuration. Fails closed if db_password or s3_secret_key is missing/empty.
    static FilesConfig load(const common::configuration::ConfigurationSource& source,
                            common::configuration::ValidationResult& out_errors);
};

} // namespace securecloud::files
