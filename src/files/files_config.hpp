#pragma once

#include "securecloud/configuration/common_service_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <cstdint>
#include <string>

namespace securecloud::files {

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

    /// Loads and validates Files configuration. Fails closed if db_password or s3_secret_key is missing/empty.
    static FilesConfig load(const common::configuration::ConfigurationSource& source,
                            common::configuration::ValidationResult& out_errors);
};

} // namespace securecloud::files
