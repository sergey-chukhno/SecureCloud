#pragma once

#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

namespace securecloud::files {

/// Concurrency domain limits for a specific bulkhead domain.
struct ConcurrencyDomainConfig {
    size_t max_concurrency{20};
    std::chrono::milliseconds acquire_timeout{500};
};

/// Comprehensive resource and bulkhead limits for Files service (ADR-009, FILES-009).
struct FilesResourceConfig {
    // Bulkhead concurrency domains
    ConcurrencyDomainConfig metadata_domain{100, std::chrono::milliseconds(500)};
    ConcurrencyDomainConfig upload_domain{20, std::chrono::milliseconds(1000)};
    ConcurrencyDomainConfig download_domain{50, std::chrono::milliseconds(1000)};

    // Storage (MinIO) concurrency limit
    size_t max_storage_concurrency{30};
    std::chrono::milliseconds storage_acquire_timeout{1000};

    // Database connection ceiling (used with FilesDbConnectionPool)
    size_t max_db_connections{10};

    // Global memory buffer capacity for chunk processing (default: 64 MiB)
    size_t max_memory_buffer_bytes{64 * 1024 * 1024};

    // Maximum request size per chunk (default: 5 MiB)
    size_t max_chunk_request_bytes{5 * 1024 * 1024};

    // Maximum transfer size per file (default: 10 GiB)
    size_t max_file_transfer_bytes{10ULL * 1024ULL * 1024ULL * 1024ULL};

    /// Loads and validates FilesResourceConfig from environment/configuration source.
    static FilesResourceConfig load(const common::configuration::ConfigurationSource& source,
                                    common::configuration::ValidationResult& out_errors);
};

} // namespace securecloud::files
