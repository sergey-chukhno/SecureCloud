#include "resource_config.hpp"

#include "securecloud/configuration/config_parser.hpp"

namespace securecloud::files {

namespace {

void load_domain_config(const std::string& prefix,
                        ConcurrencyDomainConfig& domain,
                        const common::configuration::ConfigurationSource& source,
                        common::configuration::ValidationResult& out_errors) {
    auto max_concurrency_key = prefix + "_MAX_CONCURRENCY";
    auto max_concurrency_val = source.get(max_concurrency_key);
    if (max_concurrency_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint32(
            max_concurrency_key, max_concurrency_val.value(), out_errors);
        if (parsed.has_value()) {
            if (parsed.value() == 0) {
                out_errors.add_error(max_concurrency_key, "must be greater than 0");
            } else {
                domain.max_concurrency = parsed.value();
            }
        }
    }

    auto timeout_key = prefix + "_ACQUIRE_TIMEOUT_MS";
    auto timeout_val = source.get(timeout_key);
    if (timeout_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint32(
            timeout_key, timeout_val.value(), out_errors);
        if (parsed.has_value()) {
            domain.acquire_timeout = std::chrono::milliseconds(parsed.value());
        }
    }
}

} // namespace

FilesResourceConfig FilesResourceConfig::load(const common::configuration::ConfigurationSource& source,
                                              common::configuration::ValidationResult& out_errors) {
    FilesResourceConfig config;

    // Load Concurrency Domains
    load_domain_config("SECURECLOUD_FILES_METADATA", config.metadata_domain, source, out_errors);
    load_domain_config("SECURECLOUD_FILES_UPLOAD", config.upload_domain, source, out_errors);
    load_domain_config("SECURECLOUD_FILES_DOWNLOAD", config.download_domain, source, out_errors);

    // Storage Concurrency
    auto storage_max_val = source.get("SECURECLOUD_FILES_STORAGE_MAX_CONCURRENCY");
    if (storage_max_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint32(
            "SECURECLOUD_FILES_STORAGE_MAX_CONCURRENCY", storage_max_val.value(), out_errors);
        if (parsed.has_value()) {
            if (parsed.value() == 0) {
                out_errors.add_error("SECURECLOUD_FILES_STORAGE_MAX_CONCURRENCY", "must be greater than 0");
            } else {
                config.max_storage_concurrency = parsed.value();
            }
        }
    }

    auto storage_to_val = source.get("SECURECLOUD_FILES_STORAGE_ACQUIRE_TIMEOUT_MS");
    if (storage_to_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint32(
            "SECURECLOUD_FILES_STORAGE_ACQUIRE_TIMEOUT_MS", storage_to_val.value(), out_errors);
        if (parsed.has_value()) {
            config.storage_acquire_timeout = std::chrono::milliseconds(parsed.value());
        }
    }

    // DB Connection Ceiling
    auto db_max_val = source.get("SECURECLOUD_FILES_DB_MAX_CONNECTIONS");
    if (db_max_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint32(
            "SECURECLOUD_FILES_DB_MAX_CONNECTIONS", db_max_val.value(), out_errors);
        if (parsed.has_value()) {
            if (parsed.value() == 0) {
                out_errors.add_error("SECURECLOUD_FILES_DB_MAX_CONNECTIONS", "must be greater than 0");
            } else {
                config.max_db_connections = parsed.value();
            }
        }
    }

    // Memory Buffer Limit (in bytes)
    auto mem_val = source.get("SECURECLOUD_FILES_MAX_MEMORY_BUFFER_BYTES");
    if (mem_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint64(
            "SECURECLOUD_FILES_MAX_MEMORY_BUFFER_BYTES", mem_val.value(), out_errors);
        if (parsed.has_value()) {
            if (parsed.value() == 0) {
                out_errors.add_error("SECURECLOUD_FILES_MAX_MEMORY_BUFFER_BYTES", "must be greater than 0");
            } else {
                config.max_memory_buffer_bytes = static_cast<size_t>(parsed.value());
            }
        }
    }

    // Chunk Request Size Cap (in bytes)
    auto chunk_val = source.get("SECURECLOUD_FILES_MAX_CHUNK_REQUEST_BYTES");
    if (chunk_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint64(
            "SECURECLOUD_FILES_MAX_CHUNK_REQUEST_BYTES", chunk_val.value(), out_errors);
        if (parsed.has_value()) {
            if (parsed.value() == 0) {
                out_errors.add_error("SECURECLOUD_FILES_MAX_CHUNK_REQUEST_BYTES", "must be greater than 0");
            } else {
                config.max_chunk_request_bytes = static_cast<size_t>(parsed.value());
            }
        }
    }

    // File Transfer Size Cap (in bytes)
    auto transfer_val = source.get("SECURECLOUD_FILES_MAX_FILE_TRANSFER_BYTES");
    if (transfer_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint64(
            "SECURECLOUD_FILES_MAX_FILE_TRANSFER_BYTES", transfer_val.value(), out_errors);
        if (parsed.has_value()) {
            if (parsed.value() == 0) {
                out_errors.add_error("SECURECLOUD_FILES_MAX_FILE_TRANSFER_BYTES", "must be greater than 0");
            } else {
                config.max_file_transfer_bytes = static_cast<size_t>(parsed.value());
            }
        }
    }

    return config;
}

} // namespace securecloud::files
