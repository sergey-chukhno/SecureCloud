#include "files_config.hpp"
#include "concurrency/resource_config.hpp"

#include <gtest/gtest.h>
#include <map>
#include <string>

namespace securecloud::files {
namespace {

class MapConfigSource : public common::configuration::ConfigurationSource {
  public:
    explicit MapConfigSource(std::map<std::string, std::string> values) : values_(std::move(values)) {}

    std::optional<std::string> get(const std::string& key) const override {
        auto it = values_.find(key);
        if (it != values_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

  private:
    std::map<std::string, std::string> values_;
};

TEST(ResourceConfigTest, LoadsDefaultValuesWhenNoneConfigured) {
    MapConfigSource source({});
    common::configuration::ValidationResult errors;
    auto config = FilesResourceConfig::load(source, errors);

    EXPECT_FALSE(errors.has_errors());
    EXPECT_EQ(config.metadata_domain.max_concurrency, 100);
    EXPECT_EQ(config.metadata_domain.acquire_timeout.count(), 500);

    EXPECT_EQ(config.upload_domain.max_concurrency, 20);
    EXPECT_EQ(config.upload_domain.acquire_timeout.count(), 1000);

    EXPECT_EQ(config.download_domain.max_concurrency, 50);
    EXPECT_EQ(config.download_domain.acquire_timeout.count(), 1000);

    EXPECT_EQ(config.max_storage_concurrency, 30);
    EXPECT_EQ(config.storage_acquire_timeout.count(), 1000);

    EXPECT_EQ(config.max_db_connections, 10);
    EXPECT_EQ(config.max_memory_buffer_bytes, 64 * 1024 * 1024);
    EXPECT_EQ(config.max_chunk_request_bytes, 5 * 1024 * 1024);
    EXPECT_EQ(config.max_file_transfer_bytes, 10ULL * 1024ULL * 1024ULL * 1024ULL);
}

TEST(ResourceConfigTest, LoadsCustomValuesFromSource) {
    MapConfigSource source({
        {"SECURECLOUD_FILES_METADATA_MAX_CONCURRENCY", "150"},
        {"SECURECLOUD_FILES_METADATA_ACQUIRE_TIMEOUT_MS", "250"},
        {"SECURECLOUD_FILES_UPLOAD_MAX_CONCURRENCY", "15"},
        {"SECURECLOUD_FILES_UPLOAD_ACQUIRE_TIMEOUT_MS", "2000"},
        {"SECURECLOUD_FILES_DOWNLOAD_MAX_CONCURRENCY", "80"},
        {"SECURECLOUD_FILES_DOWNLOAD_ACQUIRE_TIMEOUT_MS", "3000"},
        {"SECURECLOUD_FILES_STORAGE_MAX_CONCURRENCY", "40"},
        {"SECURECLOUD_FILES_STORAGE_ACQUIRE_TIMEOUT_MS", "1500"},
        {"SECURECLOUD_FILES_DB_MAX_CONNECTIONS", "25"},
        {"SECURECLOUD_FILES_MAX_MEMORY_BUFFER_BYTES", "134217728"}, // 128 MiB
        {"SECURECLOUD_FILES_MAX_CHUNK_REQUEST_BYTES", "8388608"},    // 8 MiB
        {"SECURECLOUD_FILES_MAX_FILE_TRANSFER_BYTES", "21474836480"} // 20 GiB
    });

    common::configuration::ValidationResult errors;
    auto config = FilesResourceConfig::load(source, errors);

    EXPECT_FALSE(errors.has_errors());
    EXPECT_EQ(config.metadata_domain.max_concurrency, 150);
    EXPECT_EQ(config.metadata_domain.acquire_timeout.count(), 250);

    EXPECT_EQ(config.upload_domain.max_concurrency, 15);
    EXPECT_EQ(config.upload_domain.acquire_timeout.count(), 2000);

    EXPECT_EQ(config.download_domain.max_concurrency, 80);
    EXPECT_EQ(config.download_domain.acquire_timeout.count(), 3000);

    EXPECT_EQ(config.max_storage_concurrency, 40);
    EXPECT_EQ(config.storage_acquire_timeout.count(), 1500);

    EXPECT_EQ(config.max_db_connections, 25);
    EXPECT_EQ(config.max_memory_buffer_bytes, 128 * 1024 * 1024);
    EXPECT_EQ(config.max_chunk_request_bytes, 8 * 1024 * 1024);
    EXPECT_EQ(config.max_file_transfer_bytes, 20ULL * 1024ULL * 1024ULL * 1024ULL);
}

TEST(ResourceConfigTest, ValidatesZeroValuesFailClosed) {
    MapConfigSource source({
        {"SECURECLOUD_FILES_METADATA_MAX_CONCURRENCY", "0"},
        {"SECURECLOUD_FILES_STORAGE_MAX_CONCURRENCY", "0"},
        {"SECURECLOUD_FILES_DB_MAX_CONNECTIONS", "0"},
        {"SECURECLOUD_FILES_MAX_MEMORY_BUFFER_BYTES", "0"},
        {"SECURECLOUD_FILES_MAX_CHUNK_REQUEST_BYTES", "0"},
        {"SECURECLOUD_FILES_MAX_FILE_TRANSFER_BYTES", "0"}
    });

    common::configuration::ValidationResult errors;
    auto config = FilesResourceConfig::load(source, errors);

    EXPECT_TRUE(errors.has_errors());
    EXPECT_GE(errors.errors().size(), 6);
}

} // namespace
} // namespace securecloud::files
