#pragma once

#include "files/storage/s3_client.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace securecloud::files::service {

/// Interface defining the object storage engine layer wrapping MinIO/S3.
class IStorageEngine {
public:
    virtual ~IStorageEngine() = default;

    /// Stores an encrypted chunk object in S3.
    virtual bool put_chunk(const std::string& file_id, uint32_t chunk_index,
                           std::string_view encrypted_data, const std::string& expected_sha256) = 0;

    /// Retrieves an encrypted chunk object from S3.
    virtual std::optional<std::string> get_chunk(const std::string& file_id, uint32_t chunk_index) = 0;

    /// Deletes all chunk objects associated with a file.
    virtual bool delete_file_objects(const std::string& file_id) = 0;
};

/// Default implementation of IStorageEngine wrapping S3Client.
class StorageEngine : public IStorageEngine {
public:
    explicit StorageEngine(std::shared_ptr<storage::S3Client> s3_client = nullptr)
        : s3_client_(std::move(s3_client)) {}
    ~StorageEngine() override = default;

    bool put_chunk(const std::string& /*file_id*/, uint32_t /*chunk_index*/,
                   std::string_view /*encrypted_data*/, const std::string& /*expected_sha256*/) override {
        return false;
    }

    std::optional<std::string> get_chunk(const std::string& /*file_id*/, uint32_t /*chunk_index*/) override {
        return std::nullopt;
    }

    bool delete_file_objects(const std::string& /*file_id*/) override {
        return false;
    }

    [[nodiscard]] std::shared_ptr<storage::S3Client> s3_client() const noexcept {
        return s3_client_;
    }

private:
    std::shared_ptr<storage::S3Client> s3_client_;
};

} // namespace securecloud::files::service
