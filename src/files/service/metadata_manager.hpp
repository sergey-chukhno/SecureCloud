#pragma once

#include "files/db/files_connection_pool.hpp"
#include "securecloud/files/v1/files.pb.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace securecloud::files::service {

/// Model representing logical file metadata stored in PostgreSQL.
struct FileMetadataRecord {
    std::string file_id;
    std::string owner_user_id;
    std::string owner_device_id;
    std::string conversation_id;
    v1::FileLifecycleState lifecycle_state{v1::FILE_LIFECYCLE_STATE_UNSPECIFIED};
    uint64_t encrypted_size_bytes{0};
    uint32_t chunk_count{0};
    std::string encryption_version;
    std::string ciphertext_integrity_hash;
    int64_t created_at_unix_ms{0};
    int64_t available_at_unix_ms{0};
    int64_t expires_at_unix_ms{0};
};

/// Interface defining the contract for file metadata persistence in PostgreSQL.
class IMetadataManager {
  public:
    virtual ~IMetadataManager() = default;

    /// Persists a new file record in CREATED state.
    virtual bool create_file_record(const FileMetadataRecord& record) = 0;

    /// Updates file lifecycle state.
    virtual bool update_file_state(const std::string& file_id, v1::FileLifecycleState new_state) = 0;

    /// Fetches file metadata by file_id.
    virtual std::optional<FileMetadataRecord> get_file_metadata(const std::string& file_id) = 0;

    /// Soft-deletes or marks a file record as DELETED.
    virtual bool mark_file_deleted(const std::string& file_id) = 0;
};

/// Default implementation of IMetadataManager wrapping FilesDbConnectionPool.
class MetadataManager : public IMetadataManager {
  public:
    explicit MetadataManager(std::shared_ptr<db::FilesDbConnectionPool> db_pool = nullptr)
        : db_pool_(std::move(db_pool)) {}
    ~MetadataManager() override = default;

    bool create_file_record(const FileMetadataRecord& /*record*/) override { return false; }

    bool update_file_state(const std::string& /*file_id*/, v1::FileLifecycleState /*new_state*/) override {
        return false;
    }

    std::optional<FileMetadataRecord> get_file_metadata(const std::string& /*file_id*/) override {
        return std::nullopt;
    }

    bool mark_file_deleted(const std::string& /*file_id*/) override { return false; }

    [[nodiscard]] std::shared_ptr<db::FilesDbConnectionPool> db_pool() const noexcept { return db_pool_; }

  private:
    std::shared_ptr<db::FilesDbConnectionPool> db_pool_;
};

} // namespace securecloud::files::service
