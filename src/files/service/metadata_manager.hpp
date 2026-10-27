#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/service/file_lifecycle_service.hpp"
#include "securecloud/files/v1/files.pb.h"

#include <chrono>
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

/// Default implementation of IMetadataManager wrapping FileLifecycleService.
class MetadataManager : public IMetadataManager {
  public:
    explicit MetadataManager(std::shared_ptr<db::FilesDbConnectionPool> db_pool = nullptr,
                             std::shared_ptr<FileLifecycleService> lifecycle_service = nullptr)
        : db_pool_(db_pool),
          lifecycle_service_(lifecycle_service ? std::move(lifecycle_service)
                                               : std::make_shared<FileLifecycleService>(std::move(db_pool))) {}
    ~MetadataManager() override = default;

    bool create_file_record(const FileMetadataRecord& record) override {
        try {
            CreateFileRequestDto dto{
                .file_id = record.file_id,
                .owner_user_id = record.owner_user_id,
                .owner_device_id = record.owner_device_id,
                .conversation_id =
                    record.conversation_id.empty() ? std::nullopt : std::make_optional(record.conversation_id),
                .encrypted_size_bytes = record.encrypted_size_bytes,
                .expected_chunk_count = record.chunk_count,
                .encryption_algorithm =
                    record.encryption_version.empty() ? "XChaCha20-Poly1305" : record.encryption_version,
                .encrypted_filename = {0x01},
                .encrypted_mime_type = std::nullopt,
                .metadata_nonce = std::vector<uint8_t>(24, 0),
                .metadata_tag = std::vector<uint8_t>(16, 0),
                .client_encryption_metadata_json = "{}",
                .retention_until = (record.expires_at_unix_ms > 0)
                                       ? std::make_optional(std::chrono::system_clock::time_point(
                                             std::chrono::milliseconds(record.expires_at_unix_ms)))
                                       : std::nullopt,
            };
            lifecycle_service_->create_file(dto, std::chrono::system_clock::now());
            return true;
        } catch (...) {
            return false;
        }
    }

    bool update_file_state(const std::string& file_id, v1::FileLifecycleState new_state) override {
        try {
            auto current_meta = lifecycle_service_->get_file_metadata(file_id, "system");
            if (!current_meta) {
                return false;
            }
            FileStatus target_status = from_proto(new_state);
            return lifecycle_service_->transition_lifecycle(file_id, current_meta->file.status, target_status,
                                                            "system");
        } catch (...) {
            return false;
        }
    }

    std::optional<FileMetadataRecord> get_file_metadata(const std::string& file_id) override {
        try {
            auto summary = lifecycle_service_->get_file_metadata(file_id, "system");
            if (!summary) {
                return std::nullopt;
            }
            auto created_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(summary->file.created_at.time_since_epoch())
                    .count();
            int64_t expires_ms = summary->file.retention_until ? std::chrono::duration_cast<std::chrono::milliseconds>(
                                                                     summary->file.retention_until->time_since_epoch())
                                                                     .count()
                                                               : 0;
            int64_t available_ms = 0;
            std::string hash;
            if (summary->active_version) {
                hash = summary->active_version->checksum_sha256;
                available_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   summary->active_version->created_at.time_since_epoch())
                                   .count();
            }

            return FileMetadataRecord{
                .file_id = summary->file.file_id,
                .owner_user_id = summary->file.owner_user_id,
                .owner_device_id = summary->file.owner_device_id,
                .conversation_id = summary->file.conversation_id.value_or(""),
                .lifecycle_state = to_proto(summary->file.status),
                .encrypted_size_bytes = static_cast<uint64_t>(summary->file.encrypted_size),
                .chunk_count = summary->expected_chunk_count,
                .encryption_version = summary->file.encryption_algorithm,
                .ciphertext_integrity_hash = hash,
                .created_at_unix_ms = created_ms,
                .available_at_unix_ms = available_ms,
                .expires_at_unix_ms = expires_ms,
            };
        } catch (...) {
            return std::nullopt;
        }
    }

    bool mark_file_deleted(const std::string& file_id) override {
        try {
            return lifecycle_service_->delete_file(file_id, "system");
        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] std::shared_ptr<db::FilesDbConnectionPool> db_pool() const noexcept { return db_pool_; }
    [[nodiscard]] std::shared_ptr<FileLifecycleService> lifecycle_service() const noexcept {
        return lifecycle_service_;
    }

  private:
    std::shared_ptr<db::FilesDbConnectionPool> db_pool_;
    std::shared_ptr<FileLifecycleService> lifecycle_service_;
};

} // namespace securecloud::files::service
