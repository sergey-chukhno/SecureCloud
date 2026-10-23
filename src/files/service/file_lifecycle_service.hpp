#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/domain/encrypted_file_metadata_entity.hpp"
#include "files/domain/file_access_entity.hpp"
#include "files/domain/file_entity.hpp"
#include "files/domain/file_version_entity.hpp"
#include "files/domain/files_outbox_entity.hpp"
#include "files/domain/lifecycle_state_machine.hpp"
#include "files/domain/metadata_validator.hpp"
#include "files/repository/file_access_repository.hpp"
#include "files/repository/file_repository.hpp"
#include "files/repository/file_version_repository.hpp"
#include "files/repository/files_outbox_repository.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::files {

// --- Domain Service Exception Hierarchy ---

class FileServiceException : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

class FileNotFoundException : public FileServiceException {
    using FileServiceException::FileServiceException;
};

class UnauthorizedFileAccessException : public FileServiceException {
    using FileServiceException::FileServiceException;
};

class ImmutableVersionException : public FileServiceException {
    using FileServiceException::FileServiceException;
};

class FileLifecycleValidationException : public FileServiceException {
    using FileServiceException::FileServiceException;
};

/// Summary aggregation of file metadata, client-encrypted fields, and active versions.
struct FileMetadataSummary {
    FileEntity file;
    EncryptedFileMetadataEntity encrypted_meta;
    std::optional<FileVersionEntity> active_version;
    std::vector<FileVersionEntity> all_versions;
    uint32_t expected_chunk_count{0};
};

/// Authoritative domain service managing file metadata, versioning, and lifecycle state.
class FileLifecycleService {
  public:
    explicit FileLifecycleService(
        std::shared_ptr<db::FilesDbConnectionPool> pool,
        std::shared_ptr<FileRepository> file_repo = nullptr,
        std::shared_ptr<FileVersionRepository> version_repo = nullptr,
        std::shared_ptr<FileAccessRepository> access_repo = nullptr,
        std::shared_ptr<FilesOutboxRepository> outbox_repo = nullptr);

    virtual ~FileLifecycleService() = default;

    /// Atomically persists a new file in CREATED state with encrypted metadata and an outbox event.
    virtual std::string create_file(const CreateFileRequestDto& dto, std::chrono::system_clock::time_point now);

    /// Creates a new immutable file version (version_number = N+1).
    /// Enforces the Immutable Completed Versions Invariant: existing versions are never mutated.
    virtual FileVersionEntity create_file_version(const CreateFileVersionRequestDto& dto,
                                                  const std::string& caller_user_id);

    /// Transitions file lifecycle state using optimistic locking and atomically records the outbox event.
    virtual bool transition_lifecycle(const std::string& file_id,
                                      FileStatus expected_current,
                                      FileStatus new_status,
                                      const std::string& caller_user_id,
                                      const std::string& reason = "");

    /// Retrieves aggregated operational and encrypted metadata for a file.
    virtual std::optional<FileMetadataSummary> get_file_metadata(const std::string& file_id,
                                                                 const std::string& caller_user_id);

    /// Validates whether the caller is the file owner or holds an active access grant.
    virtual bool check_ownership_or_access(const FileEntity& file,
                                           const std::string& caller_user_id,
                                           std::string_view permission,
                                           pqxx::work& tx);

    /// Logically deletes a file (AVAILABLE / EXPIRED / CREATED / UPLOADING -> DELETED).
    virtual bool delete_file(const std::string& file_id,
                             const std::string& caller_user_id,
                             const std::string& reason = "");

    /// Scans and transitions files past their retention deadline to EXPIRED.
    virtual size_t evaluate_and_expire_files(std::chrono::system_clock::time_point now, size_t batch_size = 100);

    [[nodiscard]] std::shared_ptr<db::FilesDbConnectionPool> pool() const noexcept { return pool_; }

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
    std::shared_ptr<FileRepository> file_repo_;
    std::shared_ptr<FileVersionRepository> version_repo_;
    std::shared_ptr<FileAccessRepository> access_repo_;
    std::shared_ptr<FilesOutboxRepository> outbox_repo_;
};

} // namespace securecloud::files
