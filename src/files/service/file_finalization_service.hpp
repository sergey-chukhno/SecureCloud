#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/domain/file_entity.hpp"
#include "files/domain/file_transfer_entity.hpp"
#include "files/domain/file_version_entity.hpp"
#include "files/domain/files_outbox_entity.hpp"
#include "files/domain/finalization_validator.hpp"
#include "files/repository/file_chunk_repository.hpp"
#include "files/repository/file_repository.hpp"
#include "files/repository/file_transfer_repository.hpp"
#include "files/repository/file_version_repository.hpp"
#include "files/repository/files_outbox_repository.hpp"
#include "files/service/object_assembly_engine.hpp"

#include <chrono>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace securecloud::files::service {

/// Exception thrown when finalization preconditions fail or contract is violated.
class FinalizationPreconditionException : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

/// Request DTO for finalizing an upload session.
struct FinalizeUploadRequestDto {
    std::string upload_id;
    std::string file_id;
    std::string caller_user_id;
    std::string expected_ciphertext_sha256;
};

/// Result DTO returned upon successful finalization or idempotent replay.
struct FinalizeUploadResultDto {
    std::string file_id;
    int32_t version_number{1};
    uint64_t total_bytes{0};
    std::string checksum_sha256;
    std::chrono::system_clock::time_point available_at;
    bool is_idempotent_replay{false};
};

/// Authoritative Whole-Object Finalization Service.
/// Implements UPLOADING -> FINALIZING -> AVAILABLE lifecycle pipeline,
/// cryptographic whole-ciphertext integrity verification, atomic PostgreSQL state
/// machine transitions, and anti-split-brain idempotency.
class FileFinalizationService {
  public:
    explicit FileFinalizationService(std::shared_ptr<db::FilesDbConnectionPool> pool,
                                     std::shared_ptr<ObjectAssemblyEngine> assembly_engine,
                                     std::shared_ptr<FileTransferRepository> transfer_repo = nullptr,
                                     std::shared_ptr<FileRepository> file_repo = nullptr,
                                     std::shared_ptr<FileVersionRepository> version_repo = nullptr,
                                     std::shared_ptr<FileChunkRepository> chunk_repo = nullptr,
                                     std::shared_ptr<FilesOutboxRepository> outbox_repo = nullptr);

    virtual ~FileFinalizationService() = default;

    FileFinalizationService(const FileFinalizationService&) = delete;
    FileFinalizationService& operator=(const FileFinalizationService&) = delete;
    FileFinalizationService(FileFinalizationService&&) = delete;
    FileFinalizationService& operator=(FileFinalizationService&&) = delete;

    /// Finalizes an uploaded file session.
    /// Strictly guarantees that AVAILABLE is never reported on failure.
    virtual FinalizeUploadResultDto finalize_file_upload(const FinalizeUploadRequestDto& request);

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
    std::shared_ptr<ObjectAssemblyEngine> assembly_engine_;
    std::shared_ptr<FileTransferRepository> transfer_repo_;
    std::shared_ptr<FileRepository> file_repo_;
    std::shared_ptr<FileVersionRepository> version_repo_;
    std::shared_ptr<FileChunkRepository> chunk_repo_;
    std::shared_ptr<FilesOutboxRepository> outbox_repo_;
    std::mutex session_locks_mutex_;
    std::unordered_map<std::string, std::shared_ptr<std::mutex>> session_locks_;
};

} // namespace securecloud::files::service
