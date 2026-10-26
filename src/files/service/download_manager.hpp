#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/domain/download_validator.hpp"
#include "files/repository/file_access_repository.hpp"
#include "files/repository/file_repository.hpp"
#include "files/repository/file_version_repository.hpp"
#include "files/service/chunk_download_engine.hpp"
#include "files/service/file_lifecycle_service.hpp"
#include "securecloud/files/v1/files.pb.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace securecloud::files::service {

/// Exception thrown when download preconditions (e.g. invalid state or bounds) fail.
class InvalidDownloadPreconditionException : public FileServiceException {
  public:
    using FileServiceException::FileServiceException;
};

/// Model representing a retrieved chunk of encrypted file data.
struct DownloadChunkResult {
    std::string file_id;
    int32_t version_number{1};
    uint32_t chunk_index{0};
    std::string encrypted_data;
    uint32_t chunk_size_bytes{0};
    std::string ciphertext_sha256;
};

/// Canonical resume model descriptor (FILES-007):
/// (file_id, file_version, starting_chunk)
struct DownloadResumeModel {
    std::string file_id;
    int32_t version_number{1};
    uint32_t starting_chunk{0};
    uint32_t total_chunks{0};
    uint64_t total_bytes{0};
    std::string ciphertext_sha256;
};

/// Interface defining the contract for validating download authorizations and retrieving chunks.
class IDownloadManager {
  public:
    virtual ~IDownloadManager() = default;

    /// Validates whether the caller has authorization to download chunks of the specified file.
    virtual bool authorize_download(const std::string& file_id, const std::string& caller_user_id) = 0;

    /// Retrieves a specific encrypted chunk for a given file (defaults to active version).
    virtual std::optional<DownloadChunkResult> get_chunk(const std::string& file_id, uint32_t chunk_index) = 0;

    /// Version-aware and caller-authorized chunk retrieval.
    /// If version_number is 0, uses latest active version.
    virtual DownloadChunkResult get_chunk_versioned(
        const std::string& file_id,
        int32_t version_number,
        uint32_t chunk_index,
        const std::string& caller_user_id) = 0;

    /// Prepares and validates a resumable download session based on canonical (file_id, version, starting_chunk).
    virtual DownloadResumeModel prepare_resume_session(
        const std::string& file_id,
        int32_t version_number,
        uint32_t starting_chunk,
        const std::string& caller_user_id) = 0;
};

/// Production implementation of IDownloadManager.
class DownloadManager : public IDownloadManager {
  public:
    explicit DownloadManager(
        std::shared_ptr<db::FilesDbConnectionPool> pool = nullptr,
        std::shared_ptr<ChunkDownloadEngine> download_engine = nullptr,
        std::shared_ptr<FileRepository> file_repo = nullptr,
        std::shared_ptr<FileVersionRepository> version_repo = nullptr,
        std::shared_ptr<FileAccessRepository> access_repo = nullptr);

    ~DownloadManager() override = default;

    DownloadManager(const DownloadManager&) = delete;
    DownloadManager& operator=(const DownloadManager&) = delete;
    DownloadManager(DownloadManager&&) noexcept = default;
    DownloadManager& operator=(DownloadManager&&) noexcept = default;

    bool authorize_download(const std::string& file_id, const std::string& caller_user_id) override;

    std::optional<DownloadChunkResult> get_chunk(const std::string& file_id, uint32_t chunk_index) override;

    DownloadChunkResult get_chunk_versioned(
        const std::string& file_id,
        int32_t version_number,
        uint32_t chunk_index,
        const std::string& caller_user_id) override;

    DownloadResumeModel prepare_resume_session(
        const std::string& file_id,
        int32_t version_number,
        uint32_t starting_chunk,
        const std::string& caller_user_id) override;

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
    std::shared_ptr<ChunkDownloadEngine> download_engine_;
    std::shared_ptr<FileRepository> file_repo_;
    std::shared_ptr<FileVersionRepository> version_repo_;
    std::shared_ptr<FileAccessRepository> access_repo_;
};

} // namespace securecloud::files::service
