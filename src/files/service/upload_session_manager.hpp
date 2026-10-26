#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/domain/file_chunk_entity.hpp"
#include "files/domain/file_transfer_entity.hpp"
#include "files/repository/file_chunk_repository.hpp"
#include "files/repository/file_transfer_repository.hpp"
#include "securecloud/files/v1/files.pb.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::files {

class TransferException : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

class TransferNotFoundException : public TransferException {
    using TransferException::TransferException;
};

class TransferExpiredException : public TransferException {
    using TransferException::TransferException;
};

class TransferCancelledException : public TransferException {
    using TransferException::TransferException;
};

class UnauthorizedTransferException : public TransferException {
    using TransferException::TransferException;
};

} // namespace securecloud::files

namespace securecloud::files::service {

using securecloud::files::TransferException;
using securecloud::files::TransferNotFoundException;
using securecloud::files::TransferExpiredException;
using securecloud::files::TransferCancelledException;
using securecloud::files::UnauthorizedTransferException;

/// Model representing an active or finalized upload transfer session.
struct UploadSession {
    std::string upload_id;
    std::string file_id;
    std::string owner_user_id;
    std::string owner_device_id;
    std::string conversation_id;
    uint64_t encrypted_size_bytes{0};
    uint32_t expected_chunk_count{0};
    uint32_t uploaded_chunk_count{0};
    std::string encryption_version;
    v1::TransferStatus status{v1::TRANSFER_STATUS_PENDING};
    std::chrono::system_clock::time_point expires_at;
};

/// Progress summary of an upload transfer session.
struct TransferProgress {
    std::string transfer_id;
    std::string file_id;
    TransferStatus status{TransferStatus::Created};
    uint32_t total_chunks{0};
    uint32_t accepted_chunks{0};
    int64_t transferred_bytes{0};
    int64_t total_bytes{0};
    std::vector<int32_t> accepted_chunk_indices;
    std::vector<int32_t> missing_chunk_indices;
    std::chrono::system_clock::time_point expires_at;
    bool is_expired{false};
    bool is_complete{false};
};

/// Interface defining the contract for managing upload transfer sessions,
/// chunk sequence tracking, lease timeouts, and crash-recovery reconstruction.
class IUploadSessionManager {
  public:
    virtual ~IUploadSessionManager() = default;

    virtual std::optional<UploadSession> create_session(const v1::CreateFileUploadRequest& request) = 0;
    virtual std::optional<UploadSession> get_session(const std::string& upload_id) = 0;
    virtual TransferProgress get_transfer_progress(const std::string& upload_id) = 0;
    virtual std::vector<int32_t> get_missing_chunk_indices(const std::string& upload_id) = 0;
    virtual bool cancel_session(const std::string& upload_id, const std::string& reason) = 0;
    virtual UploadSession reconstruct_session_from_storage(const std::string& upload_id) = 0;

    virtual bool record_chunk_upload(const std::string& upload_id, uint32_t chunk_index,
                                     const std::string& ciphertext_sha256) = 0;
    virtual bool finalize_session(const std::string& upload_id, const std::string& expected_sha256) = 0;
};

/// Authoritative Resumable Upload Session Manager with crash recovery.
class UploadSessionManager : public IUploadSessionManager {
  public:
    explicit UploadSessionManager(
        std::shared_ptr<db::FilesDbConnectionPool> pool = nullptr,
        std::shared_ptr<FileTransferRepository> transfer_repo = nullptr,
        std::shared_ptr<FileChunkRepository> chunk_repo = nullptr);

    ~UploadSessionManager() override = default;

    std::optional<UploadSession> create_session(const v1::CreateFileUploadRequest& request) override;
    std::optional<UploadSession> get_session(const std::string& upload_id) override;
    TransferProgress get_transfer_progress(const std::string& upload_id) override;
    std::vector<int32_t> get_missing_chunk_indices(const std::string& upload_id) override;
    bool cancel_session(const std::string& upload_id, const std::string& reason) override;
    UploadSession reconstruct_session_from_storage(const std::string& upload_id) override;

    bool record_chunk_upload(const std::string& upload_id, uint32_t chunk_index,
                             const std::string& ciphertext_sha256) override;
    bool finalize_session(const std::string& upload_id, const std::string& expected_sha256) override;

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
    std::shared_ptr<FileTransferRepository> transfer_repo_;
    std::shared_ptr<FileChunkRepository> chunk_repo_;
    mutable std::mutex session_mutex_;
    std::unordered_map<std::string, UploadSession> in_memory_cache_;
};

} // namespace securecloud::files::service
