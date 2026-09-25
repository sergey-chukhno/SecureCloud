#pragma once

#include "securecloud/files/v1/files.pb.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace securecloud::files::service {

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

/// Interface defining the contract for managing upload transfer sessions,
/// chunk sequence tracking, lease timeouts, and lifecycle transitions.
class IUploadSessionManager {
  public:
    virtual ~IUploadSessionManager() = default;

    /// Initiates a new upload session, generating an upload_id and storing transfer metadata.
    virtual std::optional<UploadSession> create_session(const v1::CreateFileUploadRequest& request) = 0;

    /// Records an acknowledged chunk upload for an active session.
    virtual bool record_chunk_upload(const std::string& upload_id, uint32_t chunk_index,
                                     const std::string& ciphertext_sha256) = 0;

    /// Marks an upload session as finalizing/completed after verifying cumulative hash.
    virtual bool finalize_session(const std::string& upload_id, const std::string& expected_sha256) = 0;

    /// Cancels an active upload session.
    virtual bool cancel_session(const std::string& upload_id, const std::string& reason) = 0;

    /// Retrieves an existing upload session by ID.
    virtual std::optional<UploadSession> get_session(const std::string& upload_id) const = 0;
};

/// Default skeleton implementation of IUploadSessionManager.
class UploadSessionManager : public IUploadSessionManager {
  public:
    UploadSessionManager() = default;
    ~UploadSessionManager() override = default;

    std::optional<UploadSession> create_session(const v1::CreateFileUploadRequest& /*request*/) override {
        return std::nullopt;
    }

    bool record_chunk_upload(const std::string& /*upload_id*/, uint32_t /*chunk_index*/,
                             const std::string& /*ciphertext_sha256*/) override {
        return false;
    }

    bool finalize_session(const std::string& /*upload_id*/, const std::string& /*expected_sha256*/) override {
        return false;
    }

    bool cancel_session(const std::string& /*upload_id*/, const std::string& /*reason*/) override { return false; }

    std::optional<UploadSession> get_session(const std::string& /*upload_id*/) const override { return std::nullopt; }
};

} // namespace securecloud::files::service
