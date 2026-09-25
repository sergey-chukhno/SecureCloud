#pragma once

#include "securecloud/files/v1/files.pb.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace securecloud::files::service {

/// Model representing a retrieved chunk of encrypted file data.
struct DownloadChunkResult {
    std::string file_id;
    uint32_t chunk_index{0};
    std::string encrypted_data;
    uint32_t chunk_size_bytes{0};
    std::string ciphertext_sha256;
};

/// Interface defining the contract for validating download authorizations and retrieving chunks.
class IDownloadManager {
  public:
    virtual ~IDownloadManager() = default;

    /// Validates whether the caller has authorization to download chunks of the specified file.
    virtual bool authorize_download(const std::string& file_id, const std::string& caller_user_id) = 0;

    /// Retrieves a specific encrypted chunk for a given file.
    virtual std::optional<DownloadChunkResult> get_chunk(const std::string& file_id, uint32_t chunk_index) = 0;
};

/// Default skeleton implementation of IDownloadManager.
class DownloadManager : public IDownloadManager {
  public:
    DownloadManager() = default;
    ~DownloadManager() override = default;

    bool authorize_download(const std::string& /*file_id*/, const std::string& /*caller_user_id*/) override {
        return false;
    }

    std::optional<DownloadChunkResult> get_chunk(const std::string& /*file_id*/, uint32_t /*chunk_index*/) override {
        return std::nullopt;
    }
};

} // namespace securecloud::files::service
