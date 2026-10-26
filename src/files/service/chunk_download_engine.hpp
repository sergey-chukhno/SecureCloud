#pragma once

#include "files/domain/download_validator.hpp"
#include "files/storage/s3_client.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace securecloud::files::service {

/// Result of an individual chunk download operation.
struct ChunkFetchResult {
    std::string file_id;
    int32_t version_number{1};
    uint32_t chunk_index{0};
    std::string encrypted_data;
    uint32_t chunk_size_bytes{0};
    std::string ciphertext_sha256;
};

/// Engine responsible for bounded byte-range retrieval of encrypted chunks from S3.
/// Strictly enforces zero-whole-file buffering: only the requested chunk slice is fetched.
class ChunkDownloadEngine {
  public:
    explicit ChunkDownloadEngine(std::shared_ptr<storage::S3Client> s3_client);
    virtual ~ChunkDownloadEngine() = default;

    ChunkDownloadEngine(const ChunkDownloadEngine&) = delete;
    ChunkDownloadEngine& operator=(const ChunkDownloadEngine&) = delete;
    ChunkDownloadEngine(ChunkDownloadEngine&&) noexcept = default;
    ChunkDownloadEngine& operator=(ChunkDownloadEngine&&) noexcept = default;

    /// Fetches a specific chunk slice for a file version from MinIO/S3 using HTTP Range header.
    /// Calculates byte-range coordinates via calculate_chunk_byte_range.
    /// Computes SHA-256 digest over the retrieved chunk ciphertext.
    /// Throws std::out_of_range if chunk_index exceeds file chunk count.
    /// Throws storage::S3Exception derivatives on storage failure.
    virtual ChunkFetchResult fetch_chunk(
        const std::string& file_id,
        int32_t version_number,
        uint32_t chunk_index,
        uint64_t total_file_size,
        uint32_t standard_chunk_size = k_standard_chunk_size);

    /// Computes canonical S3 version object key: objects/{file_id}/{version_number}
    [[nodiscard]] static std::string build_version_key(const std::string& file_id, int32_t version_number);

  private:
    std::shared_ptr<storage::S3Client> s3_client_;
};

} // namespace securecloud::files::service
