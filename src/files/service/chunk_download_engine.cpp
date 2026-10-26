#include "files/service/chunk_download_engine.hpp"
#include "files/domain/chunk_validator.hpp"
#include "files/storage/s3_exceptions.hpp"

#include <stdexcept>

namespace securecloud::files::service {

ChunkDownloadEngine::ChunkDownloadEngine(std::shared_ptr<storage::S3Client> s3_client)
    : s3_client_(std::move(s3_client)) {}

std::string ChunkDownloadEngine::build_version_key(const std::string& file_id, int32_t version_number) {
    return "objects/" + file_id + "/" + std::to_string(version_number);
}

ChunkFetchResult ChunkDownloadEngine::fetch_chunk(
    const std::string& file_id,
    int32_t version_number,
    uint32_t chunk_index,
    uint64_t total_file_size,
    uint32_t standard_chunk_size) {
    if (!s3_client_) {
        throw storage::S3ClientException("S3Client is uninitialized in ChunkDownloadEngine");
    }

    auto range_opt = calculate_chunk_byte_range(total_file_size, chunk_index, standard_chunk_size);
    if (!range_opt.has_value()) {
        throw std::out_of_range(
            "Chunk index " + std::to_string(chunk_index) +
            " is out of bounds for file " + file_id + " (total size: " +
            std::to_string(total_file_size) + " bytes)");
    }

    if (total_file_size == 0) {
        std::string empty_hash = compute_sha256_hex("");
        return ChunkFetchResult{
            .file_id = file_id,
            .version_number = version_number,
            .chunk_index = 0,
            .encrypted_data = "",
            .chunk_size_bytes = 0,
            .ciphertext_sha256 = empty_hash
        };
    }

    std::string key = build_version_key(file_id, version_number);
    storage::ByteRange byte_range{
        .start_byte = range_opt->start_byte,
        .end_byte = range_opt->end_byte
    };

    auto resp = s3_client_->get_object(key, byte_range);

    std::string chunk_sha256 = compute_sha256_hex(resp.body);

    return ChunkFetchResult{
        .file_id = file_id,
        .version_number = version_number,
        .chunk_index = chunk_index,
        .encrypted_data = std::move(resp.body),
        .chunk_size_bytes = static_cast<uint32_t>(resp.body.size()),
        .ciphertext_sha256 = std::move(chunk_sha256)
    };
}

} // namespace securecloud::files::service
