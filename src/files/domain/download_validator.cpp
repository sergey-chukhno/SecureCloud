#include "files/domain/download_validator.hpp"

#include "files/domain/lifecycle_state_machine.hpp"

#include <algorithm>

namespace securecloud::files {

std::optional<ChunkByteRange> calculate_chunk_byte_range(uint64_t total_file_size, uint32_t chunk_index,
                                                         uint32_t standard_chunk_size) noexcept {
    if (standard_chunk_size == 0) {
        return std::nullopt;
    }

    if (total_file_size == 0) {
        if (chunk_index == 0) {
            return ChunkByteRange{.start_byte = 0, .end_byte = 0, .chunk_size_bytes = 0, .total_chunks = 0};
        }
        return std::nullopt;
    }

    uint32_t total_chunks = static_cast<uint32_t>((total_file_size + standard_chunk_size - 1) / standard_chunk_size);

    if (chunk_index >= total_chunks) {
        return std::nullopt;
    }

    uint64_t start_byte = static_cast<uint64_t>(chunk_index) * standard_chunk_size;
    uint64_t end_byte = std::min(start_byte + standard_chunk_size - 1, total_file_size - 1);
    uint32_t chunk_size = static_cast<uint32_t>(end_byte - start_byte + 1);

    return ChunkByteRange{
        .start_byte = start_byte, .end_byte = end_byte, .chunk_size_bytes = chunk_size, .total_chunks = total_chunks};
}

DownloadValidationResult validate_download_preconditions(const DownloadValidationInput& input) {
    // 1. Validate file_id format
    if (!is_valid_uuid(input.file_id)) {
        return DownloadValidationResult::failure("Invalid file_id format: " + input.file_id);
    }

    if (input.file.file_id.empty() || input.file.file_id != input.file_id) {
        return DownloadValidationResult::failure("File record does not match requested file_id");
    }

    // 2. Validate authorization
    bool is_owner = (!input.caller_user_id.empty() && input.caller_user_id == input.file.owner_user_id);
    if (!is_owner && !input.has_read_permission) {
        return DownloadValidationResult::failure("Caller lacks READ authorization for file: " + input.file_id);
    }

    // 3. Validate file lifecycle state (must be AVAILABLE)
    if (input.file.status != FileStatus::Available) {
        return DownloadValidationResult::failure("File is not available for download; current status: " +
                                                 std::string(to_string(input.file.status)));
    }

    // 4. Validate version snapshot
    if (!input.version.has_value()) {
        return DownloadValidationResult::failure("File version snapshot not found");
    }

    if (input.requested_version > 0 && input.version->version_number != input.requested_version) {
        return DownloadValidationResult::failure("Requested version " + std::to_string(input.requested_version) +
                                                 " does not match retrieved snapshot version " +
                                                 std::to_string(input.version->version_number));
    }

    // 5. Validate chunk index bounds
    uint64_t file_size = static_cast<uint64_t>(input.version->encrypted_size);
    auto range_opt = calculate_chunk_byte_range(file_size, input.chunk_index);
    if (!range_opt.has_value()) {
        uint32_t total_chunks =
            (file_size == 0) ? 0
                             : static_cast<uint32_t>((file_size + k_standard_chunk_size - 1) / k_standard_chunk_size);
        return DownloadValidationResult::failure("Chunk index " + std::to_string(input.chunk_index) +
                                                 " is out of bounds (file has " + std::to_string(total_chunks) +
                                                 " chunks)");
    }

    return DownloadValidationResult::success();
}

} // namespace securecloud::files
