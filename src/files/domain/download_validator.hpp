#pragma once

#include "files/domain/file_entity.hpp"
#include "files/domain/file_version_entity.hpp"
#include "files/domain/metadata_validator.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace securecloud::files {

/// Calculation result of byte-range coordinates for a chunk.
struct ChunkByteRange {
    uint64_t start_byte{0};
    uint64_t end_byte{0};
    uint32_t chunk_size_bytes{0};
    uint32_t total_chunks{0};
};

/// Validation input bundle for download precondition checks.
struct DownloadValidationInput {
    std::string file_id;
    int32_t requested_version{0}; // 0 indicates active/latest version
    uint32_t chunk_index{0};
    FileEntity file;
    std::optional<FileVersionEntity> version{std::nullopt};
    std::string caller_user_id;
    bool has_read_permission{false};
};

/// Result of download precondition validation.
struct DownloadValidationResult {
    bool is_valid{true};
    std::string error_message;

    [[nodiscard]] explicit operator bool() const noexcept { return is_valid; }

    static DownloadValidationResult success() noexcept { return {true, ""}; }
    static DownloadValidationResult failure(std::string message) { return {false, std::move(message)}; }
};

/// Computes exact byte offsets and chunk size for a given chunk index.
/// Throws std::invalid_argument or returns std::nullopt if total_file_size is 0 or chunk_index is out of range.
[[nodiscard]] std::optional<ChunkByteRange> calculate_chunk_byte_range(
    uint64_t total_file_size,
    uint32_t chunk_index,
    uint32_t standard_chunk_size = k_standard_chunk_size) noexcept;

/// Validates all download preconditions:
/// 1. file_id format (UUIDv7 / RFC 4122)
/// 2. Authorization (caller has read permission or is owner)
/// 3. File status is FileStatus::Available
/// 4. Version snapshot exists and is active/valid
/// 5. chunk_index is within bounds [0, total_chunks - 1]
[[nodiscard]] DownloadValidationResult validate_download_preconditions(
    const DownloadValidationInput& input);

} // namespace securecloud::files
