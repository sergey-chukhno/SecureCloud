#pragma once

#include "files/domain/metadata_validator.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace securecloud::files {

inline constexpr uint32_t k_max_chunk_size = 8U * 1024U * 1024U; // 8 MiB hard limit
inline constexpr uint32_t k_min_chunk_size = 1U;                 // 1 byte minimum
inline constexpr size_t k_sha256_hex_length = 64;

/// DTO holding encrypted chunk data and transfer metadata.
struct ChunkPayloadDto {
    std::string upload_id;
    uint32_t chunk_index{0};
    std::string encrypted_data;
    uint32_t chunk_size_bytes{0};
    std::string claimed_sha256;
};

/// Result of chunk validation.
struct ChunkValidationResult {
    bool is_valid{true};
    std::string error_message;
    std::string computed_sha256;

    [[nodiscard]] explicit operator bool() const noexcept { return is_valid; }

    static ChunkValidationResult success(std::string computed_hash) {
        return {true, "", std::move(computed_hash)};
    }

    static ChunkValidationResult failure(std::string message, std::string computed_hash = "") {
        return {false, std::move(message), std::move(computed_hash)};
    }
};

/// Computes the lowercase hexadecimal SHA-256 digest over the given data.
[[nodiscard]] std::string compute_sha256_hex(std::string_view data);

/// Validates chunk payload metadata, size constraints, and cryptographic SHA-256 digest.
[[nodiscard]] ChunkValidationResult validate_chunk_payload(const ChunkPayloadDto& dto,
                                                          uint32_t total_chunks,
                                                          uint64_t total_file_size_bytes);

} // namespace securecloud::files
