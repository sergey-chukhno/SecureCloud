#include "files/domain/chunk_validator.hpp"
#include "files/domain/metadata_validator.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <openssl/sha.h>
#include <sstream>

namespace securecloud::files {

std::string compute_sha256_hex(std::string_view data) {
    std::array<uint8_t, SHA256_DIGEST_LENGTH> hash{};
    SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), hash.data());

    static constexpr char k_hex_digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(SHA256_DIGEST_LENGTH * 2);
    for (uint8_t b : hash) {
        hex.push_back(k_hex_digits[(b >> 4) & 0x0F]);
        hex.push_back(k_hex_digits[b & 0x0F]);
    }
    return hex;
}

ChunkValidationResult validate_chunk_payload(const ChunkPayloadDto& dto,
                                             uint32_t total_chunks,
                                             uint64_t total_file_size_bytes) {
    if (!is_valid_uuid(dto.upload_id)) {
        return ChunkValidationResult::failure("upload_id must be a valid RFC 4122 / UUIDv7 string");
    }

    if (total_chunks == 0) {
        return ChunkValidationResult::failure("total_chunks must be greater than zero");
    }

    if (dto.chunk_index >= total_chunks) {
        return ChunkValidationResult::failure(
            "chunk_index " + std::to_string(dto.chunk_index) +
            " is out of bounds for total_chunks " + std::to_string(total_chunks));
    }

    if (dto.chunk_size_bytes != dto.encrypted_data.size()) {
        return ChunkValidationResult::failure(
            "chunk_size_bytes (" + std::to_string(dto.chunk_size_bytes) +
            ") does not match encrypted_data size (" + std::to_string(dto.encrypted_data.size()) + ")");
    }

    if (dto.chunk_size_bytes < k_min_chunk_size) {
        return ChunkValidationResult::failure("chunk_size_bytes must be at least 1 byte");
    }

    if (dto.chunk_size_bytes > k_max_chunk_size) {
        return ChunkValidationResult::failure(
            "chunk_size_bytes (" + std::to_string(dto.chunk_size_bytes) +
            ") exceeds maximum allowed chunk size of 8 MiB (" + std::to_string(k_max_chunk_size) + ")");
    }

    // Size checks based on terminal vs non-terminal chunks
    if (dto.chunk_index < total_chunks - 1) {
        // Non-terminal chunks must be exactly k_standard_chunk_size (4 MiB)
        if (dto.chunk_size_bytes != k_standard_chunk_size) {
            return ChunkValidationResult::failure(
                "Non-terminal chunk " + std::to_string(dto.chunk_index) +
                " size (" + std::to_string(dto.chunk_size_bytes) +
                ") must equal standard chunk size of 4 MiB (" + std::to_string(k_standard_chunk_size) + ")");
        }
    } else {
        // Terminal chunk
        uint64_t prior_bytes = static_cast<uint64_t>(dto.chunk_index) * k_standard_chunk_size;
        if (total_file_size_bytes < prior_bytes) {
            return ChunkValidationResult::failure("total_file_size_bytes is less than cumulative chunk offset");
        }
        uint64_t expected_terminal_size = total_file_size_bytes - prior_bytes;
        if (dto.chunk_size_bytes != expected_terminal_size) {
            return ChunkValidationResult::failure(
                "Terminal chunk " + std::to_string(dto.chunk_index) +
                " size (" + std::to_string(dto.chunk_size_bytes) +
                ") does not match expected remaining size (" + std::to_string(expected_terminal_size) + ")");
        }
    }

    if (!is_valid_sha256_hex(dto.claimed_sha256)) {
        return ChunkValidationResult::failure("claimed_sha256 must be a 64-character hexadecimal string");
    }

    std::string computed_hash = compute_sha256_hex(dto.encrypted_data);

    // Case-insensitive comparison
    bool hash_matches = (dto.claimed_sha256.size() == computed_hash.size()) &&
                        std::equal(dto.claimed_sha256.begin(), dto.claimed_sha256.end(),
                                   computed_hash.begin(),
                                   [](char a, char b) {
                                       return std::tolower(static_cast<unsigned char>(a)) ==
                                              std::tolower(static_cast<unsigned char>(b));
                                   });

    if (!hash_matches) {
        return ChunkValidationResult::failure(
            "Cryptographic SHA-256 digest mismatch: computed " + computed_hash +
            " but claimed " + dto.claimed_sha256,
            computed_hash);
    }

    return ChunkValidationResult::success(computed_hash);
}

} // namespace securecloud::files
