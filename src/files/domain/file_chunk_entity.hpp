#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace securecloud::files {

/// Authoritative status of individual chunk persistence
enum class ChunkStatus { Received, Committed };

/// Strongly typed C++20 domain entity for transfer chunk records.
/// Maps 1:1 to the `file_chunks` PostgreSQL table.
struct FileChunkEntity {
    std::string chunk_id{};
    std::string transfer_id{};
    int32_t chunk_index{0};
    int64_t byte_offset{0};
    int32_t chunk_size{0};
    std::string chunk_hash_sha256{};
    std::string minio_chunk_key{};
    ChunkStatus status{ChunkStatus::Received};
    std::chrono::system_clock::time_point created_at{};

    bool operator==(const FileChunkEntity& other) const = default;
};

} // namespace securecloud::files
