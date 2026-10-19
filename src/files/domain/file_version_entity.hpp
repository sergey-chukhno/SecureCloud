#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace securecloud::files {

/// Strongly typed C++20 domain entity for immutable file version snapshots.
/// Maps 1:1 to the `file_versions` PostgreSQL table.
struct FileVersionEntity {
    std::string version_id;
    std::string file_id;
    int32_t version_number{1};
    int64_t encrypted_size{0};
    std::string minio_object_key;
    std::string checksum_sha256;
    std::chrono::system_clock::time_point created_at;
    bool is_active{true};

    bool operator==(const FileVersionEntity& other) const = default;
};

} // namespace securecloud::files
