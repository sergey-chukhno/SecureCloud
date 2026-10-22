#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace securecloud::files {

/// Authoritative file lifecycle states (Files Design 6.3)
enum class FileStatus { Created, Uploading, Finalizing, Available, Expired, Deleted, Failed };

/// Strongly typed C++20 domain entity for master logical file records.
/// Maps 1:1 to the `files` PostgreSQL table.
struct FileEntity {
    std::string file_id;
    std::string owner_user_id;
    std::string owner_device_id;
    std::optional<std::string> conversation_id{std::nullopt};
    int64_t encrypted_size{0};
    std::optional<std::string> content_type{std::nullopt};
    std::string encryption_algorithm{"XChaCha20-Poly1305"};
    FileStatus status{FileStatus::Created};
    std::optional<std::chrono::system_clock::time_point> retention_until{std::nullopt};
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;

    bool operator==(const FileEntity& other) const = default;
};

} // namespace securecloud::files
