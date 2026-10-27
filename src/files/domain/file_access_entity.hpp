#pragma once

#include <chrono>
#include <optional>
#include <string>

namespace securecloud::files {

/// Authoritative granular file permission levels
enum class FilePermission { Read, Write, Admin };

/// Strongly typed C++20 domain entity for file-level access control grants.
/// Maps 1:1 to the `file_access` PostgreSQL table.
struct FileAccessEntity {
    std::string access_id{};
    std::string file_id{};
    std::string grantee_user_id{};
    std::optional<std::string> grantee_device_id{std::nullopt};
    FilePermission permission{FilePermission::Read};
    std::string granted_by{};
    std::chrono::system_clock::time_point granted_at{};
    std::optional<std::chrono::system_clock::time_point> revoked_at{std::nullopt};

    bool operator==(const FileAccessEntity& other) const = default;
};

} // namespace securecloud::files
