#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::files {

/// Granular operation authorization level permitted by a file capability
enum class FileCapabilityOperation {
    Read,    // Chunk download and content retrieval
    Write,   // Chunk upload and transfer finalization
    Delete,  // File deletion
    Metadata // File metadata retrieval
};

[[nodiscard]] constexpr std::string_view to_string(FileCapabilityOperation op) noexcept {
    switch (op) {
    case FileCapabilityOperation::Read:
        return "read";
    case FileCapabilityOperation::Write:
        return "write";
    case FileCapabilityOperation::Delete:
        return "delete";
    case FileCapabilityOperation::Metadata:
        return "metadata";
    }
    return "unknown";
}

[[nodiscard]] inline std::optional<FileCapabilityOperation>
file_capability_operation_from_string(std::string_view s) noexcept {
    if (s == "read")
        return FileCapabilityOperation::Read;
    if (s == "write")
        return FileCapabilityOperation::Write;
    if (s == "delete")
        return FileCapabilityOperation::Delete;
    if (s == "metadata")
        return FileCapabilityOperation::Metadata;
    return std::nullopt;
}

/// Strongly-typed claims model for the signed File-Access Capability token.
/// Represents a short-lived authorization grant bound to an authenticated user, device, and file.
struct FileAccessCapabilityClaims {
    std::string capability_id; // UUIDv7 unique capability identifier / nonce
    std::string user_id;       // Authorized grantee user UUIDv7
    std::string device_id;     // Authorized grantee device UUIDv7
    std::string file_id;       // Target file UUIDv7
    int32_t file_version{0};   // 0 = any/active version, >0 = pinned version
    FileCapabilityOperation operation{FileCapabilityOperation::Read};
    std::chrono::system_clock::time_point issued_at{};
    std::chrono::system_clock::time_point expires_at{};
    std::string issuer{"securecloud-files"};

    [[nodiscard]] bool is_expired(std::chrono::system_clock::time_point now,
                                  std::chrono::seconds clock_skew = std::chrono::seconds{30}) const noexcept {
        return now > (expires_at + clock_skew);
    }

    [[nodiscard]] bool is_premature(std::chrono::system_clock::time_point now,
                                    std::chrono::seconds clock_skew = std::chrono::seconds{30}) const noexcept {
        return (now + clock_skew) < issued_at;
    }

    bool operator==(const FileAccessCapabilityClaims& other) const = default;
};

} // namespace securecloud::files
