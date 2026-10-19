#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace securecloud::files {

/// Authoritative transfer direction
enum class TransferType { Upload, Download };

/// Authoritative transfer session lifecycle states
enum class TransferStatus { Created, Transferring, Finalizing, Completed, Failed, Expired, Cancelled };

/// Strongly typed C++20 domain entity for resumable upload/download transfer sessions.
/// Maps 1:1 to the `file_transfers` PostgreSQL table.
struct FileTransferEntity {
    std::string transfer_id;
    std::string file_id;
    TransferType transfer_type{TransferType::Upload};
    std::string initiator_user_id;
    std::string initiator_device_id;
    TransferStatus status{TransferStatus::Created};
    int32_t total_chunks{0};
    int32_t accepted_chunks{0};
    int64_t total_bytes{0};
    int64_t transferred_bytes{0};
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;
    std::chrono::system_clock::time_point expires_at;

    bool operator==(const FileTransferEntity& other) const = default;
};

} // namespace securecloud::files
