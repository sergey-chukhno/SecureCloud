#pragma once

#include "domain/conversation_id.hpp"
#include "domain/user_id.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::client::domain {

inline constexpr uint32_t kDefaultFileWireChunkSize = 4U * 1024U * 1024U;
inline constexpr uint32_t kMaxFileWireChunkSize = 8U * 1024U * 1024U;
inline constexpr uint32_t kFileChunkAeadOverheadBytes = 28U;
inline constexpr uint64_t kMaxEncryptedFileSizeBytes = 5ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr std::string_view kDefaultFileCipherSuite = "AES-256-GCM-v1";

enum class FileTransferDirection { Outbound, Inbound };

[[nodiscard]] std::string_view to_string(FileTransferDirection direction) noexcept;
[[nodiscard]] std::optional<FileTransferDirection> file_transfer_direction_from_string(std::string_view str) noexcept;

enum class FileTransferStatus { Pending, InProgress, Paused, Finalizing, Completed, Cancelled, Failed };

[[nodiscard]] std::string_view to_string(FileTransferStatus status) noexcept;
[[nodiscard]] std::optional<FileTransferStatus> file_transfer_status_from_string(std::string_view str) noexcept;

struct FileTransferRecord {
    std::string transfer_id;
    std::string file_id;
    std::string upload_id;
    ConversationId conversation_id;
    UserId peer_user_id;
    std::string local_path;
    std::string file_name;
    std::string mime_type{"application/octet-stream"};
    std::string cipher_suite{std::string(kDefaultFileCipherSuite)};
    FileTransferDirection direction{FileTransferDirection::Outbound};
    FileTransferStatus status{FileTransferStatus::Pending};
    uint64_t plaintext_size_bytes{0};
    uint64_t encrypted_size_bytes{0};
    uint32_t chunk_size_bytes{kDefaultFileWireChunkSize};
    uint32_t total_chunks{0};
    uint32_t completed_chunks{0};
    std::string plaintext_sha256;
    std::string ciphertext_sha256;
    std::string error_message;
    int64_t created_at_ms{0};
    int64_t updated_at_ms{0};

    [[nodiscard]] uint32_t progress_percent() const noexcept;
    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] static std::optional<FileTransferRecord> from_json(std::string_view json_str);

    bool operator==(const FileTransferRecord& other) const noexcept = default;
};

struct FileAttachmentKeyEnvelope {
    static constexpr std::string_view kEnvelopeType = "securecloud.file_attachment_key.v1";
    static constexpr uint32_t kSchemaVersion = 1U;

    std::string file_id;
    securecloud::common::configuration::SecretString file_key_hex;
    std::string file_name;
    std::string mime_type{"application/octet-stream"};
    uint64_t plaintext_size_bytes{0};
    uint64_t encrypted_size_bytes{0};
    uint32_t chunk_size_bytes{kDefaultFileWireChunkSize};
    uint32_t chunk_count{0};
    std::string ciphertext_sha256;
    std::string plaintext_sha256;
    std::string cipher_suite{std::string(kDefaultFileCipherSuite)};

    [[nodiscard]] std::string serialize() const;
    [[nodiscard]] static std::optional<FileAttachmentKeyEnvelope> deserialize(std::string_view json_str);
    [[nodiscard]] static bool is_file_attachment_envelope(std::string_view payload) noexcept;

    bool operator==(const FileAttachmentKeyEnvelope& other) const noexcept = default;
};

} // namespace securecloud::client::domain
