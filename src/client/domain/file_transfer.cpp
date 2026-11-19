#include "domain/file_transfer.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <nlohmann/json.hpp>

namespace securecloud::client::domain {
namespace {

bool is_valid_hex_string(std::string_view value, std::size_t expected_len) noexcept {
    if (value.size() != expected_len) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) noexcept { return std::isxdigit(ch) != 0; });
}

bool extract_required_nonempty_string(const nlohmann::json& j, const char* key, std::string& out) {
    const auto it = j.find(key);
    if (it == j.end() || !it->is_string()) {
        return false;
    }
    out = it->get<std::string>();
    return !out.empty();
}

bool extract_optional_string(const nlohmann::json& j, const char* key, std::string& out) {
    const auto it = j.find(key);
    if (it == j.end()) {
        return true;
    }
    if (!it->is_string()) {
        return false;
    }
    out = it->get<std::string>();
    return true;
}

bool extract_optional_u64(const nlohmann::json& j, const char* key, uint64_t& out) {
    const auto it = j.find(key);
    if (it == j.end()) {
        return true;
    }
    if (!it->is_number_unsigned()) {
        return false;
    }
    out = it->get<uint64_t>();
    return true;
}

bool extract_required_u64(const nlohmann::json& j, const char* key, uint64_t& out) {
    const auto it = j.find(key);
    if (it == j.end() || !it->is_number_unsigned()) {
        return false;
    }
    out = it->get<uint64_t>();
    return true;
}

bool extract_u32_value(const nlohmann::json& value, uint32_t& out) {
    if (!value.is_number_unsigned()) {
        return false;
    }
    const auto raw = value.get<uint64_t>();
    if (raw > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
        return false;
    }
    out = static_cast<uint32_t>(raw);
    return true;
}

bool extract_optional_u32(const nlohmann::json& j, const char* key, uint32_t& out) {
    const auto it = j.find(key);
    if (it == j.end()) {
        return true;
    }
    return extract_u32_value(*it, out);
}

bool extract_required_u32(const nlohmann::json& j, const char* key, uint32_t& out) {
    const auto it = j.find(key);
    if (it == j.end()) {
        return false;
    }
    return extract_u32_value(*it, out);
}

bool extract_optional_i64(const nlohmann::json& j, const char* key, int64_t& out) {
    const auto it = j.find(key);
    if (it == j.end()) {
        return true;
    }
    if (!it->is_number_integer()) {
        return false;
    }
    out = it->get<int64_t>();
    return true;
}

} // namespace

std::string_view to_string(FileTransferDirection direction) noexcept {
    switch (direction) {
    case FileTransferDirection::Outbound:
        return "Outbound";
    case FileTransferDirection::Inbound:
        return "Inbound";
    }
    return "Unknown";
}

std::optional<FileTransferDirection> file_transfer_direction_from_string(std::string_view str) noexcept {
    if (str == "Outbound") {
        return FileTransferDirection::Outbound;
    }
    if (str == "Inbound") {
        return FileTransferDirection::Inbound;
    }
    return std::nullopt;
}

std::string_view to_string(FileTransferStatus status) noexcept {
    switch (status) {
    case FileTransferStatus::Pending:
        return "Pending";
    case FileTransferStatus::InProgress:
        return "InProgress";
    case FileTransferStatus::Paused:
        return "Paused";
    case FileTransferStatus::Finalizing:
        return "Finalizing";
    case FileTransferStatus::Completed:
        return "Completed";
    case FileTransferStatus::Cancelled:
        return "Cancelled";
    case FileTransferStatus::Failed:
        return "Failed";
    }
    return "Unknown";
}

std::optional<FileTransferStatus> file_transfer_status_from_string(std::string_view str) noexcept {
    if (str == "Pending") {
        return FileTransferStatus::Pending;
    }
    if (str == "InProgress") {
        return FileTransferStatus::InProgress;
    }
    if (str == "Paused") {
        return FileTransferStatus::Paused;
    }
    if (str == "Finalizing") {
        return FileTransferStatus::Finalizing;
    }
    if (str == "Completed") {
        return FileTransferStatus::Completed;
    }
    if (str == "Cancelled") {
        return FileTransferStatus::Cancelled;
    }
    if (str == "Failed") {
        return FileTransferStatus::Failed;
    }
    return std::nullopt;
}

uint32_t FileTransferRecord::progress_percent() const noexcept {
    if (status == FileTransferStatus::Completed) {
        return 100U;
    }
    if (total_chunks == 0U) {
        return 0U;
    }
    const uint32_t bounded_completed = std::min(completed_chunks, total_chunks);
    return static_cast<uint32_t>((static_cast<uint64_t>(bounded_completed) * 100ULL) /
                                 static_cast<uint64_t>(total_chunks));
}

std::string FileTransferRecord::to_json() const {
    nlohmann::json j;
    j["transfer_id"] = transfer_id;
    j["file_id"] = file_id;
    j["upload_id"] = upload_id;
    j["conversation_id"] = conversation_id.value();
    j["peer_user_id"] = peer_user_id.value();
    j["local_path"] = local_path;
    j["file_name"] = file_name;
    j["mime_type"] = mime_type;
    j["cipher_suite"] = cipher_suite;
    j["direction"] = std::string(to_string(direction));
    j["status"] = std::string(to_string(status));
    j["plaintext_size_bytes"] = plaintext_size_bytes;
    j["encrypted_size_bytes"] = encrypted_size_bytes;
    j["chunk_size_bytes"] = chunk_size_bytes;
    j["total_chunks"] = total_chunks;
    j["completed_chunks"] = completed_chunks;
    j["plaintext_sha256"] = plaintext_sha256;
    j["ciphertext_sha256"] = ciphertext_sha256;
    j["error_message"] = error_message;
    j["created_at_ms"] = created_at_ms;
    j["updated_at_ms"] = updated_at_ms;
    return j.dump();
}

std::optional<FileTransferRecord> FileTransferRecord::from_json(std::string_view json_str) {
    try {
        const auto j = nlohmann::json::parse(json_str);
        if (!j.is_object()) {
            return std::nullopt;
        }

        FileTransferRecord record;
        std::string conversation_id_str;
        std::string peer_user_id_str;
        std::string direction_str;
        std::string status_str;

        if (!extract_required_nonempty_string(j, "transfer_id", record.transfer_id) ||
            !extract_required_nonempty_string(j, "file_id", record.file_id) ||
            !extract_required_nonempty_string(j, "conversation_id", conversation_id_str) ||
            !extract_required_nonempty_string(j, "direction", direction_str) ||
            !extract_required_nonempty_string(j, "status", status_str)) {
            return std::nullopt;
        }

        const auto direction_opt = file_transfer_direction_from_string(direction_str);
        const auto status_opt = file_transfer_status_from_string(status_str);
        if (!direction_opt.has_value() || !status_opt.has_value()) {
            return std::nullopt;
        }
        record.direction = *direction_opt;
        record.status = *status_opt;
        record.conversation_id = ConversationId(std::move(conversation_id_str));

        if (!extract_optional_string(j, "peer_user_id", peer_user_id_str)) {
            return std::nullopt;
        }
        if (!peer_user_id_str.empty()) {
            record.peer_user_id = UserId(std::move(peer_user_id_str));
        }

        if (!extract_optional_string(j, "upload_id", record.upload_id) ||
            !extract_optional_string(j, "local_path", record.local_path) ||
            !extract_optional_string(j, "file_name", record.file_name) ||
            !extract_optional_string(j, "mime_type", record.mime_type) ||
            !extract_optional_string(j, "cipher_suite", record.cipher_suite) ||
            !extract_optional_string(j, "plaintext_sha256", record.plaintext_sha256) ||
            !extract_optional_string(j, "ciphertext_sha256", record.ciphertext_sha256) ||
            !extract_optional_string(j, "error_message", record.error_message) ||
            !extract_optional_u64(j, "plaintext_size_bytes", record.plaintext_size_bytes) ||
            !extract_optional_u64(j, "encrypted_size_bytes", record.encrypted_size_bytes) ||
            !extract_optional_u32(j, "chunk_size_bytes", record.chunk_size_bytes) ||
            !extract_optional_u32(j, "total_chunks", record.total_chunks) ||
            !extract_optional_u32(j, "completed_chunks", record.completed_chunks) ||
            !extract_optional_i64(j, "created_at_ms", record.created_at_ms) ||
            !extract_optional_i64(j, "updated_at_ms", record.updated_at_ms)) {
            return std::nullopt;
        }

        return record;
    } catch (...) {
        return std::nullopt;
    }
}

std::string FileAttachmentKeyEnvelope::serialize() const {
    nlohmann::json j;
    j["type"] = std::string(kEnvelopeType);
    j["version"] = kSchemaVersion;
    j["file_id"] = file_id;
    j["file_key_hex"] = file_key_hex.expose_unredacted_secret();
    j["file_name"] = file_name;
    j["mime_type"] = mime_type;
    j["plaintext_size_bytes"] = plaintext_size_bytes;
    j["encrypted_size_bytes"] = encrypted_size_bytes;
    j["chunk_size_bytes"] = chunk_size_bytes;
    j["chunk_count"] = chunk_count;
    j["ciphertext_sha256"] = ciphertext_sha256;
    j["plaintext_sha256"] = plaintext_sha256;
    j["cipher_suite"] = cipher_suite;
    return j.dump();
}

std::optional<FileAttachmentKeyEnvelope> FileAttachmentKeyEnvelope::deserialize(std::string_view json_str) {
    try {
        const auto j = nlohmann::json::parse(json_str);
        if (!j.is_object()) {
            return std::nullopt;
        }

        std::string type_str;
        uint32_t version{0};
        if (!extract_required_nonempty_string(j, "type", type_str) || type_str != kEnvelopeType ||
            !extract_required_u32(j, "version", version) || version != kSchemaVersion) {
            return std::nullopt;
        }

        FileAttachmentKeyEnvelope env;
        std::string raw_key_hex;
        if (!extract_required_nonempty_string(j, "file_id", env.file_id) ||
            !extract_required_nonempty_string(j, "file_key_hex", raw_key_hex) ||
            !extract_required_nonempty_string(j, "file_name", env.file_name) ||
            !extract_optional_string(j, "mime_type", env.mime_type) ||
            !extract_required_nonempty_string(j, "ciphertext_sha256", env.ciphertext_sha256) ||
            !extract_required_nonempty_string(j, "plaintext_sha256", env.plaintext_sha256) ||
            !extract_required_nonempty_string(j, "cipher_suite", env.cipher_suite) ||
            !extract_required_u64(j, "plaintext_size_bytes", env.plaintext_size_bytes) ||
            !extract_required_u64(j, "encrypted_size_bytes", env.encrypted_size_bytes) ||
            !extract_required_u32(j, "chunk_size_bytes", env.chunk_size_bytes) ||
            !extract_required_u32(j, "chunk_count", env.chunk_count)) {
            return std::nullopt;
        }

        constexpr std::size_t kSha256HexLen = 64U;
        if (!is_valid_hex_string(raw_key_hex, kSha256HexLen) ||
            !is_valid_hex_string(env.ciphertext_sha256, kSha256HexLen) ||
            !is_valid_hex_string(env.plaintext_sha256, kSha256HexLen)) {
            return std::nullopt;
        }

        if (env.chunk_count == 0U || env.chunk_size_bytes <= kFileChunkAeadOverheadBytes ||
            env.chunk_size_bytes > kMaxFileWireChunkSize || env.encrypted_size_bytes == 0ULL ||
            env.encrypted_size_bytes > kMaxEncryptedFileSizeBytes ||
            env.plaintext_size_bytes > env.encrypted_size_bytes) {
            return std::nullopt;
        }

        env.file_key_hex = securecloud::common::configuration::SecretString(std::move(raw_key_hex));
        return env;
    } catch (...) {
        return std::nullopt;
    }
}

bool FileAttachmentKeyEnvelope::is_file_attachment_envelope(std::string_view payload) noexcept {
    const auto j = nlohmann::json::parse(payload, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        return false;
    }
    const auto it = j.find("type");
    return it != j.end() && it->is_string() && it->get<std::string>() == kEnvelopeType;
}

} // namespace securecloud::client::domain
