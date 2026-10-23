#include "files/domain/metadata_validator.hpp"

#include <array>
#include <cctype>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>
#include <sstream>

namespace securecloud::files {

namespace {

int hex_val(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

std::optional<std::vector<uint8_t>> decode_hex(std::string_view hex_str) {
    if (hex_str.size() % 2 != 0) {
        return std::nullopt;
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex_str.size() / 2);
    for (size_t i = 0; i < hex_str.size(); i += 2) {
        int hi = hex_val(hex_str[i]);
        int lo = hex_val(hex_str[i + 1]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return bytes;
}

} // namespace

bool is_valid_uuid(std::string_view str) noexcept {
    if (str.size() != 36) {
        return false;
    }
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (str[i] != '-') {
                return false;
            }
        } else {
            if (hex_val(str[i]) < 0) {
                return false;
            }
        }
    }
    return true;
}

std::string generate_uuid_v7() {
    auto now_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    std::array<uint8_t, 16> bytes{};
    bytes[0] = static_cast<uint8_t>((now_ms >> 40) & 0xFF);
    bytes[1] = static_cast<uint8_t>((now_ms >> 32) & 0xFF);
    bytes[2] = static_cast<uint8_t>((now_ms >> 24) & 0xFF);
    bytes[3] = static_cast<uint8_t>((now_ms >> 16) & 0xFF);
    bytes[4] = static_cast<uint8_t>((now_ms >> 8) & 0xFF);
    bytes[5] = static_cast<uint8_t>(now_ms & 0xFF);

    std::array<uint8_t, 10> rand_bytes{};
    if (RAND_bytes(rand_bytes.data(), static_cast<int>(rand_bytes.size())) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed to generate entropy for UUIDv7");
    }

    bytes[6] = static_cast<uint8_t>(0x70 | (rand_bytes[0] & 0x0F));
    bytes[7] = rand_bytes[1];
    bytes[8] = static_cast<uint8_t>(0x80 | (rand_bytes[2] & 0x3F));
    for (size_t i = 3; i < rand_bytes.size(); ++i) {
        bytes[6 + i] = rand_bytes[i];
    }

    char buf[37];
    std::snprintf(buf, sizeof(buf),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  bytes[0], bytes[1], bytes[2], bytes[3],
                  bytes[4], bytes[5], bytes[6], bytes[7],
                  bytes[8], bytes[9], bytes[10], bytes[11],
                  bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(buf, 36);
}

bool is_valid_sha256_hex(std::string_view hex_str) noexcept {
    if (hex_str.size() != 64) {
        return false;
    }
    for (char c : hex_str) {
        if (hex_val(c) < 0) {
            return false;
        }
    }
    return true;
}

uint32_t calculate_expected_chunk_count(uint64_t file_size_bytes, uint32_t chunk_size) noexcept {
    if (file_size_bytes == 0 || chunk_size == 0) {
        return 0;
    }
    return static_cast<uint32_t>((file_size_bytes + chunk_size - 1) / chunk_size);
}

ValidationResult unpack_client_crypto_metadata(const std::string& raw_crypto_metadata_bytes,
                                               CreateFileRequestDto& out_dto) {
    if (raw_crypto_metadata_bytes.empty()) {
        return ValidationResult::failure("client_crypto_metadata payload is empty");
    }

    // Try parsing as JSON first
    try {
        auto j = nlohmann::json::parse(raw_crypto_metadata_bytes);
        if (j.is_object()) {
            bool found_fields = false;

            if (j.contains("encrypted_filename_hex") && j["encrypted_filename_hex"].is_string()) {
                auto decoded = decode_hex(j["encrypted_filename_hex"].get<std::string>());
                if (!decoded) {
                    return ValidationResult::failure("Invalid hex in encrypted_filename_hex");
                }
                out_dto.encrypted_filename = *decoded;
                found_fields = true;
            } else if (j.contains("encrypted_filename") && j["encrypted_filename"].is_string()) {
                auto decoded = decode_hex(j["encrypted_filename"].get<std::string>());
                if (decoded) {
                    out_dto.encrypted_filename = *decoded;
                    found_fields = true;
                }
            }

            if (j.contains("encrypted_mime_type_hex") && j["encrypted_mime_type_hex"].is_string()) {
                auto decoded = decode_hex(j["encrypted_mime_type_hex"].get<std::string>());
                if (!decoded) {
                    return ValidationResult::failure("Invalid hex in encrypted_mime_type_hex");
                }
                out_dto.encrypted_mime_type = *decoded;
            }

            if (j.contains("metadata_nonce_hex") && j["metadata_nonce_hex"].is_string()) {
                auto decoded = decode_hex(j["metadata_nonce_hex"].get<std::string>());
                if (!decoded) {
                    return ValidationResult::failure("Invalid hex in metadata_nonce_hex");
                }
                out_dto.metadata_nonce = *decoded;
                found_fields = true;
            } else if (j.contains("nonce_hex") && j["nonce_hex"].is_string()) {
                auto decoded = decode_hex(j["nonce_hex"].get<std::string>());
                if (decoded) {
                    out_dto.metadata_nonce = *decoded;
                    found_fields = true;
                }
            }

            if (j.contains("metadata_tag_hex") && j["metadata_tag_hex"].is_string()) {
                auto decoded = decode_hex(j["metadata_tag_hex"].get<std::string>());
                if (!decoded) {
                    return ValidationResult::failure("Invalid hex in metadata_tag_hex");
                }
                out_dto.metadata_tag = *decoded;
                found_fields = true;
            } else if (j.contains("tag_hex") && j["tag_hex"].is_string()) {
                auto decoded = decode_hex(j["tag_hex"].get<std::string>());
                if (decoded) {
                    out_dto.metadata_tag = *decoded;
                    found_fields = true;
                }
            }

            if (found_fields) {
                out_dto.client_encryption_metadata_json = j.dump();
                return ValidationResult::success();
            }
        }
    } catch (...) {
        // Not a JSON document, proceed to packed binary fallback
    }

    // Binary packed format fallback:
    // [24 bytes nonce] + [16 bytes tag] + [>=1 bytes encrypted_filename]
    constexpr size_t min_packed_len = k_xchacha20_nonce_bytes + k_poly1305_tag_bytes + 1;
    if (raw_crypto_metadata_bytes.size() >= min_packed_len) {
        const auto* data_ptr = reinterpret_cast<const uint8_t*>(raw_crypto_metadata_bytes.data());
        out_dto.metadata_nonce.assign(data_ptr, data_ptr + k_xchacha20_nonce_bytes);
        out_dto.metadata_tag.assign(data_ptr + k_xchacha20_nonce_bytes,
                                    data_ptr + k_xchacha20_nonce_bytes + k_poly1305_tag_bytes);
        out_dto.encrypted_filename.assign(data_ptr + k_xchacha20_nonce_bytes + k_poly1305_tag_bytes,
                                          data_ptr + raw_crypto_metadata_bytes.size());
        out_dto.client_encryption_metadata_json = "{}";
        return ValidationResult::success();
    }

    return ValidationResult::failure(
        "Malformed client_crypto_metadata: payload is neither valid JSON nor valid packed binary format");
}

ValidationResult validate_create_file_request(const CreateFileRequestDto& dto,
                                              std::chrono::system_clock::time_point now) {
    if (!is_valid_uuid(dto.file_id)) {
        return ValidationResult::failure("file_id is not a valid UUIDv7 format: " + dto.file_id);
    }
    if (!is_valid_uuid(dto.owner_user_id)) {
        return ValidationResult::failure("owner_user_id is not a valid UUID format: " + dto.owner_user_id);
    }
    if (!is_valid_uuid(dto.owner_device_id)) {
        return ValidationResult::failure("owner_device_id is not a valid UUID format: " + dto.owner_device_id);
    }
    if (dto.conversation_id.has_value() && !is_valid_uuid(*dto.conversation_id)) {
        return ValidationResult::failure("conversation_id is not a valid UUID format: " + *dto.conversation_id);
    }
    if (dto.encrypted_size_bytes == 0) {
        return ValidationResult::failure("encrypted_size_bytes must be greater than zero");
    }
    if (dto.encrypted_size_bytes > k_max_file_size_bytes) {
        return ValidationResult::failure("encrypted_size_bytes exceeds maximum allowed limit (5 GiB)");
    }
    uint32_t expected_chunks = calculate_expected_chunk_count(dto.encrypted_size_bytes);
    if (dto.expected_chunk_count != expected_chunks) {
        return ValidationResult::failure("expected_chunk_count (" + std::to_string(dto.expected_chunk_count) +
                                         ") does not match calculated count (" + std::to_string(expected_chunks) + ")");
    }
    if (dto.encryption_algorithm != k_approved_encryption_algorithm) {
        return ValidationResult::failure("Unsupported encryption_algorithm: " + dto.encryption_algorithm +
                                         " (must be " + std::string(k_approved_encryption_algorithm) + ")");
    }
    if (dto.encrypted_filename.empty()) {
        return ValidationResult::failure("encrypted_filename must not be empty");
    }
    if (dto.metadata_nonce.size() != k_xchacha20_nonce_bytes) {
        return ValidationResult::failure("metadata_nonce must be exactly 24 bytes (XChaCha20 nonce), got " +
                                         std::to_string(dto.metadata_nonce.size()));
    }
    if (dto.metadata_tag.size() != k_poly1305_tag_bytes) {
        return ValidationResult::failure("metadata_tag must be exactly 16 bytes (Poly1305 tag), got " +
                                         std::to_string(dto.metadata_tag.size()));
    }
    if (dto.retention_until.has_value() && *dto.retention_until <= now) {
        return ValidationResult::failure("retention_until must be in the future");
    }

    return ValidationResult::success();
}

ValidationResult validate_create_version_request(const CreateFileVersionRequestDto& dto) {
    if (!is_valid_uuid(dto.file_id)) {
        return ValidationResult::failure("file_id is not a valid UUIDv7 format: " + dto.file_id);
    }
    if (dto.version_number <= 0) {
        return ValidationResult::failure("version_number must be greater than zero");
    }
    if (dto.encrypted_size_bytes == 0) {
        return ValidationResult::failure("encrypted_size_bytes must be greater than zero");
    }
    if (dto.encrypted_size_bytes > k_max_file_size_bytes) {
        return ValidationResult::failure("encrypted_size_bytes exceeds maximum allowed limit (5 GiB)");
    }
    if (dto.minio_object_key.empty()) {
        return ValidationResult::failure("minio_object_key must not be empty");
    }
    if (dto.minio_object_key.find("..") != std::string::npos || dto.minio_object_key.front() == '/') {
        return ValidationResult::failure("minio_object_key contains invalid path traversal or leading slash: " +
                                         dto.minio_object_key);
    }
    if (!is_valid_sha256_hex(dto.checksum_sha256)) {
        return ValidationResult::failure("checksum_sha256 must be a valid 64-hex SHA-256 digest: " +
                                         dto.checksum_sha256);
    }

    return ValidationResult::success();
}

} // namespace securecloud::files
