#pragma once

#include "files/domain/file_entity.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::files {

/// Authoritative file metadata constraints (Files Design 6.13, 6.14, 6.18)
inline constexpr uint64_t k_max_file_size_bytes = 5ULL * 1024ULL * 1024ULL * 1024ULL; // 5 GiB maximum
inline constexpr uint32_t k_standard_chunk_size = 4U * 1024U * 1024U;                 // 4 MiB logical chunk
inline constexpr size_t k_xchacha20_nonce_bytes = 24;
inline constexpr size_t k_poly1305_tag_bytes = 16;
inline constexpr std::string_view k_approved_encryption_algorithm = "XChaCha20-Poly1305";

/// Domain DTO carrying validated attributes for creating a new logical file.
struct CreateFileRequestDto {
    std::string file_id{};
    std::string owner_user_id{};
    std::string owner_device_id{};
    std::optional<std::string> conversation_id{std::nullopt};
    uint64_t encrypted_size_bytes{0};
    uint32_t expected_chunk_count{0};
    std::string encryption_algorithm{std::string(k_approved_encryption_algorithm)};
    std::vector<uint8_t> encrypted_filename{};
    std::optional<std::vector<uint8_t>> encrypted_mime_type{std::nullopt};
    std::vector<uint8_t> metadata_nonce{};
    std::vector<uint8_t> metadata_tag{};
    std::string client_encryption_metadata_json{"{}"};
    std::optional<std::chrono::system_clock::time_point> retention_until{std::nullopt};
};

/// Domain DTO carrying validated attributes for creating a new immutable file version.
struct CreateFileVersionRequestDto {
    std::string file_id{};
    int32_t version_number{1};
    uint64_t encrypted_size_bytes{0};
    std::string minio_object_key{};
    std::string checksum_sha256{};
};

/// Result of metadata validation checking.
struct ValidationResult {
    bool is_valid{true};
    std::string error_message;

    [[nodiscard]] explicit operator bool() const noexcept { return is_valid; }

    static ValidationResult success() noexcept { return {true, ""}; }
    static ValidationResult failure(std::string message) { return {false, std::move(message)}; }
};

/// Validates UUID RFC 4122 format (e.g., 8-4-4-4-12 hex string).
[[nodiscard]] bool is_valid_uuid(std::string_view str) noexcept;

/// Generates a RFC 9562 compliant time-ordered UUIDv7.
[[nodiscard]] std::string generate_uuid_v7();

/// Validates SHA-256 hex string (exactly 64 hexadecimal characters).
[[nodiscard]] bool is_valid_sha256_hex(std::string_view hex_str) noexcept;

/// Computes expected chunk count for a given total file size and chunk size.
[[nodiscard]] uint32_t calculate_expected_chunk_count(uint64_t file_size_bytes,
                                                      uint32_t chunk_size = k_standard_chunk_size) noexcept;

/// Unpacks Protobuf client_crypto_metadata bytes into the corresponding fields in CreateFileRequestDto.
ValidationResult unpack_client_crypto_metadata(const std::string& raw_crypto_metadata_bytes,
                                               CreateFileRequestDto& out_dto);

/// Validates all parameters of CreateFileRequestDto against authoritative security rules.
ValidationResult validate_create_file_request(const CreateFileRequestDto& dto,
                                              std::chrono::system_clock::time_point now);

/// Validates all parameters of CreateFileVersionRequestDto.
ValidationResult validate_create_version_request(const CreateFileVersionRequestDto& dto);

} // namespace securecloud::files
