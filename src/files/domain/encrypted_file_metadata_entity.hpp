#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::files {

/// Strongly typed C++20 domain entity for client-side encrypted metadata fields.
/// Enforces the Zero-Plaintext Invariant (ADR-005, ADR-008): plaintext filenames,
/// plaintext MIME types, and file decryption keys MUST NEVER be stored.
/// Maps 1:1 to the `encrypted_file_metadata` PostgreSQL table.
struct EncryptedFileMetadataEntity {
    std::string file_id;
    std::vector<uint8_t> encrypted_filename;
    std::optional<std::vector<uint8_t>> encrypted_mime_type{std::nullopt};
    std::vector<uint8_t> metadata_nonce;
    std::vector<uint8_t> metadata_tag;
    std::string client_encryption_metadata_json{"{}"};
    std::chrono::system_clock::time_point updated_at;

    bool operator==(const EncryptedFileMetadataEntity& other) const = default;
};

} // namespace securecloud::files
