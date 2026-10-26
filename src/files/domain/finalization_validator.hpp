#pragma once

#include "files/domain/file_chunk_entity.hpp"
#include "files/domain/file_entity.hpp"
#include "files/domain/file_transfer_entity.hpp"
#include "files/domain/metadata_validator.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace securecloud::files {

/// Input bundle aggregating all domain entities needed to validate finalization preconditions.
struct FinalizationValidationInput {
    FileTransferEntity transfer;
    FileEntity file;
    std::vector<FileChunkEntity> chunks;
    std::string expected_ciphertext_sha256;
};

/// Result of finalization precondition validation.
struct FinalizationValidationResult {
    bool is_valid{true};
    std::string error_message;

    [[nodiscard]] explicit operator bool() const noexcept { return is_valid; }

    static FinalizationValidationResult success() noexcept {
        return {true, ""};
    }

    static FinalizationValidationResult failure(std::string message) {
        return {false, std::move(message)};
    }
};

/// Authoritative precondition validator for whole-object finalization.
/// Verifies:
/// 1. Transfer existence and status (Transferring/Finalizing).
/// 2. Chunk completeness (all expected chunks present).
/// 3. Gapless contiguous indices (0..N-1).
/// 4. Chunk size summation matching parent file encrypted_size.
/// 5. Valid storage keys and hashes for each chunk.
/// 6. Expected SHA-256 digest format validity.
[[nodiscard]] FinalizationValidationResult validate_finalization_preconditions(
    const FinalizationValidationInput& input);

} // namespace securecloud::files
