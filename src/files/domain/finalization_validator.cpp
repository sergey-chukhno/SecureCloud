#include "files/domain/finalization_validator.hpp"

#include <algorithm>
#include <numeric>

namespace securecloud::files {

namespace {

constexpr const char* transfer_status_to_string(TransferStatus status) noexcept {
    switch (status) {
    case TransferStatus::Created:
        return "Created";
    case TransferStatus::Transferring:
        return "Transferring";
    case TransferStatus::Finalizing:
        return "Finalizing";
    case TransferStatus::Completed:
        return "Completed";
    case TransferStatus::Failed:
        return "Failed";
    case TransferStatus::Expired:
        return "Expired";
    case TransferStatus::Cancelled:
        return "Cancelled";
    }
    return "Unknown";
}

constexpr const char* file_status_to_string(FileStatus status) noexcept {
    switch (status) {
    case FileStatus::Created:
        return "Created";
    case FileStatus::Uploading:
        return "Uploading";
    case FileStatus::Finalizing:
        return "Finalizing";
    case FileStatus::Available:
        return "Available";
    case FileStatus::Expired:
        return "Expired";
    case FileStatus::Deleted:
        return "Deleted";
    case FileStatus::Failed:
        return "Failed";
    }
    return "Unknown";
}

} // namespace

FinalizationValidationResult validate_finalization_preconditions(const FinalizationValidationInput& input) {
    // 1. Verify transfer existence
    if (input.transfer.transfer_id.empty()) {
        return FinalizationValidationResult::failure("Transfer ID must not be empty");
    }

    // 2. Verify transfer status allows finalization
    if (input.transfer.status == TransferStatus::Cancelled) {
        return FinalizationValidationResult::failure("Cannot finalize a cancelled transfer session");
    }
    if (input.transfer.status == TransferStatus::Expired) {
        return FinalizationValidationResult::failure("Cannot finalize an expired transfer session");
    }
    if (input.transfer.status == TransferStatus::Failed) {
        return FinalizationValidationResult::failure("Cannot finalize a failed transfer session");
    }
    if (input.transfer.status != TransferStatus::Transferring && input.transfer.status != TransferStatus::Finalizing &&
        !(input.transfer.status == TransferStatus::Created && input.transfer.total_chunks == 0)) {
        return FinalizationValidationResult::failure("Transfer session is in invalid state for finalization: " +
                                                     std::string(transfer_status_to_string(input.transfer.status)));
    }

    // 3. Verify file status allows finalization
    if (input.file.status == FileStatus::Deleted) {
        return FinalizationValidationResult::failure("Cannot finalize a deleted file");
    }
    if (input.file.status == FileStatus::Expired) {
        return FinalizationValidationResult::failure("Cannot finalize an expired file");
    }
    if (input.file.status == FileStatus::Failed) {
        return FinalizationValidationResult::failure("Cannot finalize a failed file");
    }
    if (input.file.status != FileStatus::Uploading && input.file.status != FileStatus::Finalizing &&
        !(input.file.status == FileStatus::Created && input.transfer.total_chunks == 0)) {
        return FinalizationValidationResult::failure("File is in invalid state for finalization: " +
                                                     std::string(file_status_to_string(input.file.status)));
    }

    // 4. Verify chunk counts match transfer contract
    if (input.transfer.total_chunks < 0 || input.chunks.size() != static_cast<size_t>(input.transfer.total_chunks)) {
        return FinalizationValidationResult::failure(
            "Chunk count mismatch: expected " + std::to_string(input.transfer.total_chunks) + " chunks, but found " +
            std::to_string(input.chunks.size()) + " staged chunks");
    }

    if (input.transfer.accepted_chunks != input.transfer.total_chunks) {
        return FinalizationValidationResult::failure("Not all chunks have been accepted: accepted " +
                                                     std::to_string(input.transfer.accepted_chunks) + " of " +
                                                     std::to_string(input.transfer.total_chunks));
    }

    // 5. Verify chunk indices are gapless and sequential
    auto sorted_chunks = input.chunks;
    std::sort(sorted_chunks.begin(), sorted_chunks.end(),
              [](const FileChunkEntity& a, const FileChunkEntity& b) { return a.chunk_index < b.chunk_index; });

    uint64_t accumulated_bytes = 0;
    for (size_t i = 0; i < sorted_chunks.size(); ++i) {
        const auto& chunk = sorted_chunks[i];
        if (chunk.chunk_index < 0 || static_cast<size_t>(chunk.chunk_index) != i) {
            return FinalizationValidationResult::failure("Missing chunk at index " + std::to_string(i) +
                                                         "; found chunk index " + std::to_string(chunk.chunk_index));
        }

        if (chunk.minio_chunk_key.empty()) {
            return FinalizationValidationResult::failure("Chunk " + std::to_string(i) +
                                                         " has missing or empty storage key");
        }

        if (!is_valid_sha256_hex(chunk.chunk_hash_sha256)) {
            return FinalizationValidationResult::failure(
                "Chunk " + std::to_string(i) + " has invalid SHA-256 digest format: " + chunk.chunk_hash_sha256);
        }

        if (chunk.chunk_size == 0 && input.transfer.total_bytes > 0) {
            return FinalizationValidationResult::failure("Chunk " + std::to_string(i) +
                                                         " has invalid zero chunk_size for non-empty transfer");
        }

        if (chunk.chunk_size < 0) {
            return FinalizationValidationResult::failure("Chunk " + std::to_string(i) + " has negative chunk_size");
        }

        accumulated_bytes += static_cast<uint64_t>(chunk.chunk_size);
    }

    // 6. Verify total byte summation
    if (input.transfer.total_bytes < 0 || accumulated_bytes != static_cast<uint64_t>(input.transfer.total_bytes)) {
        return FinalizationValidationResult::failure(
            "Cumulative chunk byte size mismatch: chunks sum to " + std::to_string(accumulated_bytes) +
            " bytes, but transfer expects " + std::to_string(input.transfer.total_bytes) + " bytes");
    }

    if (input.file.encrypted_size != input.transfer.total_bytes) {
        return FinalizationValidationResult::failure(
            "Transfer total bytes (" + std::to_string(input.transfer.total_bytes) +
            ") does not match file encrypted size (" + std::to_string(input.file.encrypted_size) + ")");
    }

    // 7. Verify expected whole-object hash format if provided
    if (!input.expected_ciphertext_sha256.empty() && !is_valid_sha256_hex(input.expected_ciphertext_sha256)) {
        return FinalizationValidationResult::failure(
            "Provided expected_ciphertext_sha256 is not a valid 64-character hex string: " +
            input.expected_ciphertext_sha256);
    }

    return FinalizationValidationResult::success();
}

} // namespace securecloud::files
