#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/db/pqxx_compat.hpp"
#include "files/db/pqxx_mappers.hpp"
#include "files/domain/file_chunk_entity.hpp"
#include "files/repository/file_repository.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::files {

/// Result of recording an uploaded chunk into persistent storage
enum class ChunkRecordResult {
    NewlyInserted,          ///< Chunk was newly recorded and accepted
    AlreadyExistsIdentical, ///< Chunk was already recorded with identical hash (idempotent replay)
    ConflictHashMismatch    ///< Chunk index already recorded but hash differs (integrity violation)
};

/// Exception thrown when a duplicate chunk index is submitted with a mismatched hash.
class ChunkIntegrityException : public RepositoryException {
    using RepositoryException::RepositoryException;
};

/// Authoritative repository managing idempotent chunk records for file transfers.
/// Enforces idempotent replays and SHA-256 integrity verification (Files Design 6.3, 6.18, 6.19).
class FileChunkRepository {
  public:
    explicit FileChunkRepository(std::shared_ptr<db::FilesDbConnectionPool> pool = nullptr);

    /// Records a chunk within the provided transaction `tx`.
    /// Employs ON CONFLICT (transfer_id, chunk_index) DO NOTHING for idempotency.
    /// If conflict occurs, verifies hash integrity:
    /// - If hash matches: returns ChunkRecordResult::AlreadyExistsIdentical (safe idempotent retry).
    /// - If hash differs: throws ChunkIntegrityException (tampering / corruption detected).
    ChunkRecordResult record_chunk(const FileChunkEntity& chunk, pqxx::work& tx);

    /// Retrieves an ordered list of accepted chunk indices for a transfer within a transaction.
    [[nodiscard]] std::vector<int32_t> get_accepted_chunk_indices(const std::string& transfer_id, pqxx::work& tx);

    /// Retrieves an ordered list of accepted chunk indices for a transfer (creates autonomous work session).
    [[nodiscard]] std::vector<int32_t> get_accepted_chunk_indices(const std::string& transfer_id);

    /// Counts accepted chunks for a transfer within a transaction.
    [[nodiscard]] int32_t count_accepted_chunks(const std::string& transfer_id, pqxx::work& tx);

    /// Counts accepted chunks for a transfer (creates autonomous work session).
    [[nodiscard]] int32_t count_accepted_chunks(const std::string& transfer_id);

    /// Checks if a specific chunk index has been accepted within a transaction.
    [[nodiscard]] bool is_chunk_present(const std::string& transfer_id, int32_t chunk_index, pqxx::work& tx);

    /// Checks if a specific chunk index has been accepted (creates autonomous work session).
    [[nodiscard]] bool is_chunk_present(const std::string& transfer_id, int32_t chunk_index);

    /// Lists all chunks for a transfer ordered by chunk_index ASC within a transaction.
    [[nodiscard]] std::vector<FileChunkEntity> list_chunks_for_transfer(const std::string& transfer_id, pqxx::work& tx);

    /// Lists all chunks for a transfer ordered by chunk_index ASC (creates autonomous work session).
    [[nodiscard]] std::vector<FileChunkEntity> list_chunks_for_transfer(const std::string& transfer_id);

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
};

} // namespace securecloud::files
