#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/db/pqxx_compat.hpp"
#include "files/db/pqxx_mappers.hpp"
#include "files/domain/file_transfer_entity.hpp"
#include "files/repository/file_repository.hpp"

#include <memory>
#include <optional>
#include <string>

namespace securecloud::files {

/// Authoritative repository managing resumable upload/download transfer sessions.
/// Maps 1:1 to the `file_transfers` PostgreSQL table (Files Design 6.3, 6.18, 6.19).
class FileTransferRepository {
  public:
    explicit FileTransferRepository(std::shared_ptr<db::FilesDbConnectionPool> pool = nullptr);

    /// Inserts a new transfer session record within the provided transaction `tx`.
    void create_transfer(const FileTransferEntity& transfer, pqxx::work& tx);

    /// Retrieves a transfer session by transfer_id within a transaction.
    [[nodiscard]] std::optional<FileTransferEntity> find_by_id(const std::string& transfer_id, pqxx::work& tx);

    /// Retrieves a transfer session by transfer_id (creates autonomous work session).
    [[nodiscard]] std::optional<FileTransferEntity> find_by_id(const std::string& transfer_id);

    /// Updates the transfer status and refreshed updated_at timestamp.
    /// Returns true if updated; returns false if transfer_id does not exist.
    bool update_status(const std::string& transfer_id, TransferStatus status, pqxx::work& tx);

    /// Updates the transfer status (creates autonomous work session).
    bool update_status(const std::string& transfer_id, TransferStatus status);

    /// Increments accepted_chunks by 1 and transferred_bytes by bytes_added atomically.
    /// Returns true if updated; returns false if transfer_id does not exist.
    bool increment_chunk_progress(const std::string& transfer_id, int64_t bytes_added, pqxx::work& tx);

    /// Increments accepted_chunks and transferred_bytes (creates autonomous work session).
    bool increment_chunk_progress(const std::string& transfer_id, int64_t bytes_added);

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
};

} // namespace securecloud::files
