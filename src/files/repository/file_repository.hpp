#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/db/pqxx_compat.hpp"
#include "files/db/pqxx_mappers.hpp"
#include "files/domain/encrypted_file_metadata_entity.hpp"
#include "files/domain/file_entity.hpp"
#include "files/domain/lifecycle_state_machine.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace securecloud::files {

// --- Repository Exception Hierarchy ---

class RepositoryException : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

class InvalidStateTransitionException : public RepositoryException {
    using RepositoryException::RepositoryException;
};

class UniqueConstraintViolationException : public RepositoryException {
    using RepositoryException::RepositoryException;
};

class EntityNotFoundException : public RepositoryException {
    using RepositoryException::RepositoryException;
};

/// Authoritative repository managing persistent storage and state transitions for files
/// and their client-encrypted metadata (ADR-005, Files Design 6.3, 6.18, 6.19).
class FileRepository {
  public:
    explicit FileRepository(std::shared_ptr<db::FilesDbConnectionPool> pool = nullptr);

    /// Atomically creates a master file record and its corresponding client-encrypted metadata.
    /// Both records are inserted within the provided transaction `tx`.
    void create_file(const FileEntity& file, const EncryptedFileMetadataEntity& metadata, pqxx::work& tx);

    /// Retrieves a file record by its unique identifier within a transaction.
    [[nodiscard]] std::optional<FileEntity> find_by_id(const std::string& file_id, pqxx::work& tx);

    /// Retrieves a file record by its unique identifier (creates autonomous work session).
    [[nodiscard]] std::optional<FileEntity> find_by_id(const std::string& file_id);

    /// Retrieves client-encrypted metadata for a file within a transaction.
    [[nodiscard]] std::optional<EncryptedFileMetadataEntity> find_encrypted_metadata(const std::string& file_id,
                                                                                     pqxx::work& tx);

    /// Retrieves client-encrypted metadata for a file (creates autonomous work session).
    [[nodiscard]] std::optional<EncryptedFileMetadataEntity> find_encrypted_metadata(const std::string& file_id);

    /// Enforces optimistic concurrency and valid lifecycle state transitions.
    /// Returns true if updated; returns false if row was not in `expected_current` status.
    /// Throws InvalidStateTransitionException if transition is illegal.
    bool update_status(const std::string& file_id, FileStatus expected_current, FileStatus new_status, pqxx::work& tx);

    /// Logically marks a file as DELETED within the given transaction.
    bool delete_file_logical(const std::string& file_id, pqxx::work& tx);

    /// Queries files whose retention period has expired up to `limit` entries.
    [[nodiscard]] std::vector<FileEntity> find_expired_files(std::chrono::system_clock::time_point now, size_t limit,
                                                             pqxx::work& tx);

    /// Queries files whose retention period has expired up to `limit` entries (creates autonomous work session).
    [[nodiscard]] std::vector<FileEntity> find_expired_files(std::chrono::system_clock::time_point now, size_t limit);

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
};

} // namespace securecloud::files
