#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/db/pqxx_compat.hpp"
#include "files/db/pqxx_mappers.hpp"
#include "files/domain/file_version_entity.hpp"
#include "files/repository/file_repository.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::files {

/// Authoritative repository managing persistent immutable version snapshots for files.
class FileVersionRepository {
  public:
    explicit FileVersionRepository(std::shared_ptr<db::FilesDbConnectionPool> pool = nullptr);

    /// Creates an immutable version record within transaction `tx`.
    /// Enforces UNIQUE(file_id, version_number).
    /// If version.is_active is true, previous active versions for this file are deactivated.
    /// Throws UniqueConstraintViolationException if (file_id, version_number) already exists.
    void create_version(const FileVersionEntity& version, pqxx::work& tx);

    /// Finds the currently active version for a given file within a transaction.
    [[nodiscard]] std::optional<FileVersionEntity> find_active_version(const std::string& file_id, pqxx::work& tx);

    /// Finds the currently active version for a given file (creates autonomous work session).
    [[nodiscard]] std::optional<FileVersionEntity> find_active_version(const std::string& file_id);

    /// Lists all versions associated with a given file within a transaction, ordered by version_number ascending.
    [[nodiscard]] std::vector<FileVersionEntity> list_versions(const std::string& file_id, pqxx::work& tx);

    /// Lists all versions associated with a given file, ordered by version_number ascending.
    [[nodiscard]] std::vector<FileVersionEntity> list_versions(const std::string& file_id);

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
};

} // namespace securecloud::files
