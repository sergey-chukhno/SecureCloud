#pragma once

#include "files/db/files_connection_pool.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::files::db {

/// Represents an applied database migration entry
struct MigrationRecord {
    std::string version;
    std::string description;
    std::string applied_at;
};

/// Result of migration execution
struct MigrationResult {
    bool success{false};
    std::vector<std::string> applied_versions;
    std::string error_message;
};

/// Schema migration orchestrator for SecureCloud Files service.
/// Ensures authoritative relational schema baseline (V001) is applied idempotently.
class MigrationRunner {
  public:
    explicit MigrationRunner(std::shared_ptr<FilesDbConnectionPool> pool);

    /// Returns the authoritative embedded V001 schema DDL.
    static std::string_view get_v001_schema_sql() noexcept;

    /// Parses an SQL script and splits it into discrete executable statements.
    /// Filters out pure comments and empty statements.
    static std::vector<std::string> split_statements(std::string_view sql);

    /// Validates DDL structural integrity: table existence, foreign keys, and indexes.
    static bool validate_schema_ddl_syntax(std::string_view sql, std::vector<std::string>& out_missing_elements);

    /// Runs all pending migrations against the database.
    MigrationResult run_migrations();

    /// Applies a specific SQL migration by version.
    bool apply_migration(std::string_view version, std::string_view description, std::string_view sql);

    /// Returns list of versions applied so far in memory or from database.
    [[nodiscard]] std::vector<std::string> get_applied_versions() const;

  private:
    std::shared_ptr<FilesDbConnectionPool> pool_;
    std::vector<std::string> applied_versions_;
};

} // namespace securecloud::files::db
