#pragma once

#include "auth/db/postgres_connection_pool.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::auth::db {

/// 64-bit PostgreSQL advisory lock ID for Auth migrations: 'SCAUTH01'
inline constexpr int64_t k_auth_migration_advisory_lock = 0x5343415554483031LL;

/// Exception base class for migration failures.
class MigrationException : public std::runtime_error {
  public:
    explicit MigrationException(const std::string& message) : std::runtime_error(message) {}
};

/// Exception thrown when an already applied migration's checksum does not match current script.
class MigrationChecksumMismatchException : public MigrationException {
  public:
    MigrationChecksumMismatchException(int version, std::string_view expected, std::string_view actual)
        : MigrationException("Checksum mismatch for migration version " + std::to_string(version) + ": expected " +
                             std::string(expected) + ", found " + std::string(actual)) {}
};

/// Exception thrown when executing a migration SQL script fails.
class MigrationExecutionException : public MigrationException {
  public:
    MigrationExecutionException(int version, std::string_view script_name, std::string_view sql_error)
        : MigrationException("Failed to apply migration V" + std::to_string(version) + " (" + std::string(script_name) +
                             "): " + std::string(sql_error)) {}
};

/// Represents an individual migration script.
struct MigrationScript {
    int version{0};
    std::string description;
    std::string sql_content;
    std::string checksum;
};

/// Summary of migration execution.
struct MigrationResult {
    int migrations_applied{0};
    int current_version{0};
    std::vector<std::string> applied_scripts;
};

/// Transactional, advisory-locked schema migration engine for Auth Service.
class MigrationRunner {
  public:
    explicit MigrationRunner(PostgresConnectionPool& pool);

    /// Normalizes script content (CRLF -> LF, trims whitespace) and computes its hex SHA-256 digest.
    [[nodiscard]] static std::string calculate_checksum(std::string_view sql_content);

    /// Normalizes SQL content by replacing \r\n with \n.
    [[nodiscard]] static std::string normalize_sql(std::string_view sql_content);

    /// Returns the built-in canonical list of migrations (V001, V002, V003).
    [[nodiscard]] static std::vector<MigrationScript> get_standard_migrations();

    /// Executes all pending migrations under PostgreSQL advisory lock.
    MigrationResult run_migrations();

    /// Executes a custom list of migrations under PostgreSQL advisory lock (useful for testing).
    MigrationResult run_migrations(const std::vector<MigrationScript>& scripts);

    /// Returns the highest applied schema version, or 0 if no migrations have been applied.
    [[nodiscard]] int get_current_schema_version();

  private:
    PostgresConnectionPool& pool_;
};

} // namespace securecloud::auth::db
