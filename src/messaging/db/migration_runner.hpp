#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::messaging::db {

/// Exception base class for ScyllaDB migration failures.
class MigrationException : public std::runtime_error {
  public:
    explicit MigrationException(const std::string& message) : std::runtime_error(message) {}
};

/// Thrown when an already applied migration's checksum does not match current script content.
class MigrationChecksumMismatchException : public MigrationException {
  public:
    MigrationChecksumMismatchException(int version, std::string_view expected, std::string_view actual)
        : MigrationException("Checksum mismatch for migration version " + std::to_string(version) + ": expected " +
                             std::string(expected) + ", found " + std::string(actual)) {}
};

/// Thrown when executing a CQL migration script or statement fails.
class MigrationExecutionException : public MigrationException {
  public:
    MigrationExecutionException(int version, std::string_view script_name, std::string_view error)
        : MigrationException("Failed to apply migration V" + std::to_string(version) + " (" + std::string(script_name) +
                             "): " + std::string(error)) {}
};

/// Represents an individual migration script.
struct MigrationScript {
    int version{0};
    std::string script_name;
    std::string cql_content;
    std::string checksum;
};

/// Represents an applied migration record from the schema_migrations table.
struct AppliedMigrationRecord {
    int version{0};
    std::string script_name;
    std::string checksum;
    std::string applied_at;
};

/// Result summary of migration execution.
struct MigrationResult {
    int migrations_applied{0};
    int current_version{0};
    std::vector<std::string> applied_scripts;
};

/// Abstract CQL execution interface used by the migration runner.
class ICqlExecutor {
  public:
    virtual ~ICqlExecutor() = default;

    /// Executes a single CQL statement.
    virtual void execute_cql(std::string_view cql) = 0;

    /// Queries currently applied migrations from the schema tracking table.
    virtual std::vector<AppliedMigrationRecord> get_applied_migrations() = 0;

    /// Records an applied migration in the schema tracking table.
    virtual void record_migration(int version, std::string_view script_name, std::string_view checksum) = 0;
};

/// Idempotent schema migration runner for ScyllaDB.
class ScyllaMigrationRunner {
  public:
    explicit ScyllaMigrationRunner(ICqlExecutor& executor);

    /// Normalizes script content (CRLF -> LF, trims leading/trailing whitespace).
    [[nodiscard]] static std::string normalize_cql(std::string_view cql_content);

    /// Computes hex-encoded SHA-256 digest of normalized CQL content.
    [[nodiscard]] static std::string calculate_checksum(std::string_view cql_content);

    /// Parses a multi-statement CQL script into individual executable statements,
    /// stripping line comments (-- and //) and block comments (/* ... */) while
    /// preserving single-quoted string literals.
    [[nodiscard]] static std::vector<std::string> parse_cql_statements(std::string_view cql_content);

    /// Returns the standard built-in migration suite (V001, V002, V003).
    [[nodiscard]] static std::vector<MigrationScript> get_standard_migrations();

    /// Runs all standard migrations.
    MigrationResult run_migrations();

    /// Runs a custom set of migrations.
    MigrationResult run_migrations(const std::vector<MigrationScript>& scripts);

  private:
    ICqlExecutor& executor_;
};

} // namespace securecloud::messaging::db
