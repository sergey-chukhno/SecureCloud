#pragma once

#include "audit_config.hpp"

#include <string>
#include <vector>

namespace securecloud::audit::repository {

/// Detailed schema verification report containing runtime table inspection state.
struct SchemaVerificationReport {
    bool is_valid{false};
    std::string engine;
    std::string partition_key;
    std::string sorting_key;
    std::string create_table_query;
    std::vector<std::string> violations;
};

/// Result taxonomy for database schema migration/initialization operations.
enum class SchemaInitResult { Success, DatabaseConnectionFailed, MigrationExecutionFailed, DatabaseVerificationFailed };

/// Service responsible for applying idempotent DDL schema migrations to ClickHouse 24.8.
class SchemaInitializer {
  public:
    explicit SchemaInitializer(const ClickHouseConfig& config);
    ~SchemaInitializer() = default;

    /// Executes database and table initialization idempotently.
    [[nodiscard]] SchemaInitResult initialize_schema() const;

    /// Programmatically inspects system.tables to verify engine, partitioning, sorting, and 36-month TTL on
    /// occurred_at.
    [[nodiscard]] SchemaVerificationReport verify_effective_schema() const;

    /// Verifies that the required table and database exist and match expected properties.
    [[nodiscard]] bool verify_schema_integrity() const;

  private:
    ClickHouseConfig config_;

    [[nodiscard]] std::string build_clickhouse_url(const std::string& query) const;
    [[nodiscard]] bool execute_http_query(const std::string& query, std::string* out_response = nullptr) const;
};

} // namespace securecloud::audit::repository