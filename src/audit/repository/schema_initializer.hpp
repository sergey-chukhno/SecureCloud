#pragma once

#include "audit_config.hpp"

#include <string>

namespace securecloud::audit::repository {

    /// Result taxonomy for database schema migration/initialization operations.
    enum class SchemaInitResult {
        Success,
        DatabaseConnectionFailed,
        MigrationExecutionFailed,
        DatabaseVerificationFailed
    };

    /// Service responsible for applying idempotent DDL schema migrations to ClickHouse 24.8.
    class SchemaInitializer {
    public:
        explicit SchemaInitializer(const ClickHouseConfig& config);
        ~SchemaInitializer() = default;

        /// Executes database and table initialization idempotently.
        [[nodiscard]] SchemaInitResult initialize_schema() const;

        /// Verifies that the required table and database exist and match expected properties.
        [[nodiscard]] bool verify_schema_integrity() const;

    private:
        ClickHouseConfig config_;

        [[nodiscard]] std::string build_clickhouse_url(const std::string& query) const;
        [[nodiscard]] bool execute_http_query(const std::string& query, std::string* out_response = nullptr) const;
    };

} // namespace securecloud::audit::repository