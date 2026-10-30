#pragma once

#include "audit_config.hpp"
#include "repository/audit_repository_exceptions.hpp"
#include "repository/clickhouse_query_builder.hpp"

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace securecloud::audit::repository {

    /// Low-level ClickHouse HTTP client with connection pooling and keep-alive support.
    class ClickHouseClient {
    public:
        explicit ClickHouseClient(const ClickHouseConfig& config);
        virtual ~ClickHouseClient();

        // Prevent copying to maintain connection state safety
        ClickHouseClient(const ClickHouseClient&) = delete;
        ClickHouseClient& operator=(const ClickHouseClient&) = delete;

        /// Executes a read/command SQL query (e.g. SELECT, ALTER).
        [[nodiscard]] virtual bool execute_query(const std::string& query, std::string* out_response = nullptr,
                                                 std::chrono::milliseconds timeout = std::chrono::milliseconds(3000));

        /// Executes a read-only parameterized SQL query (readonly=1, param_<key>=val) with result size capping.
        [[nodiscard]] virtual bool execute_parameterized_query(
            const ParameterizedClickHouseQuery& query,
            std::string* out_response = nullptr,
            std::chrono::milliseconds timeout = std::chrono::milliseconds(10000),
            size_t max_bytes = 16777216);

        /// Executes an insert query with raw data payload in HTTP body.
        [[nodiscard]] virtual bool execute_insert(const std::string& query, const std::string& body_data,
                                                  std::chrono::milliseconds timeout = std::chrono::milliseconds(3000));

        /// Rapid healthcheck probe (executes `SELECT 1` with sub-second deadline).
        [[nodiscard]] virtual bool ping(std::chrono::milliseconds timeout = std::chrono::milliseconds(800));

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace securecloud::audit::repository