#pragma once

#include "messaging/db/scylla_params.hpp"
#include "messaging/db/scylla_statement.hpp"
#include "messaging/db/scylla_types.hpp"

#include <chrono>
#include <memory>
#include <string_view>
#include <vector>

namespace securecloud::messaging::db {

/// Abstract ScyllaDB client session interface.
class IScyllaSession {
  public:
    virtual ~IScyllaSession() = default;

    /// Executes an ad-hoc CQL query.
    virtual ScyllaQueryResult execute(std::string_view cql, ConsistencyLevel cl = ConsistencyLevel::LocalQuorum) = 0;

    /// Registers/prepares a CQL statement and returns its cache identifier.
    virtual PreparedStatementId prepare(std::string_view query_id, std::string_view cql) = 0;

    /// Executes a previously prepared statement with bound parameters.
    virtual ScyllaQueryResult execute_prepared(const PreparedStatementId& id, const ScyllaParams& params,
                                               ConsistencyLevel cl = ConsistencyLevel::LocalQuorum) = 0;

    /// Executes a batch of statements atomically or unlogged.
    virtual void execute_batch(const std::vector<BoundStatement>& batch, BatchType type = BatchType::Logged) = 0;

    /// Health check verification of connectivity.
    virtual bool ping() = 0;

    /// Closes the session and releases connection resources.
    virtual void close() = 0;

    /// Checks if the session has been closed.
    [[nodiscard]] virtual bool is_closed() const noexcept = 0;
};

/// Abstract ScyllaDB session connection pool interface.
class IScyllaSessionPool {
  public:
    virtual ~IScyllaSessionPool() = default;

    /// Acquires a session from the pool with timeout.
    virtual std::shared_ptr<IScyllaSession>
    acquire(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) = 0;

    /// Releases a session back to the pool.
    virtual void release(std::shared_ptr<IScyllaSession> session) = 0;

    /// Returns the total capacity of the pool.
    [[nodiscard]] virtual std::size_t size() const noexcept = 0;

    /// Returns the number of currently checked-out active sessions.
    [[nodiscard]] virtual std::size_t active_count() const noexcept = 0;

    /// Verifies pool health.
    virtual bool ping() = 0;

    /// Closes and drains all sessions in the pool.
    virtual void close() = 0;
};

} // namespace securecloud::messaging::db
