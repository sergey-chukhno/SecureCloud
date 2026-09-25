#pragma once

#include "auth/auth_config.hpp"
#include "auth/db/pooled_connection.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <pqxx/pqxx>
#include <queue>
#include <stdexcept>
#include <string>

namespace securecloud::auth::db {

/// Configuration parameters for the PostgreSQL connection pool.
struct ConnectionPoolConfig {
    std::size_t min_connections{2};
    std::size_t max_connections{10};
    std::chrono::milliseconds acquire_timeout{5000};
    std::chrono::seconds connect_timeout{1};
    std::chrono::milliseconds statement_timeout{250};
};

/// Exception thrown when acquiring a connection times out.
class ConnectionAcquisitionTimeoutException : public std::runtime_error {
  public:
    explicit ConnectionAcquisitionTimeoutException(const std::string& message) : std::runtime_error(message) {}
};

/// Exception thrown when attempting to acquire a connection from a draining or closed pool.
class PoolShuttingDownException : public std::runtime_error {
  public:
    explicit PoolShuttingDownException(const std::string& message) : std::runtime_error(message) {}
};

class PostgresConnectionPool {
  public:
    explicit PostgresConnectionPool(const AuthConfig& auth_config,
                                    const ConnectionPoolConfig& pool_config = ConnectionPoolConfig{});

    ~PostgresConnectionPool();

    PostgresConnectionPool(const PostgresConnectionPool&) = delete;
    PostgresConnectionPool(PostgresConnectionPool&&) = delete;
    PostgresConnectionPool& operator=(const PostgresConnectionPool&) = delete;
    PostgresConnectionPool& operator=(PostgresConnectionPool&&) = delete;

    PooledConnection acquire();
    PooledConnection try_acquire(std::chrono::milliseconds timeout);

    void shutdown(std::chrono::milliseconds drain_timeout = std::chrono::milliseconds{5000});
    [[nodiscard]] bool ping(std::chrono::milliseconds timeout = std::chrono::milliseconds{1000}) noexcept;

    [[nodiscard]] std::size_t available_count() const noexcept;
    [[nodiscard]] std::size_t leased_count() const noexcept;
    [[nodiscard]] std::size_t total_count() const noexcept;

  private:
    friend class PooledConnection;

    enum class PoolState { OPEN, DRAINING, CLOSED };

    AuthConfig auth_config_;
    ConnectionPoolConfig pool_config_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;

    PoolState state_{PoolState::OPEN};
    std::queue<std::unique_ptr<pqxx::connection>> available_connections_;
    std::size_t total_connections_{0};
    std::size_t leased_connections_{0};

    std::unique_ptr<pqxx::connection> health_connection_;

    void release(std::unique_ptr<pqxx::connection> conn);
    std::unique_ptr<pqxx::connection> create_raw_connection();
};

} // namespace securecloud::auth::db
