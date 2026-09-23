#pragma once

#include "files/db/pooled_connection.hpp"
#include "files/files_config.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace securecloud::files::db {

// --- Pool Exception Hierarchy ---

class ConnectionPoolException : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

class PoolTimeoutException : public ConnectionPoolException {
    using ConnectionPoolException::ConnectionPoolException;
};

class PoolDrainingException : public ConnectionPoolException {
    using ConnectionPoolException::ConnectionPoolException;
};

class PoolClosedException : public ConnectionPoolException {
    using ConnectionPoolException::ConnectionPoolException;
};

class PortForbiddenException : public ConnectionPoolException {
    using ConnectionPoolException::ConnectionPoolException;
};

/// 3-state lifecycle for the connection pool
enum class PoolState {
    OPEN,
    DRAINING,
    CLOSED
};

/// Strongly typed configuration model for PostgreSQL connection pool
struct ConnectionPoolConfig {
    size_t min_connections{2};
    size_t max_connections{10};
    std::chrono::milliseconds acquire_timeout{500};
    std::chrono::milliseconds connect_timeout{1000};
    std::chrono::milliseconds statement_timeout{250};

    std::string host{"postgres"};
    uint16_t port{5433}; // Dev default is 5433 (host port 5432 is strictly forbidden)
    std::string db_name{"securecloud_files"};
    std::string db_user{"files_user"};
    common::configuration::SecretString db_password;

    /// Constructs pool configuration from service-level FilesConfig
    static ConnectionPoolConfig from_files_config(const FilesConfig& config);

    /// Validates configuration parameters and strictly enforces the Port 5432 invariant
    void validate() const;
};

/// Factory function signature for creating new IDbConnection instances
using ConnectionFactory = std::function<std::unique_ptr<IDbConnection>(const ConnectionPoolConfig&, const std::string&)>;

/// Default connection implementation executing TCP reachability / ping checks
class DefaultDbConnection : public IDbConnection {
public:
    DefaultDbConnection(std::string id, std::string host, uint16_t port, std::chrono::milliseconds connect_timeout);
    ~DefaultDbConnection() override;

    [[nodiscard]] bool is_open() const noexcept override;
    void close() noexcept override;
    [[nodiscard]] bool execute_ping(std::chrono::milliseconds timeout) override;
    [[nodiscard]] const std::string& connection_id() const noexcept override;

private:
    std::string id_;
    std::string host_;
    uint16_t port_;
    std::chrono::milliseconds timeout_;
    bool is_open_{true};
};

/// Thread-safe bounded PostgreSQL connection pool with move-only RAII leases and dedicated health probe
class FilesDbConnectionPool {
public:
    explicit FilesDbConnectionPool(ConnectionPoolConfig config, ConnectionFactory factory = nullptr);
    ~FilesDbConnectionPool();

    // Pool managers are strictly non-copyable and non-movable
    FilesDbConnectionPool(const FilesDbConnectionPool&) = delete;
    FilesDbConnectionPool& operator=(const FilesDbConnectionPool&) = delete;
    FilesDbConnectionPool(FilesDbConnectionPool&&) = delete;
    FilesDbConnectionPool& operator=(FilesDbConnectionPool&&) = delete;

    /// Acquires a connection lease from the pool. Blocks up to acquire_timeout.
    /// Throws PoolTimeoutException if timeout expires.
    /// Throws PoolDrainingException or PoolClosedException if pool is draining/closed.
    [[nodiscard]] PooledConnection acquire();

    /// Returns a leased connection back to the pool (called by ~PooledConnection).
    void return_connection(std::unique_ptr<IDbConnection> conn, bool is_healthy = true) noexcept;

    /// Independent health probe executing a ping against a dedicated health connection.
    /// Immune to application worker pool exhaustion.
    [[nodiscard]] bool ping(std::chrono::milliseconds timeout = std::chrono::milliseconds(250)) noexcept;

    /// Initiates graceful drain: prevents new acquires and closes connections as they return.
    void drain() noexcept;

    /// Closes all connections and transitions pool to CLOSED state.
    void close() noexcept;

    // Capacity & state inspection
    [[nodiscard]] PoolState state() const noexcept;
    [[nodiscard]] size_t total_connections() const noexcept;
    [[nodiscard]] size_t available_connections() const noexcept;
    [[nodiscard]] size_t active_leases() const noexcept;
    [[nodiscard]] size_t waiting_threads() const noexcept;
    [[nodiscard]] const ConnectionPoolConfig& config() const noexcept;

private:
    std::unique_ptr<IDbConnection> create_connection(const std::string& role);

    ConnectionPoolConfig config_;
    ConnectionFactory factory_;

    mutable std::mutex mutex_;
    std::condition_variable cv_available_;
    std::condition_variable cv_drained_;

    PoolState state_{PoolState::OPEN};
    std::vector<std::unique_ptr<IDbConnection>> available_connections_;
    size_t total_created_{0};
    size_t active_leases_{0};
    size_t waiting_threads_{0};
    uint64_t connection_counter_{0};

    // Dedicated Health Connection: isolated from application pool exhaustion
    mutable std::mutex health_mutex_;
    std::unique_ptr<IDbConnection> health_connection_;
};

} // namespace securecloud::files::db
