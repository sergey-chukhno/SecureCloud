#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <utility>

namespace securecloud::files::db {

/// Abstract interface representing a managed database connection handle.
/// Allows unit test injection and future backend driver abstraction (e.g., libpqxx).
class IDbConnection {
public:
    virtual ~IDbConnection() = default;

    [[nodiscard]] virtual bool is_open() const noexcept = 0;
    virtual void close() noexcept = 0;
    [[nodiscard]] virtual bool execute_ping(std::chrono::milliseconds timeout) = 0;
    [[nodiscard]] virtual const std::string& connection_id() const noexcept = 0;
};

// Forward declaration of the connection pool
class FilesDbConnectionPool;

/// RAII move-only lease for a pooled database connection.
/// Automatically returns the borrowed connection to its owning FilesDbConnectionPool upon destruction.
class PooledConnection {
public:
    PooledConnection() noexcept = default;

    PooledConnection(std::unique_ptr<IDbConnection> conn, FilesDbConnectionPool* pool) noexcept
        : conn_(std::move(conn)), pool_(pool) {}

    ~PooledConnection();

    // Move-only semantics (ADR-005 RAII lease ownership)
    PooledConnection(const PooledConnection&) = delete;
    PooledConnection& operator=(const PooledConnection&) = delete;

    PooledConnection(PooledConnection&& other) noexcept
        : conn_(std::move(other.conn_)), pool_(other.pool_), is_healthy_(other.is_healthy_) {
        other.pool_ = nullptr;
    }

    PooledConnection& operator=(PooledConnection&& other) noexcept {
        if (this != &other) {
            return_to_pool();
            conn_ = std::move(other.conn_);
            pool_ = other.pool_;
            is_healthy_ = other.is_healthy_;
            other.pool_ = nullptr;
        }
        return *this;
    }

    [[nodiscard]] bool is_valid() const noexcept {
        return conn_ != nullptr && pool_ != nullptr && conn_->is_open();
    }

    explicit operator bool() const noexcept {
        return is_valid();
    }

    [[nodiscard]] IDbConnection* get() const noexcept {
        return conn_.get();
    }

    IDbConnection* operator->() const noexcept {
        return conn_.get();
    }

    IDbConnection& operator*() const noexcept {
        return *conn_;
    }

    [[nodiscard]] const std::string& connection_id() const noexcept {
        static const std::string k_empty;
        return conn_ ? conn_->connection_id() : k_empty;
    }

    void mark_unhealthy() noexcept {
        is_healthy_ = false;
    }

    [[nodiscard]] bool is_healthy() const noexcept {
        return is_healthy_;
    }

    /// Discards pool tracking and releases ownership of the underlying connection without returning it.
    std::unique_ptr<IDbConnection> release() noexcept {
        pool_ = nullptr;
        return std::move(conn_);
    }

private:
    void return_to_pool() noexcept;

    std::unique_ptr<IDbConnection> conn_{nullptr};
    FilesDbConnectionPool* pool_{nullptr};
    bool is_healthy_{true};
};

} // namespace securecloud::files::db
