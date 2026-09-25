#pragma once

#include <memory>
#include <pqxx/pqxx>
#include <utility>

namespace securecloud::auth::db {

class PostgresConnectionPool;

/// RAII move-only wrapper representing a leased database connection.
/// Automatically returns the underlying connection to the pool upon destruction.
class PooledConnection {
  public:
    PooledConnection() noexcept = default;

    PooledConnection(std::unique_ptr<pqxx::connection> conn, PostgresConnectionPool& pool)
        : conn_(std::move(conn)), pool_(&pool) {}

    ~PooledConnection();

    PooledConnection(const PooledConnection&) = delete;
    PooledConnection& operator=(const PooledConnection&) = delete;

    PooledConnection(PooledConnection&& other) noexcept : conn_(std::move(other.conn_)), pool_(other.pool_) {
        other.pool_ = nullptr;
    }

    PooledConnection& operator=(PooledConnection&& other) noexcept;

    [[nodiscard]] pqxx::connection* get() const noexcept { return conn_.get(); }
    [[nodiscard]] pqxx::connection& operator*() const { return *conn_; }
    [[nodiscard]] pqxx::connection* operator->() const noexcept { return conn_.get(); }
    explicit operator bool() const noexcept { return conn_ != nullptr; }

  private:
    std::unique_ptr<pqxx::connection> conn_{nullptr};
    PostgresConnectionPool* pool_{nullptr};
};

} // namespace securecloud::auth::db
