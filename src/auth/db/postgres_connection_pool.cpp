#include "auth/db/postgres_connection_pool.hpp"

#include "auth/db/pooled_connection.hpp"

#include <sstream>

namespace securecloud::auth::db {

PooledConnection::~PooledConnection() {
    if (conn_ && pool_) {
        pool_->release(std::move(conn_));
    }
}

PooledConnection& PooledConnection::operator=(PooledConnection&& other) noexcept {
    if (this != &other) {
        if (conn_ && pool_) {
            pool_->release(std::move(conn_));
        }
        conn_ = std::move(other.conn_);
        pool_ = other.pool_;
        other.pool_ = nullptr;
    }
    return *this;
}

void PostgresConnectionPool::validate_config() const {
    if (pool_config_.max_connections == 0) {
        throw std::invalid_argument("ConnectionPoolConfig: max_connections must be at least 1");
    }
    if (pool_config_.min_connections > pool_config_.max_connections) {
        throw std::invalid_argument("ConnectionPoolConfig: min_connections cannot exceed max_connections");
    }

    const bool is_loopback = (auth_config_.db_host == "localhost" || auth_config_.db_host == "127.0.0.1" ||
                              auth_config_.db_host == "::1" || auth_config_.db_host == "host.docker.internal");
    if (is_loopback && auth_config_.db_port == 5432) {
        throw PortForbiddenException("[SecureCloud] Port 5432 Invariant Violation: Connecting to " +
                                     auth_config_.db_host +
                                     ":5432 is strictly forbidden. Host PostgreSQL 14 must remain untouched. "
                                     "SecureCloud PostgreSQL 17 binds to port 5433.");
    }
}

PostgresConnectionPool::PostgresConnectionPool(const AuthConfig& auth_config, const ConnectionPoolConfig& pool_config)
    : auth_config_(auth_config), pool_config_(pool_config) {

    validate_config();

    for (std::size_t i = 0; i < pool_config_.min_connections; ++i) {
        available_connections_.push(create_raw_connection());
        ++total_connections_;
    }

    try {
        health_connection_ = create_raw_connection();
    } catch (...) {
        // If DB is offline at construction, health_connection_ will be lazily created on subsequent ping()
    }
}

PostgresConnectionPool::~PostgresConnectionPool() {
    shutdown(std::chrono::milliseconds{1000});
}

std::unique_ptr<pqxx::connection> PostgresConnectionPool::create_raw_connection() {
    std::ostringstream conn_builder;
    conn_builder << "host=" << auth_config_.db_host << " port=" << auth_config_.db_port
                 << " dbname=" << auth_config_.db_name << " user=" << auth_config_.db_user
                 << " password=" << auth_config_.db_password.expose_unredacted_secret()
                 << " connect_timeout=" << pool_config_.connect_timeout.count()
                 << " options='-c statement_timeout=" << pool_config_.statement_timeout.count() << "ms'";

    return std::make_unique<pqxx::connection>(conn_builder.str());
}

PooledConnection PostgresConnectionPool::acquire() {
    return try_acquire(pool_config_.acquire_timeout);
}

PooledConnection PostgresConnectionPool::try_acquire(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);

    auto predicate = [this]() {
        return state_ != PoolState::OPEN || !available_connections_.empty() ||
               total_connections_ < pool_config_.max_connections;
    };

    if (!cv_.wait_for(lock, timeout, predicate)) {
        throw ConnectionAcquisitionTimeoutException(
            "Timeout expired while waiting for an available database connection.");
    }

    if (state_ != PoolState::OPEN) {
        throw PoolShuttingDownException("Cannot acquire connection: pool is shutting down or closed.");
    }

    if (!available_connections_.empty()) {
        auto conn = std::move(available_connections_.front());
        available_connections_.pop();
        ++leased_connections_;
        return PooledConnection(std::move(conn), *this);
    }

    if (total_connections_ < pool_config_.max_connections) {
        auto conn = create_raw_connection();
        ++total_connections_;
        ++leased_connections_;
        return PooledConnection(std::move(conn), *this);
    }

    throw ConnectionAcquisitionTimeoutException("Failed to obtain a connection.");
}

void PostgresConnectionPool::release(std::unique_ptr<pqxx::connection> conn) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (leased_connections_ > 0) {
        --leased_connections_;
    }

    if (conn && conn->is_open()) {
        available_connections_.push(std::move(conn));
    } else {
        if (total_connections_ > 0) {
            --total_connections_;
        }
    }

    cv_.notify_one();
}

void PostgresConnectionPool::shutdown(std::chrono::milliseconds drain_timeout) {
    {
        std::unique_lock<std::mutex> lock(mutex_);

        if (state_ == PoolState::CLOSED) {
            return;
        }

        state_ = PoolState::DRAINING;
        cv_.notify_all();

        cv_.wait_for(lock, drain_timeout, [this]() { return leased_connections_ == 0; });

        while (!available_connections_.empty()) {
            available_connections_.pop();
        }

        total_connections_ = 0;
        state_ = PoolState::CLOSED;
    }

    {
        std::lock_guard<std::mutex> h_lock(health_mutex_);
        health_connection_.reset();
    }
}

std::size_t PostgresConnectionPool::available_count() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return available_connections_.size();
}

std::size_t PostgresConnectionPool::leased_count() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return leased_connections_;
}

std::size_t PostgresConnectionPool::total_count() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_connections_;
}

bool PostgresConnectionPool::ping(std::chrono::milliseconds timeout) noexcept {
    std::lock_guard<std::mutex> h_lock(health_mutex_);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ == PoolState::CLOSED) {
            return false;
        }
    }

    try {
        if (!health_connection_ || !health_connection_->is_open()) {
            health_connection_ = create_raw_connection();
        }
        if (!health_connection_) {
            return false;
        }

        pqxx::nontransaction tx(*health_connection_);
        if (timeout > std::chrono::milliseconds::zero()) {
            tx.exec("SET LOCAL statement_timeout = " + std::to_string(timeout.count()) + ";").no_rows();
        }
        const auto result = tx.exec("SELECT 1;");

        return !result.empty();
    } catch (...) {
        health_connection_.reset();
        return false;
    }
}

} // namespace securecloud::auth::db