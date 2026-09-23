#include "files/db/files_connection_pool.hpp"

#include "securecloud/health/transport_probe.hpp"

#include <iostream>
#include <sstream>

namespace securecloud::files::db {

// --- PooledConnection Implementation ---

PooledConnection::~PooledConnection() {
    return_to_pool();
}

void PooledConnection::return_to_pool() noexcept {
    if (pool_ && conn_) {
        pool_->return_connection(std::move(conn_), is_healthy_);
        pool_ = nullptr;
    }
}

// --- ConnectionPoolConfig Implementation ---

ConnectionPoolConfig ConnectionPoolConfig::from_files_config(const FilesConfig& config) {
    ConnectionPoolConfig pool_cfg;
    pool_cfg.host = config.db_host;
    pool_cfg.port = config.db_port;
    pool_cfg.db_name = config.db_name;
    pool_cfg.db_user = config.db_user;
    pool_cfg.db_password = config.db_password;
    return pool_cfg;
}

void ConnectionPoolConfig::validate() const {
    if (max_connections == 0) {
        throw std::invalid_argument("ConnectionPoolConfig: max_connections must be at least 1");
    }
    if (min_connections > max_connections) {
        throw std::invalid_argument("ConnectionPoolConfig: min_connections (" + std::to_string(min_connections) +
                                   ") cannot exceed max_connections (" + std::to_string(max_connections) + ")");
    }

    // Port 5432 Hard Security Invariant (ADR-005, FILES-001-T02)
    const bool is_loopback = (host == "localhost" || host == "127.0.0.1" || host == "::1" ||
                              host == "host.docker.internal");
    if (is_loopback && port == 5432) {
        throw PortForbiddenException(
            "[SecureCloud] Port 5432 Invariant Violation: Connecting to " + host + ":5432 is strictly forbidden. "
            "Host PostgreSQL 14 must remain untouched. SecureCloud PostgreSQL 17 binds to port 5433.");
    }
}

// --- DefaultDbConnection Implementation ---

DefaultDbConnection::DefaultDbConnection(std::string id, std::string host, uint16_t port,
                                         std::chrono::milliseconds connect_timeout)
    : id_(std::move(id)), host_(std::move(host)), port_(port), timeout_(connect_timeout) {
    // Basic connectivity probe on construction
    is_open_ = common::health::probe_tcp_connectivity(host_, port_, timeout_);
}

DefaultDbConnection::~DefaultDbConnection() {
    close();
}

bool DefaultDbConnection::is_open() const noexcept {
    return is_open_;
}

void DefaultDbConnection::close() noexcept {
    is_open_ = false;
}

bool DefaultDbConnection::execute_ping(std::chrono::milliseconds timeout) {
    if (!is_open_) {
        return false;
    }
    return common::health::probe_tcp_connectivity(host_, port_, timeout);
}

const std::string& DefaultDbConnection::connection_id() const noexcept {
    return id_;
}

// --- FilesDbConnectionPool Implementation ---

FilesDbConnectionPool::FilesDbConnectionPool(ConnectionPoolConfig config, ConnectionFactory factory)
    : config_(std::move(config)), factory_(std::move(factory)) {
    config_.validate();

    if (!factory_) {
        factory_ = [](const ConnectionPoolConfig& cfg, const std::string& id) -> std::unique_ptr<IDbConnection> {
            return std::make_unique<DefaultDbConnection>(id, cfg.host, cfg.port, cfg.connect_timeout);
        };
    }

    // Eagerly pre-warm min_connections
    for (size_t i = 0; i < config_.min_connections; ++i) {
        auto conn = create_connection("worker-init");
        if (conn) {
            available_connections_.push_back(std::move(conn));
            total_created_++;
        }
    }
}

FilesDbConnectionPool::~FilesDbConnectionPool() {
    close();
}

std::unique_ptr<IDbConnection> FilesDbConnectionPool::create_connection(const std::string& role) {
    const uint64_t seq = ++connection_counter_;
    std::string conn_id = "conn-" + role + "-" + std::to_string(seq);
    return factory_(config_, conn_id);
}

PooledConnection FilesDbConnectionPool::acquire() {
    std::unique_lock<std::mutex> lock(mutex_);

    if (state_ == PoolState::DRAINING) {
        throw PoolDrainingException("Connection pool is currently draining");
    }
    if (state_ == PoolState::CLOSED) {
        throw PoolClosedException("Connection pool is closed");
    }

    // 1. Check if an idle connection is available in the pool
    if (!available_connections_.empty()) {
        auto conn = std::move(available_connections_.back());
        available_connections_.pop_back();
        active_leases_++;
        return PooledConnection(std::move(conn), this);
    }

    // 2. If below max_connections limit, create a new connection dynamically
    if (total_created_ < config_.max_connections) {
        total_created_++;
        active_leases_++;
        lock.unlock();

        try {
            auto conn = create_connection("worker");
            return PooledConnection(std::move(conn), this);
        } catch (...) {
            lock.lock();
            total_created_--;
            active_leases_--;
            cv_available_.notify_one();
            throw;
        }
    }

    // 3. Pool is exhausted: wait with acquire_timeout for a returned connection
    waiting_threads_++;
    const auto deadline = std::chrono::steady_clock::now() + config_.acquire_timeout;
    const bool acquired = cv_available_.wait_until(lock, deadline, [this]() {
        return state_ != PoolState::OPEN || !available_connections_.empty();
    });
    waiting_threads_--;

    if (state_ == PoolState::DRAINING) {
        throw PoolDrainingException("Connection pool began draining while waiting for lease");
    }
    if (state_ == PoolState::CLOSED) {
        throw PoolClosedException("Connection pool was closed while waiting for lease");
    }
    if (!acquired || available_connections_.empty()) {
        throw PoolTimeoutException("Timed out waiting to acquire database connection after " +
                                   std::to_string(config_.acquire_timeout.count()) + "ms");
    }

    auto conn = std::move(available_connections_.back());
    available_connections_.pop_back();
    active_leases_++;
    return PooledConnection(std::move(conn), this);
}

void FilesDbConnectionPool::return_connection(std::unique_ptr<IDbConnection> conn, bool is_healthy) noexcept {
    if (!conn) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (active_leases_ > 0) {
        active_leases_--;
    }

    if (state_ == PoolState::OPEN && is_healthy && conn->is_open()) {
        available_connections_.push_back(std::move(conn));
        cv_available_.notify_one();
    } else {
        // Discard connection if pool is draining, closed, or connection is unhealthy
        conn->close();
        if (total_created_ > 0) {
            total_created_--;
        }
        if (state_ == PoolState::DRAINING && active_leases_ == 0) {
            cv_drained_.notify_all();
        }
    }
}

bool FilesDbConnectionPool::ping(std::chrono::milliseconds timeout) noexcept {
    std::lock_guard<std::mutex> h_lock(health_mutex_);
    if (state() == PoolState::CLOSED) {
        return false;
    }

    try {
        if (!health_connection_ || !health_connection_->is_open()) {
            health_connection_ = create_connection("health");
        }
        if (!health_connection_) {
            return false;
        }
        return health_connection_->execute_ping(timeout);
    } catch (...) {
        return false;
    }
}

void FilesDbConnectionPool::drain() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == PoolState::CLOSED) {
        return;
    }

    state_ = PoolState::DRAINING;
    for (auto& conn : available_connections_) {
        if (conn) {
            conn->close();
            if (total_created_ > 0) {
                total_created_--;
            }
        }
    }
    available_connections_.clear();
    cv_available_.notify_all();

    if (active_leases_ == 0) {
        cv_drained_.notify_all();
    }
}

void FilesDbConnectionPool::close() noexcept {
    drain();
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (active_leases_ > 0) {
            cv_drained_.wait_for(lock, std::chrono::milliseconds(2000), [this]() {
                return active_leases_ == 0;
            });
        }
        state_ = PoolState::CLOSED;
    }
    {
        std::lock_guard<std::mutex> h_lock(health_mutex_);
        if (health_connection_) {
            health_connection_->close();
            health_connection_.reset();
        }
    }
}

PoolState FilesDbConnectionPool::state() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

size_t FilesDbConnectionPool::total_connections() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_created_;
}

size_t FilesDbConnectionPool::available_connections() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return available_connections_.size();
}

size_t FilesDbConnectionPool::active_leases() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_leases_;
}

size_t FilesDbConnectionPool::waiting_threads() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return waiting_threads_;
}

const ConnectionPoolConfig& FilesDbConnectionPool::config() const noexcept {
    return config_;
}

} // namespace securecloud::files::db
