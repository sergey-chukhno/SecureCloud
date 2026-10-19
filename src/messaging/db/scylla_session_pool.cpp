#include "messaging/db/scylla_session_pool.hpp"

#include "messaging/db/scylla_error_mapper.hpp"
#include "securecloud/health/transport_probe.hpp"

namespace securecloud::messaging::db {

ScyllaSessionPool::ScyllaSessionPool(ScyllaConfig config)
    : config_(std::move(config)), pool_capacity_(config_.connection_pool_size > 0 ? config_.connection_pool_size : 4) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (std::size_t i = 0; i < pool_capacity_; ++i) {
        available_sessions_.push(std::make_shared<ScyllaSession>(config_));
    }
}

ScyllaSessionPool::~ScyllaSessionPool() {
    close();
}

std::shared_ptr<IScyllaSession> ScyllaSessionPool::acquire(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (closed_) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError, "Session pool is closed");
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (available_sessions_.empty()) {
        if (cv_.wait_until(lock, deadline) == std::cv_status::timeout) {
            throw ScyllaException(ScyllaErrorCode::Timeout, "Timed out acquiring session from pool after " +
                                                                std::to_string(timeout.count()) + "ms");
        }
        if (closed_) {
            throw ScyllaException(ScyllaErrorCode::ConnectionError, "Session pool is closed");
        }
    }

    auto session = available_sessions_.front();
    available_sessions_.pop();
    ++active_count_;
    return session;
}

void ScyllaSessionPool::release(std::shared_ptr<IScyllaSession> session) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_ || !session) {
        if (active_count_ > 0) {
            --active_count_;
        }
        return;
    }

    available_sessions_.push(std::move(session));
    if (active_count_ > 0) {
        --active_count_;
    }
    cv_.notify_one();
}

std::size_t ScyllaSessionPool::size() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return pool_capacity_;
}

std::size_t ScyllaSessionPool::active_count() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_count_;
}

bool ScyllaSessionPool::ping() {
    std::chrono::milliseconds timeout{config_.connect_timeout_ms > 0 ? config_.connect_timeout_ms : 2000};
    return common::health::probe_tcp_connectivity(config_.host, config_.port, timeout);
}

void ScyllaSessionPool::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_) {
        return;
    }
    closed_ = true;
    while (!available_sessions_.empty()) {
        auto sess = available_sessions_.front();
        available_sessions_.pop();
        if (sess) {
            sess->close();
        }
    }
    cv_.notify_all();
}

} // namespace securecloud::messaging::db
