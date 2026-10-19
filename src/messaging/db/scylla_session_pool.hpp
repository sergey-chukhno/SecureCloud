#pragma once

#include "messaging/db/scylla_session.hpp"
#include "messaging/db/scylla_session_interface.hpp"
#include "messaging/messaging_config.hpp"

#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <vector>

namespace securecloud::messaging::db {

/// RAII lease wrapper for a pooled ScyllaDB session.
class PooledScyllaSession {
  public:
    PooledScyllaSession(std::shared_ptr<IScyllaSession> session, IScyllaSessionPool& pool)
        : session_(std::move(session)), pool_(pool) {}

    ~PooledScyllaSession() {
        if (session_) {
            pool_.release(session_);
        }
    }

    PooledScyllaSession(const PooledScyllaSession&) = delete;
    PooledScyllaSession& operator=(const PooledScyllaSession&) = delete;

    PooledScyllaSession(PooledScyllaSession&& other) noexcept
        : session_(std::move(other.session_)), pool_(other.pool_) {}

    PooledScyllaSession& operator=(PooledScyllaSession&& other) noexcept {
        if (this != &other) {
            if (session_) {
                pool_.release(session_);
            }
            session_ = std::move(other.session_);
        }
        return *this;
    }

    IScyllaSession* operator->() noexcept { return session_.get(); }
    IScyllaSession& operator*() noexcept { return *session_; }
    [[nodiscard]] std::shared_ptr<IScyllaSession> get() const noexcept { return session_; }

  private:
    std::shared_ptr<IScyllaSession> session_;
    IScyllaSessionPool& pool_;
};

/// Production connection pool for ScyllaDB sessions.
class ScyllaSessionPool : public IScyllaSessionPool {
  public:
    explicit ScyllaSessionPool(ScyllaConfig config);
    ~ScyllaSessionPool() override;

    std::shared_ptr<IScyllaSession>
    acquire(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) override;

    void release(std::shared_ptr<IScyllaSession> session) override;

    [[nodiscard]] std::size_t size() const noexcept override;
    [[nodiscard]] std::size_t active_count() const noexcept override;

    bool ping() override;
    void close() override;

    /// Acquires a session wrapped in an RAII lease guard.
    [[nodiscard]] PooledScyllaSession
    acquire_lease(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) {
        return PooledScyllaSession(acquire(timeout), *this);
    }

  private:
    ScyllaConfig config_;
    std::size_t pool_capacity_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<std::shared_ptr<IScyllaSession>> available_sessions_;
    std::size_t active_count_{0};
    bool closed_{false};
};

} // namespace securecloud::messaging::db
