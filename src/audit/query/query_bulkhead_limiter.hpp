#pragma once

#include <atomic>
#include <cstdint>
#include <utility>

namespace securecloud::audit::query {

class QueryBulkheadLimiter;

/// RAII Lease object ensuring automatic release of occupied bulkhead query slots upon destruction.
class QueryBulkheadLease {
  public:
    QueryBulkheadLease() noexcept = default;
    explicit QueryBulkheadLease(QueryBulkheadLimiter* limiter) noexcept : limiter_(limiter) {}

    ~QueryBulkheadLease() {
        release();
    }

    QueryBulkheadLease(const QueryBulkheadLease&) = delete;
    QueryBulkheadLease& operator=(const QueryBulkheadLease&) = delete;

    QueryBulkheadLease(QueryBulkheadLease&& other) noexcept : limiter_(std::exchange(other.limiter_, nullptr)) {}
    QueryBulkheadLease& operator=(QueryBulkheadLease&& other) noexcept {
        if (this != &other) {
            release();
            limiter_ = std::exchange(other.limiter_, nullptr);
        }
        return *this;
    }

    [[nodiscard]] bool is_acquired() const noexcept { return limiter_ != nullptr; }

  private:
    void release();
    QueryBulkheadLimiter* limiter_{nullptr};
};

/// Thread-safe concurrency bulkhead limiter for audit queries.
class QueryBulkheadLimiter {
  public:
    explicit QueryBulkheadLimiter(uint32_t max_concurrent_queries) noexcept
        : max_concurrent_queries_(max_concurrent_queries) {}

    /// Tries to non-blockingly acquire 1 query slot. Returns an unacquired lease if bulkhead is saturated.
    [[nodiscard]] QueryBulkheadLease try_acquire() noexcept {
        uint32_t current = active_queries_.load(std::memory_order_relaxed);
        while (current < max_concurrent_queries_) {
            if (active_queries_.compare_exchange_weak(current, current + 1,
                                                      std::memory_order_acquire,
                                                      std::memory_order_relaxed)) {
                return QueryBulkheadLease(this);
            }
        }
        rejections_total_.fetch_add(1, std::memory_order_relaxed);
        return QueryBulkheadLease();
    }

    void release_lease() noexcept {
        active_queries_.fetch_sub(1, std::memory_order_release);
    }

    [[nodiscard]] uint32_t active_queries() const noexcept {
        return active_queries_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t rejections_total() const noexcept {
        return rejections_total_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] uint32_t max_concurrent_queries() const noexcept {
        return max_concurrent_queries_;
    }

  private:
    uint32_t max_concurrent_queries_{4};
    std::atomic<uint32_t> active_queries_{0};
    std::atomic<uint64_t> rejections_total_{0};
};

inline void QueryBulkheadLease::release() {
    if (limiter_) {
        limiter_->release_lease();
        limiter_ = nullptr;
    }
}

} // namespace securecloud::audit::query