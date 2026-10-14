#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::messaging::concurrency {

/// Thread-safe bounded worker pool implementing queue backpressure and graceful drain (ADR-009, ADR-010).
class BoundedWorkerPool {
  public:
    explicit BoundedWorkerPool(size_t thread_count, size_t max_queue_capacity, std::string pool_name = "worker");
    ~BoundedWorkerPool();

    BoundedWorkerPool(const BoundedWorkerPool&) = delete;
    BoundedWorkerPool& operator=(const BoundedWorkerPool&) = delete;
    BoundedWorkerPool(BoundedWorkerPool&&) = delete;
    BoundedWorkerPool& operator=(BoundedWorkerPool&&) = delete;

    /// Non-blocking submission. Returns false immediately if the queue is full or pool is stopping.
    [[nodiscard]] bool try_submit(std::function<void()> task);

    /// Timed submission. Blocks up to timeout waiting for queue space. Returns false on expiry or shutdown.
    [[nodiscard]] bool submit_with_timeout(std::function<void()> task, std::chrono::milliseconds timeout);

    /// Initiates immediate shutdown: drops unstarted queued tasks and joins worker threads.
    void shutdown();

    /// Graceful drain: completes all currently queued tasks before joining worker threads.
    void drain_and_stop();

    [[nodiscard]] size_t thread_count() const noexcept;
    [[nodiscard]] size_t queue_capacity() const noexcept;
    [[nodiscard]] size_t queued_tasks() const;
    [[nodiscard]] size_t active_workers() const;
    [[nodiscard]] bool is_shutdown() const;
    [[nodiscard]] const std::string& name() const noexcept;

  private:
    void worker_loop(size_t worker_index);

    const size_t thread_count_;
    const size_t max_queue_capacity_;
    const std::string pool_name_;

    mutable std::mutex mutex_;
    std::condition_variable cv_not_empty_;
    std::condition_variable cv_not_full_;
    std::condition_variable cv_drained_;

    std::queue<std::function<void()>> tasks_;
    std::vector<std::thread> workers_;

    size_t active_workers_{0};
    bool is_draining_{false};
    bool is_shutdown_{false};
};

} // namespace securecloud::messaging::concurrency
