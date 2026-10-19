#include "bounded_worker_pool.hpp"

#include <stdexcept>
#include <utility>

namespace securecloud::messaging::concurrency {

BoundedWorkerPool::BoundedWorkerPool(size_t thread_count, size_t max_queue_capacity, std::string pool_name)
    : thread_count_(thread_count), max_queue_capacity_(max_queue_capacity), pool_name_(std::move(pool_name)) {
    if (thread_count_ == 0) {
        throw std::invalid_argument("thread_count must be greater than zero");
    }
    if (max_queue_capacity_ == 0) {
        throw std::invalid_argument("max_queue_capacity must be greater than zero");
    }

    workers_.reserve(thread_count_);
    for (size_t i = 0; i < thread_count_; ++i) {
        workers_.emplace_back(&BoundedWorkerPool::worker_loop, this, i);
    }
}

BoundedWorkerPool::~BoundedWorkerPool() {
    drain_and_stop();
}

bool BoundedWorkerPool::try_submit(std::function<void()> task) {
    if (!task) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    if (is_shutdown_ || is_draining_ || tasks_.size() >= max_queue_capacity_) {
        return false;
    }

    tasks_.push(std::move(task));
    cv_not_empty_.notify_one();
    return true;
}

bool BoundedWorkerPool::submit_with_timeout(std::function<void()> task, std::chrono::milliseconds timeout) {
    if (!task) {
        return false;
    }

    std::unique_lock<std::mutex> lock(mutex_);
    bool space_available = cv_not_full_.wait_for(
        lock, timeout, [this] { return is_shutdown_ || is_draining_ || tasks_.size() < max_queue_capacity_; });

    if (!space_available || is_shutdown_ || is_draining_) {
        return false;
    }

    tasks_.push(std::move(task));
    cv_not_empty_.notify_one();
    return true;
}

void BoundedWorkerPool::shutdown() {
    std::vector<std::thread> to_join;
    {
        std::scoped_lock lock(mutex_);
        if (is_shutdown_) {
            return;
        }
        is_shutdown_ = true;
        is_draining_ = true;

        // Drop unstarted tasks
        while (!tasks_.empty()) {
            tasks_.pop();
        }

        cv_not_empty_.notify_all();
        cv_not_full_.notify_all();
        cv_drained_.notify_all();
        to_join = std::move(workers_);
    }

    for (auto& t : to_join) {
        if (t.joinable()) {
            t.join();
        }
    }
}

void BoundedWorkerPool::drain_and_stop() {
    std::vector<std::thread> to_join;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (is_shutdown_) {
            return;
        }

        is_draining_ = true;
        cv_drained_.wait(lock, [this] { return tasks_.empty() && active_workers_ == 0; });

        is_shutdown_ = true;
        cv_not_empty_.notify_all();
        cv_not_full_.notify_all();
        to_join = std::move(workers_);
    }

    for (auto& t : to_join) {
        if (t.joinable()) {
            t.join();
        }
    }
}

size_t BoundedWorkerPool::thread_count() const noexcept {
    return thread_count_;
}

size_t BoundedWorkerPool::queue_capacity() const noexcept {
    return max_queue_capacity_;
}

size_t BoundedWorkerPool::queued_tasks() const {
    std::scoped_lock lock(mutex_);
    return tasks_.size();
}

size_t BoundedWorkerPool::active_workers() const {
    std::scoped_lock lock(mutex_);
    return active_workers_;
}

bool BoundedWorkerPool::is_shutdown() const {
    std::scoped_lock lock(mutex_);
    return is_shutdown_;
}

const std::string& BoundedWorkerPool::name() const noexcept {
    return pool_name_;
}

void BoundedWorkerPool::worker_loop(size_t /*worker_index*/) {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_not_empty_.wait(lock, [this] { return is_shutdown_ || (!tasks_.empty()); });

            if (is_shutdown_ && tasks_.empty()) {
                return;
            }

            if (tasks_.empty()) {
                continue;
            }

            task = std::move(tasks_.front());
            tasks_.pop();
            ++active_workers_;
            cv_not_full_.notify_one();
        }

        try {
            if (task) {
                task();
            }
            // NOLINTNEXTLINE(bugprone-empty-catch)
        } catch (...) {
            // Task exceptions must not terminate worker thread
        }

        {
            std::scoped_lock lock(mutex_);
            --active_workers_;
            if (is_draining_ && tasks_.empty() && active_workers_ == 0) {
                cv_drained_.notify_all();
            }
        }
    }
}

} // namespace securecloud::messaging::concurrency
