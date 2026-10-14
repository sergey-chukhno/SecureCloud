#include "concurrency/bounded_worker_pool.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace securecloud::messaging::concurrency {
namespace {

TEST(BoundedWorkerPoolTest, ConstructorValidations) {
    EXPECT_THROW(BoundedWorkerPool(0, 10, "invalid"), std::invalid_argument);
    EXPECT_THROW(BoundedWorkerPool(4, 0, "invalid"), std::invalid_argument);

    BoundedWorkerPool pool(4, 32, "submission-pool");
    EXPECT_EQ(pool.thread_count(), 4);
    EXPECT_EQ(pool.queue_capacity(), 32);
    EXPECT_EQ(pool.name(), "submission-pool");
    EXPECT_FALSE(pool.is_shutdown());
    EXPECT_EQ(pool.queued_tasks(), 0);
    EXPECT_EQ(pool.active_workers(), 0);
}

TEST(BoundedWorkerPoolTest, ExecuteBasicTasksInParallel) {
    BoundedWorkerPool pool(4, 100, "parallel-test");
    std::atomic<int> counter{0};
    constexpr int k_task_count = 50;

    for (int i = 0; i < k_task_count; ++i) {
        bool submitted = pool.try_submit([&counter] { counter.fetch_add(1, std::memory_order_relaxed); });
        EXPECT_TRUE(submitted);
    }

    pool.drain_and_stop();
    EXPECT_EQ(counter.load(), k_task_count);
    EXPECT_TRUE(pool.is_shutdown());
}

TEST(BoundedWorkerPoolTest, QueueCapacityBackpressureAndRejection) {
    // 2 threads, 2 queue slots = max 4 tasks in-flight/queued
    BoundedWorkerPool pool(2, 2, "backpressure-test");

    std::atomic<bool> block_workers{true};
    std::atomic<int> running_tasks{0};

    // Fill the 2 worker threads
    for (int i = 0; i < 2; ++i) {
        bool ok = pool.try_submit([&block_workers, &running_tasks] {
            running_tasks.fetch_add(1);
            while (block_workers.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(5ms);
            }
        });
        EXPECT_TRUE(ok);
    }

    // Wait until both workers are running
    while (running_tasks.load() < 2) {
        std::this_thread::sleep_for(2ms);
    }

    // Fill the 2 queue slots
    EXPECT_TRUE(pool.try_submit([] {}));
    EXPECT_TRUE(pool.try_submit([] {}));

    // 5th task must be rejected immediately (fail-fast backpressure)
    EXPECT_FALSE(pool.try_submit([] {}));
    EXPECT_EQ(pool.queued_tasks(), 2);

    // Unblock workers
    block_workers.store(false);
    pool.drain_and_stop();
}

TEST(BoundedWorkerPoolTest, SubmitWithTimeout) {
    BoundedWorkerPool pool(1, 1, "timeout-test");

    std::atomic<bool> block_worker{true};
    std::atomic<bool> worker_started{false};

    // Block the single thread
    EXPECT_TRUE(pool.try_submit([&block_worker, &worker_started] {
        worker_started.store(true);
        while (block_worker.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(5ms);
        }
    }));

    while (!worker_started.load()) {
        std::this_thread::sleep_for(2ms);
    }

    // Fill the 1 queue slot
    EXPECT_TRUE(pool.try_submit([] {}));

    // Next submit with timeout should fail after timeout
    auto start = std::chrono::steady_clock::now();
    bool timed_out = pool.submit_with_timeout([] {}, 30ms);
    auto duration = std::chrono::steady_clock::now() - start;

    EXPECT_FALSE(timed_out);
    EXPECT_GE(duration, 25ms);

    // Unblock and drain
    block_worker.store(false);
    pool.drain_and_stop();
}

TEST(BoundedWorkerPoolTest, DrainAndStopCompletesQueuedTasks) {
    BoundedWorkerPool pool(2, 50, "drain-test");
    std::atomic<int> completed{0};

    for (int i = 0; i < 20; ++i) {
        EXPECT_TRUE(pool.try_submit([&completed] {
            std::this_thread::sleep_for(2ms);
            completed.fetch_add(1);
        }));
    }

    pool.drain_and_stop();
    EXPECT_EQ(completed.load(), 20);
    EXPECT_TRUE(pool.is_shutdown());

    // Submitting after shutdown fails
    EXPECT_FALSE(pool.try_submit([] {}));
}

TEST(BoundedWorkerPoolTest, ShutdownAbortsQueuedTasks) {
    BoundedWorkerPool pool(1, 20, "shutdown-test");

    std::atomic<bool> block_worker{true};
    std::atomic<bool> first_started{false};
    std::atomic<int> executed_tasks{0};

    // First task blocks
    EXPECT_TRUE(pool.try_submit([&block_worker, &first_started, &executed_tasks] {
        first_started.store(true);
        while (block_worker.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(5ms);
        }
        executed_tasks.fetch_add(1);
    }));

    while (!first_started.load()) {
        std::this_thread::sleep_for(2ms);
    }

    // Queue 5 more tasks
    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(pool.try_submit([&executed_tasks] { executed_tasks.fetch_add(1); }));
    }

    EXPECT_EQ(pool.queued_tasks(), 5);

    // Unblock worker and call immediate shutdown
    block_worker.store(false);
    pool.shutdown();

    EXPECT_TRUE(pool.is_shutdown());
    // Only the first task ran; queued tasks were cleared
    EXPECT_EQ(executed_tasks.load(), 1);
}

TEST(BoundedWorkerPoolTest, ExceptionSafetyDoesNotKillWorkerThread) {
    BoundedWorkerPool pool(1, 10, "exception-safety-test");

    std::atomic<bool> subsequent_task_ran{false};

    // Task that throws an exception
    EXPECT_TRUE(pool.try_submit([] { throw std::runtime_error("simulated worker task failure"); }));

    // Subsequent task must still be picked up and executed by the worker
    EXPECT_TRUE(pool.try_submit([&subsequent_task_ran] { subsequent_task_ran.store(true); }));

    pool.drain_and_stop();
    EXPECT_TRUE(subsequent_task_ran.load());
}

} // namespace
} // namespace securecloud::messaging::concurrency
