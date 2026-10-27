#include "concurrency/concurrency_bulkhead.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

namespace securecloud::files {
namespace {

TEST(ConcurrencyBulkheadTest, AllowsAcquisitionUpToCapacity) {
    auto bulkhead = ConcurrencyBulkhead::create("test_domain", 3, std::chrono::milliseconds(50));

    EXPECT_EQ(bulkhead->domain_name(), "test_domain");
    EXPECT_EQ(bulkhead->max_concurrency(), 3);
    EXPECT_EQ(bulkhead->active_permits(), 0);
    EXPECT_EQ(bulkhead->available_permits(), 3);

    auto p1 = bulkhead->try_acquire();
    EXPECT_TRUE(p1.holds_permit());
    EXPECT_EQ(bulkhead->active_permits(), 1);
    EXPECT_EQ(bulkhead->available_permits(), 2);

    auto p2 = bulkhead->try_acquire();
    EXPECT_TRUE(p2.holds_permit());
    EXPECT_EQ(bulkhead->active_permits(), 2);

    auto p3 = bulkhead->try_acquire();
    EXPECT_TRUE(p3.holds_permit());
    EXPECT_EQ(bulkhead->active_permits(), 3);
    EXPECT_EQ(bulkhead->available_permits(), 0);

    // Saturated
    auto p4 = bulkhead->try_acquire();
    EXPECT_FALSE(p4.holds_permit());
    EXPECT_EQ(bulkhead->active_permits(), 3);
}

TEST(ConcurrencyBulkheadTest, AutomaticallyReleasesPermitOnDestruction) {
    auto bulkhead = ConcurrencyBulkhead::create("test_domain", 2);

    {
        auto p1 = bulkhead->try_acquire();
        auto p2 = bulkhead->try_acquire();
        EXPECT_EQ(bulkhead->active_permits(), 2);
    } // p1 and p2 destroyed here

    EXPECT_EQ(bulkhead->active_permits(), 0);
    EXPECT_EQ(bulkhead->available_permits(), 2);

    auto p3 = bulkhead->try_acquire();
    EXPECT_TRUE(p3.holds_permit());
    EXPECT_EQ(bulkhead->active_permits(), 1);
}

TEST(ConcurrencyBulkheadTest, ExplicitReleaseReleasesPermitImmediately) {
    auto bulkhead = ConcurrencyBulkhead::create("test_domain", 1);

    auto p1 = bulkhead->try_acquire();
    EXPECT_TRUE(p1.holds_permit());
    EXPECT_EQ(bulkhead->active_permits(), 1);

    p1.release();
    EXPECT_FALSE(p1.holds_permit());
    EXPECT_EQ(bulkhead->active_permits(), 0);

    // Can acquire again
    auto p2 = bulkhead->try_acquire();
    EXPECT_TRUE(p2.holds_permit());
}

TEST(ConcurrencyBulkheadTest, AcquireWithTimeoutTimesOutWhenSaturated) {
    auto bulkhead = ConcurrencyBulkhead::create("test_domain", 1, std::chrono::milliseconds(20));

    auto p1 = bulkhead->try_acquire();
    EXPECT_TRUE(p1.holds_permit());

    auto start = std::chrono::steady_clock::now();
    auto p2 = bulkhead->acquire_with_timeout(std::chrono::milliseconds(50));
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    EXPECT_FALSE(p2.holds_permit());
    EXPECT_GE(duration.count(), 40);
}

TEST(ConcurrencyBulkheadTest, AcquireWithTimeoutSucceedsWhenPermitFreedByAnotherThread) {
    auto bulkhead = ConcurrencyBulkhead::create("test_domain", 1, std::chrono::milliseconds(200));

    auto p1 = bulkhead->try_acquire();
    EXPECT_TRUE(p1.holds_permit());

    std::thread releaser([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
        p1.release();
    });

    auto p2 = bulkhead->acquire_with_timeout(std::chrono::milliseconds(200));
    EXPECT_TRUE(p2.holds_permit());

    releaser.join();
}

TEST(ConcurrencyBulkheadTest, MoveAssignmentTransfersPermitOwnership) {
    auto bulkhead = ConcurrencyBulkhead::create("test_domain", 2);

    auto p1 = bulkhead->try_acquire();
    EXPECT_EQ(bulkhead->active_permits(), 1);

    BulkheadPermit p2;
    EXPECT_FALSE(p2.holds_permit());

    p2 = std::move(p1);
    EXPECT_FALSE(p1.holds_permit());
    EXPECT_TRUE(p2.holds_permit());
    EXPECT_EQ(bulkhead->active_permits(), 1);
}

TEST(ConcurrencyBulkheadTest, ConcurrentAcquiresAndReleasesMaintainCorrectAccounting) {
    constexpr size_t k_concurrency_limit = 5;
    constexpr size_t k_num_threads = 20;
    constexpr size_t k_iterations = 50;

    auto bulkhead = ConcurrencyBulkhead::create("stress_domain", k_concurrency_limit, std::chrono::milliseconds(100));
    std::atomic<size_t> max_observed_concurrency{0};
    std::vector<std::thread> threads;

    for (size_t i = 0; i < k_num_threads; ++i) {
        threads.emplace_back([&] {
            for (size_t j = 0; j < k_iterations; ++j) {
                auto permit = bulkhead->acquire_with_timeout(std::chrono::milliseconds(50));
                if (permit) {
                    size_t current = bulkhead->active_permits();
                    size_t prev_max = max_observed_concurrency.load();
                    while (current > prev_max && !max_observed_concurrency.compare_exchange_weak(prev_max, current)) {
                    }
                    std::this_thread::yield();
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_LE(max_observed_concurrency.load(), k_concurrency_limit);
    EXPECT_EQ(bulkhead->active_permits(), 0);
    EXPECT_EQ(bulkhead->available_permits(), k_concurrency_limit);
}

} // namespace
} // namespace securecloud::files
