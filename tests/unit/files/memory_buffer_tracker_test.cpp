#include "concurrency/memory_buffer_tracker.hpp"

#include <gtest/gtest.h>
#include <atomic>
#include <thread>
#include <vector>

namespace securecloud::files {
namespace {

TEST(MemoryBufferTrackerTest, ReservesMemoryWithinCapacity) {
    auto tracker = MemoryBufferTracker::create(1024);

    EXPECT_EQ(tracker->max_memory_bytes(), 1024);
    EXPECT_EQ(tracker->current_reserved_bytes(), 0);
    EXPECT_EQ(tracker->available_bytes(), 1024);

    auto res1 = tracker->try_reserve(400);
    EXPECT_TRUE(res1.holds_reservation());
    EXPECT_EQ(res1.reserved_bytes(), 400);
    EXPECT_EQ(tracker->current_reserved_bytes(), 400);
    EXPECT_EQ(tracker->available_bytes(), 624);

    auto res2 = tracker->try_reserve(600);
    EXPECT_TRUE(res2.holds_reservation());
    EXPECT_EQ(res2.reserved_bytes(), 600);
    EXPECT_EQ(tracker->current_reserved_bytes(), 1000);
    EXPECT_EQ(tracker->available_bytes(), 24);

    // Exceeds remaining 24 bytes
    auto res3 = tracker->try_reserve(25);
    EXPECT_FALSE(res3.holds_reservation());
    EXPECT_EQ(res3.reserved_bytes(), 0);
    EXPECT_EQ(tracker->current_reserved_bytes(), 1000);
}

TEST(MemoryBufferTrackerTest, AutomaticallyReleasesOnDestruction) {
    auto tracker = MemoryBufferTracker::create(1024);

    {
        auto res1 = tracker->try_reserve(500);
        auto res2 = tracker->try_reserve(300);
        EXPECT_EQ(tracker->current_reserved_bytes(), 800);
    } // res1 and res2 go out of scope

    EXPECT_EQ(tracker->current_reserved_bytes(), 0);
    EXPECT_EQ(tracker->available_bytes(), 1024);
}

TEST(MemoryBufferTrackerTest, ExplicitReleaseFreesBudgetImmediately) {
    auto tracker = MemoryBufferTracker::create(500);

    auto res = tracker->try_reserve(300);
    EXPECT_EQ(tracker->current_reserved_bytes(), 300);

    res.release();
    EXPECT_FALSE(res.holds_reservation());
    EXPECT_EQ(tracker->current_reserved_bytes(), 0);
}

TEST(MemoryBufferTrackerTest, MoveSemanticsTransferReservation) {
    auto tracker = MemoryBufferTracker::create(1000);

    auto res1 = tracker->try_reserve(400);
    EXPECT_EQ(tracker->current_reserved_bytes(), 400);

    MemoryBufferReservation res2 = std::move(res1);
    EXPECT_FALSE(res1.holds_reservation());
    EXPECT_TRUE(res2.holds_reservation());
    EXPECT_EQ(res2.reserved_bytes(), 400);
    EXPECT_EQ(tracker->current_reserved_bytes(), 400);
}

TEST(MemoryBufferTrackerTest, ConcurrentReservationsNeverExceedMaximumBudget) {
    constexpr size_t k_budget = 5000;
    constexpr size_t k_threads = 10;
    constexpr size_t k_iterations = 50;

    auto tracker = MemoryBufferTracker::create(k_budget);
    std::atomic<size_t> max_observed{0};
    std::vector<std::thread> threads;

    for (size_t i = 0; i < k_threads; ++i) {
        threads.emplace_back([&] {
            for (size_t j = 0; j < k_iterations; ++j) {
                auto res = tracker->try_reserve(200);
                if (res) {
                    size_t curr = tracker->current_reserved_bytes();
                    size_t prev = max_observed.load();
                    while (curr > prev && !max_observed.compare_exchange_weak(prev, curr)) {}
                    std::this_thread::yield();
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_LE(max_observed.load(), k_budget);
    EXPECT_EQ(tracker->current_reserved_bytes(), 0);
}

TEST(SizeValidatorsTest, ValidatesChunkRequestSizeBounds) {
    std::string err;
    constexpr size_t k_max_chunk = 5 * 1024 * 1024; // 5 MiB

    EXPECT_TRUE(validate_chunk_request_size(1024, k_max_chunk, err));
    EXPECT_TRUE(validate_chunk_request_size(k_max_chunk, k_max_chunk, err));

    EXPECT_FALSE(validate_chunk_request_size(0, k_max_chunk, err));
    EXPECT_FALSE(validate_chunk_request_size(k_max_chunk + 1, k_max_chunk, err));
    EXPECT_NE(err.find("exceeds maximum allowed size"), std::string::npos);
}

TEST(SizeValidatorsTest, ValidatesFileTransferSizeBounds) {
    std::string err;
    constexpr uint64_t k_max_transfer = 10ULL * 1024ULL * 1024ULL * 1024ULL; // 10 GiB

    EXPECT_TRUE(validate_file_transfer_size(1024, k_max_transfer, err));
    EXPECT_TRUE(validate_file_transfer_size(k_max_transfer, k_max_transfer, err));

    EXPECT_FALSE(validate_file_transfer_size(0, k_max_transfer, err));
    EXPECT_FALSE(validate_file_transfer_size(k_max_transfer + 1, k_max_transfer, err));
    EXPECT_NE(err.find("exceeds maximum allowed size"), std::string::npos);
}

} // namespace
} // namespace securecloud::files
