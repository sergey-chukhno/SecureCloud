#include "grpc/client_call_context.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::gateway::grpc {
namespace {

constexpr int k_test_custom_timeout_ms = 1500;
constexpr int k_test_short_timeout_ms = 100;
constexpr int k_test_negative_timeout_ms = -50;
constexpr int k_concurrency_thread_count = 4;
constexpr int k_concurrency_iteration_count = 500;
constexpr const char* k_test_request_id = "018f3a22-38d5-7b56-b072-000000000001";
constexpr const char* k_test_service_name = "gateway";

TEST(ClientCallContextTest, DefaultConstructionEnforcesSoundDefaults) {
    const auto before = std::chrono::system_clock::now();
    ClientCallContext ctx;
    const auto after = std::chrono::system_clock::now();

    EXPECT_FALSE(ctx.is_cancelled());
    EXPECT_FALSE(ctx.is_deadline_expired());
    EXPECT_TRUE(ctx.request_id().empty());
    EXPECT_EQ(ctx.client_service(), k_test_service_name);

    EXPECT_GE(ctx.deadline(), before + ClientCallContext::k_default_timeout);
    EXPECT_LE(ctx.deadline(), after + ClientCallContext::k_default_timeout + std::chrono::milliseconds(50));
    EXPECT_GT(ctx.deadline_remaining().count(), 0);
}

TEST(ClientCallContextTest, CustomOptionsAndMetadata) {
    CallContextOptions options;
    options.timeout = std::chrono::milliseconds(k_test_custom_timeout_ms);
    options.request_id = k_test_request_id;
    options.client_service = k_test_service_name;

    ClientCallContext ctx(options);

    EXPECT_EQ(ctx.request_id(), k_test_request_id);
    EXPECT_EQ(ctx.client_service(), k_test_service_name);
    EXPECT_FALSE(ctx.is_cancelled());
    EXPECT_FALSE(ctx.is_deadline_expired());
    EXPECT_GT(ctx.deadline_remaining().count(), 0);
    EXPECT_LE(ctx.deadline_remaining().count(), k_test_custom_timeout_ms);
}

TEST(ClientCallContextTest, ConvenienceConstructorSetsIdAndTimeout) {
    const auto timeout = std::chrono::milliseconds(k_test_custom_timeout_ms);
    ClientCallContext ctx(k_test_request_id, timeout);

    EXPECT_EQ(ctx.request_id(), k_test_request_id);
    EXPECT_EQ(ctx.client_service(), k_test_service_name);
    EXPECT_FALSE(ctx.is_cancelled());
    EXPECT_FALSE(ctx.is_deadline_expired());
}

TEST(ClientCallContextTest, ExpiredDeadlineReportsZeroRemaining) {
    const auto timeout = std::chrono::milliseconds(k_test_negative_timeout_ms);
    ClientCallContext ctx(timeout);

    EXPECT_TRUE(ctx.is_deadline_expired());
    EXPECT_EQ(ctx.deadline_remaining().count(), 0);
}

TEST(ClientCallContextTest, CancellationIsIdempotentAndThreadSafe) {
    ClientCallContext ctx;

    EXPECT_FALSE(ctx.is_cancelled());
    ctx.cancel();
    EXPECT_TRUE(ctx.is_cancelled());

    // Idempotent secondary call
    ctx.cancel();
    EXPECT_TRUE(ctx.is_cancelled());
}

TEST(ClientCallContextTest, MoveConstructorTransfersState) {
    const auto timeout = std::chrono::milliseconds(k_test_custom_timeout_ms);
    ClientCallContext original(k_test_request_id, timeout);
    original.cancel();

    ClientCallContext moved(std::move(original));

    EXPECT_TRUE(moved.is_cancelled());
    EXPECT_EQ(moved.request_id(), k_test_request_id);
    EXPECT_EQ(moved.client_service(), k_test_service_name);
}

TEST(ClientCallContextTest, MoveAssignmentTransfersState) {
    const auto timeout = std::chrono::milliseconds(k_test_custom_timeout_ms);
    ClientCallContext original(k_test_request_id, timeout);
    original.cancel();

    ClientCallContext target;
    target = std::move(original);

    EXPECT_TRUE(target.is_cancelled());
    EXPECT_EQ(target.request_id(), k_test_request_id);
    EXPECT_EQ(target.client_service(), k_test_service_name);
}

void run_reader_thread(const ClientCallContext* ctx, const std::atomic<bool>* start, std::atomic<int>* observed_count) {
    while (!start->load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    for (int i = 0; i < k_concurrency_iteration_count; ++i) {
        if (ctx->is_cancelled()) {
            observed_count->fetch_add(1, std::memory_order_relaxed);
        }
    }
}

TEST(ClientCallContextTest, ConcurrentCancellationDoesNotRace) {
    const auto timeout = std::chrono::milliseconds(k_test_short_timeout_ms);
    ClientCallContext ctx(timeout);
    std::atomic<bool> start{false};
    std::atomic<int> observed_count{0};
    std::vector<std::thread> readers;
    readers.reserve(k_concurrency_thread_count);

    for (int i = 0; i < k_concurrency_thread_count; ++i) {
        readers.emplace_back(run_reader_thread, &ctx, &start, &observed_count);
    }

    start.store(true, std::memory_order_release);
    ctx.cancel();

    for (auto& t : readers) {
        t.join();
    }

    EXPECT_TRUE(ctx.is_cancelled());
    EXPECT_GT(observed_count.load(std::memory_order_relaxed), 0);
}

} // namespace
} // namespace securecloud::gateway::grpc
