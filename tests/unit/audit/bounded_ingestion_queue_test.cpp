#include "ingestion/bounded_ingestion_queue.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

namespace securecloud::audit::ingestion::testing {

class BoundedIngestionQueueTest : public ::testing::Test {
protected:
    IngestionEnvelope create_sample_envelope(const std::string& event_id) {
        IngestionEnvelope env;
        auto parsed_id = domain::EventId::from_string(event_id);
        if (parsed_id.has_value()) {
            env.event.event_id = parsed_id.value();
        }
        env.event.event_type = "test.event";
        return env;
    }
};

TEST_F(BoundedIngestionQueueTest, CapacityLimitsAndTryPush) {
    BoundedIngestionQueue queue(2);
    EXPECT_EQ(queue.capacity(), 2);
    EXPECT_EQ(queue.size(), 0);

    EXPECT_TRUE(queue.try_push(create_sample_envelope("018f6e4a-7b3c-7000-8000-000000000001")));
    EXPECT_TRUE(queue.try_push(create_sample_envelope("018f6e4a-7b3c-7000-8000-000000000002")));

    // Overflow attempt
    EXPECT_FALSE(queue.try_push(create_sample_envelope("018f6e4a-7b3c-7000-8000-000000000003")));

    EXPECT_EQ(queue.size(), 2);
    EXPECT_EQ(queue.total_enqueued(), 2);
    EXPECT_EQ(queue.total_rejected(), 1);
    EXPECT_EQ(queue.peak_watermark(), 2);
}

TEST_F(BoundedIngestionQueueTest, PopAndPopBatch) {
    BoundedIngestionQueue queue(5);

    EXPECT_TRUE(queue.try_push(create_sample_envelope("018f6e4a-7b3c-7000-8000-000000000001")));
    EXPECT_TRUE(queue.try_push(create_sample_envelope("018f6e4a-7b3c-7000-8000-000000000002")));
    EXPECT_TRUE(queue.try_push(create_sample_envelope("018f6e4a-7b3c-7000-8000-000000000003")));

    auto item = queue.pop(std::chrono::milliseconds(10));
    ASSERT_TRUE(item.has_value());
    EXPECT_EQ(item->event.event_id.to_string(), "018f6e4a-7b3c-7000-8000-000000000001");

    auto batch = queue.pop_batch(10, std::chrono::milliseconds(10));
    EXPECT_EQ(batch.size(), 2);
    EXPECT_EQ(queue.size(), 0);

    // Timeout pop on empty queue
    auto empty_item = queue.pop(std::chrono::milliseconds(5));
    EXPECT_FALSE(empty_item.has_value());
}

TEST_F(BoundedIngestionQueueTest, ShutdownWakesWaiters) {
    BoundedIngestionQueue queue(10);

    std::thread worker([&queue]() {
        auto item = queue.pop(std::chrono::milliseconds(5000));
        EXPECT_FALSE(item.has_value());
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    queue.shutdown();
    worker.join();

    EXPECT_TRUE(queue.is_shutdown());
    EXPECT_FALSE(queue.try_push(create_sample_envelope("018f6e4a-7b3c-7000-8000-000000000001")));
}

TEST_F(BoundedIngestionQueueTest, BackpressureStatusHelper) {
    grpc::ServerContext context;
    auto status = create_backpressure_status(&context);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
    EXPECT_NE(status.error_message().find("backpressure"), std::string::npos);
}

TEST_F(BoundedIngestionQueueTest, ConcurrentPushAndPop) {
    BoundedIngestionQueue queue(100);
    const int num_producers = 4;
    const int items_per_producer = 250;
    std::atomic<int> consumed_count{0};

    std::thread consumer([&queue, &consumed_count, total_items = num_producers * items_per_producer]() {
        while (consumed_count.load() < total_items) {
            auto batch = queue.pop_batch(50, std::chrono::milliseconds(10));
            consumed_count.fetch_add(static_cast<int>(batch.size()));
        }
    });

    std::vector<std::thread> producers;
    for (int p = 0; p < num_producers; ++p) {
        producers.emplace_back([&queue, p, items_per_producer]() {
            for (int i = 0; i < items_per_producer; ++i) {
                IngestionEnvelope env;
                env.event.event_type = "producer." + std::to_string(p);
                while (!queue.push_with_timeout(env, std::chrono::milliseconds(10))) {
                    std::this_thread::yield();
                }
            }
        });
    }

    for (auto& t : producers) {
        t.join();
    }
    consumer.join();

    EXPECT_EQ(consumed_count.load(), num_producers * items_per_producer);
    EXPECT_EQ(queue.total_enqueued(), static_cast<size_t>(num_producers * items_per_producer));
    EXPECT_EQ(queue.size(), 0);
}

} // namespace securecloud::audit::ingestion::testing