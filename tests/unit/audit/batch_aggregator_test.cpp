#include "ingestion/batch_aggregator.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

namespace securecloud::audit::ingestion::testing {

class BatchAggregatorTest : public ::testing::Test {
  protected:
    IngestionEnvelope create_sample_envelope(size_t index) {
        IngestionEnvelope env;
        env.event.event_type = "batch.test.event." + std::to_string(index);
        return env;
    }
};

TEST_F(BatchAggregatorTest, CountTriggerFlushesBatchImmediately) {
    auto input_q = std::make_shared<BoundedIngestionQueue>(100);
    auto batch_q = std::make_shared<BoundedBatchQueue>(10);

    // Max size: 5 events, Max delay: 5000 ms
    BatchAggregator aggregator(5, std::chrono::milliseconds(5000), input_q, batch_q);
    aggregator.start();

    for (size_t i = 0; i < 5; ++i) {
        EXPECT_TRUE(input_q->try_push(create_sample_envelope(i)));
    }

    auto batch_opt = batch_q->pop(std::chrono::milliseconds(1000));
    ASSERT_TRUE(batch_opt.has_value());
    EXPECT_EQ(batch_opt->size(), 5);
    EXPECT_EQ(aggregator.total_count_triggers(), 1);
    EXPECT_EQ(aggregator.total_timer_triggers(), 0);

    aggregator.stop();
}

TEST_F(BatchAggregatorTest, TimeTriggerFlushesTrickleTraffic) {
    auto input_q = std::make_shared<BoundedIngestionQueue>(100);
    auto batch_q = std::make_shared<BoundedBatchQueue>(10);

    // Max size: 100 events, Max delay: 50 ms
    BatchAggregator aggregator(100, std::chrono::milliseconds(50), input_q, batch_q);
    aggregator.start();

    // Push only 2 events (below count threshold)
    EXPECT_TRUE(input_q->try_push(create_sample_envelope(1)));
    EXPECT_TRUE(input_q->try_push(create_sample_envelope(2)));

    auto start_time = std::chrono::steady_clock::now();
    auto batch_opt = batch_q->pop(std::chrono::milliseconds(1000));
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time);

    ASSERT_TRUE(batch_opt.has_value());
    EXPECT_EQ(batch_opt->size(), 2);
    EXPECT_LE(duration.count(), 300); // Margin for MinGW scheduler
    EXPECT_EQ(aggregator.total_timer_triggers(), 1);
    EXPECT_EQ(aggregator.total_count_triggers(), 0);

    aggregator.stop();
}

TEST_F(BatchAggregatorTest, FlushesRemainingBatchOnShutdown) {
    auto input_q = std::make_shared<BoundedIngestionQueue>(100);
    auto batch_q = std::make_shared<BoundedBatchQueue>(10);

    BatchAggregator aggregator(100, std::chrono::milliseconds(10000), input_q, batch_q);
    aggregator.start();

    EXPECT_TRUE(input_q->try_push(create_sample_envelope(1)));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    aggregator.stop();

    auto batch_opt = batch_q->pop(std::chrono::milliseconds(100));
    ASSERT_TRUE(batch_opt.has_value());
    EXPECT_EQ(batch_opt->size(), 1);
}

} // namespace securecloud::audit::ingestion::testing