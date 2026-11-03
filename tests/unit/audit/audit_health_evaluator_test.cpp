#include "health/audit_health_evaluator.hpp"
#include "securecloud/health/health_status_manager.hpp"

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <thread>

namespace securecloud::audit::health::testing {

class AuditHealthEvaluatorTest : public ::testing::Test {
  protected:
    void SetUp() override {
        health_manager_ = std::make_unique<common::health::HealthStatusManager>("audit");
        health_manager_->set_live(true);
    }

    std::unique_ptr<common::health::HealthStatusManager> health_manager_;
};

TEST_F(AuditHealthEvaluatorTest, EvaluatesHealthyWhenClickHouseAndQueueNormal) {
    AuditHealthEvaluatorConfig config;
    config.auto_start = false;

    AuditHealthEvaluator evaluator(
        *health_manager_,
        [](std::chrono::milliseconds) { return true; },
        [](uint32_t& out_pct) {
            out_pct = 10;
            return true;
        },
        config);

    bool ready = evaluator.evaluate_once();

    EXPECT_TRUE(ready);
    EXPECT_TRUE(evaluator.is_clickhouse_healthy());
    EXPECT_TRUE(evaluator.is_queue_healthy());
    EXPECT_TRUE(evaluator.is_ready());
    EXPECT_TRUE(health_manager_->is_ready());
}

TEST_F(AuditHealthEvaluatorTest, TransitionsToNotReadyOnConsecutiveClickHouseFailures) {
    AuditHealthEvaluatorConfig config;
    config.auto_start = false;
    config.consecutive_failures_threshold = 3;

    AuditHealthEvaluator evaluator(
        *health_manager_,
        [](std::chrono::milliseconds) { return false; },
        [](uint32_t& out_pct) {
            out_pct = 10;
            return true;
        },
        config);

    // Iteration 1 failure
    evaluator.evaluate_once();
    EXPECT_TRUE(evaluator.is_clickhouse_healthy()); // Not marked unready until threshold reached

    // Iteration 2 failure
    evaluator.evaluate_once();
    EXPECT_TRUE(evaluator.is_clickhouse_healthy());

    // Iteration 3 failure (threshold reached)
    bool ready = evaluator.evaluate_once();
    EXPECT_FALSE(ready);
    EXPECT_FALSE(evaluator.is_clickhouse_healthy());
    EXPECT_FALSE(evaluator.is_ready());
    EXPECT_FALSE(health_manager_->is_ready());
}

TEST_F(AuditHealthEvaluatorTest, TransitionsToNotReadyOnQueueHighWaterExceeded) {
    AuditHealthEvaluatorConfig config;
    config.auto_start = false;
    config.queue_high_water_pct = 90;

    AuditHealthEvaluator evaluator(
        *health_manager_,
        [](std::chrono::milliseconds) { return true; },
        [](uint32_t& out_pct) {
            out_pct = 95; // Exceeds 90% threshold
            return true;
        },
        config);

    bool ready = evaluator.evaluate_once();

    EXPECT_FALSE(ready);
    EXPECT_TRUE(evaluator.is_clickhouse_healthy());
    EXPECT_FALSE(evaluator.is_queue_healthy());
    EXPECT_FALSE(evaluator.is_ready());
    EXPECT_FALSE(health_manager_->is_ready());
}

TEST_F(AuditHealthEvaluatorTest, RecoversReadinessWhenClickHouseAndQueueRestored) {
    AuditHealthEvaluatorConfig config;
    config.auto_start = false;
    config.consecutive_failures_threshold = 1;

    std::atomic<bool> ch_probe_result{false};
    std::atomic<uint32_t> queue_occupancy{95};

    AuditHealthEvaluator evaluator(
        *health_manager_,
        [&ch_probe_result](std::chrono::milliseconds) { return ch_probe_result.load(); },
        [&queue_occupancy](uint32_t& out_pct) {
            out_pct = queue_occupancy.load();
            return true;
        },
        config);

    // Initial failing evaluation
    evaluator.evaluate_once();
    EXPECT_FALSE(evaluator.is_ready());

    // Recover dependencies
    ch_probe_result.store(true);
    queue_occupancy.store(20);

    evaluator.evaluate_once();
    EXPECT_TRUE(evaluator.is_ready());
    EXPECT_TRUE(evaluator.is_clickhouse_healthy());
    EXPECT_TRUE(evaluator.is_queue_healthy());
    EXPECT_TRUE(health_manager_->is_ready());
}

TEST_F(AuditHealthEvaluatorTest, BackgroundThreadStartsAndStopsCleanly) {
    AuditHealthEvaluatorConfig config;
    config.check_interval = std::chrono::milliseconds(20);
    config.auto_start = true;

    AuditHealthEvaluator evaluator(
        *health_manager_,
        [](std::chrono::milliseconds) { return true; },
        [](uint32_t& out_pct) {
            out_pct = 5;
            return true;
        },
        config);

    EXPECT_TRUE(evaluator.is_running());

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_TRUE(evaluator.is_ready());

    evaluator.stop();
    EXPECT_FALSE(evaluator.is_running());
}

} // namespace securecloud::audit::health::testing
