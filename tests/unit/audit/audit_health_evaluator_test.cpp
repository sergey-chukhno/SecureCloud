#include "health/audit_health_evaluator.hpp"
#include "securecloud/health/health_status_manager.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <gtest/gtest.h>
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

// Test 1: Initial State & Startup Probing
TEST_F(AuditHealthEvaluatorTest, InitialStateIsNotReadyUntilEvaluationSucceeds) {
    EXPECT_FALSE(health_manager_->is_ready());

    AuditHealthEvaluatorConfig config;
    config.auto_start = false;

    AuditHealthEvaluator evaluator(
        *health_manager_, [](std::chrono::milliseconds) { return true; },
        [](uint32_t& out_pct) {
            out_pct = 10;
            return true;
        },
        config);

    EXPECT_FALSE(evaluator.is_ready());
    EXPECT_FALSE(health_manager_->is_ready());

    bool ready = evaluator.evaluate_once();

    EXPECT_TRUE(ready);
    EXPECT_TRUE(evaluator.is_clickhouse_healthy());
    EXPECT_TRUE(evaluator.is_queue_healthy());
    EXPECT_TRUE(evaluator.is_ready());
    EXPECT_TRUE(health_manager_->is_ready());
}

// Test 2: ClickHouse Responsiveness & Flapping Hysteresis (3 failures required)
TEST_F(AuditHealthEvaluatorTest, FlappingHysteresisRequiresThreeConsecutiveFailuresToDegrade) {
    AuditHealthEvaluatorConfig config;
    config.auto_start = false;
    config.consecutive_failures_threshold = 3;

    AuditHealthEvaluator evaluator(
        *health_manager_, [](std::chrono::milliseconds) { return false; },
        [](uint32_t& out_pct) {
            out_pct = 10;
            return true;
        },
        config);

    // Initial successful state
    health_manager_->set_ready(true);

    // 1st failure: should NOT degrade readiness yet
    evaluator.evaluate_once();
    EXPECT_TRUE(evaluator.is_clickhouse_healthy());
    EXPECT_TRUE(evaluator.is_ready());

    // 2nd failure: still NOT degraded
    evaluator.evaluate_once();
    EXPECT_TRUE(evaluator.is_clickhouse_healthy());
    EXPECT_TRUE(evaluator.is_ready());

    // 3rd failure: threshold reached, degrades to NOT_SERVING
    bool ready = evaluator.evaluate_once();
    EXPECT_FALSE(ready);
    EXPECT_FALSE(evaluator.is_clickhouse_healthy());
    EXPECT_FALSE(evaluator.is_ready());
    EXPECT_FALSE(health_manager_->is_ready());
}

// Test 3: ClickHouse Outage Recovery (2 consecutive successful pings required)
TEST_F(AuditHealthEvaluatorTest, OutageRecoveryRequiresTwoConsecutiveSuccessesToRestore) {
    AuditHealthEvaluatorConfig config;
    config.auto_start = false;
    config.consecutive_failures_threshold = 1;
    config.consecutive_successes_threshold = 2;

    std::atomic<bool> ch_healthy{false};

    AuditHealthEvaluator evaluator(
        *health_manager_, [&ch_healthy](std::chrono::milliseconds) { return ch_healthy.load(); },
        [](uint32_t& out_pct) {
            out_pct = 10;
            return true;
        },
        config);

    // Initial failure drops readiness
    evaluator.evaluate_once();
    EXPECT_FALSE(evaluator.is_ready());

    // Restore ClickHouse connection
    ch_healthy.store(true);

    // 1st successful probe: not yet restored (hysteresis)
    evaluator.evaluate_once();
    EXPECT_FALSE(evaluator.is_ready());

    // 2nd successful probe: restored to SERVING
    evaluator.evaluate_once();
    EXPECT_TRUE(evaluator.is_ready());
    EXPECT_TRUE(evaluator.is_clickhouse_healthy());
    EXPECT_TRUE(health_manager_->is_ready());
}

// Test 4: Queue Saturation Threshold (>=90% drops readiness, <80% restores)
TEST_F(AuditHealthEvaluatorTest, QueueSaturationThresholdTransitionsImmediately) {
    AuditHealthEvaluatorConfig config;
    config.auto_start = false;
    config.queue_high_water_pct = 90;
    config.queue_low_water_pct = 80;

    std::atomic<uint32_t> queue_occupancy{10};

    AuditHealthEvaluator evaluator(
        *health_manager_, [](std::chrono::milliseconds) { return true; },
        [&queue_occupancy](uint32_t& out_pct) {
            out_pct = queue_occupancy.load();
            return true;
        },
        config);

    evaluator.evaluate_once();
    EXPECT_TRUE(evaluator.is_ready());

    // Queue reaches 92% (>= 90%)
    queue_occupancy.store(92);
    evaluator.evaluate_once();
    EXPECT_FALSE(evaluator.is_ready());
    EXPECT_FALSE(evaluator.is_queue_healthy());

    // Queue drops to 85% (still above low water mark 80%)
    queue_occupancy.store(85);
    evaluator.evaluate_once();
    EXPECT_FALSE(evaluator.is_ready());

    // Queue drops to 75% (< 80% low water mark)
    queue_occupancy.store(75);
    evaluator.evaluate_once();
    EXPECT_TRUE(evaluator.is_ready());
    EXPECT_TRUE(evaluator.is_queue_healthy());
}

// Test 5: Non-Blocking Evaluation Property
TEST_F(AuditHealthEvaluatorTest, ProbeTimeoutDoesNotBlockConcurrentStatusQueries) {
    AuditHealthEvaluatorConfig config;
    config.auto_start = false;
    config.probe_timeout = std::chrono::milliseconds(500);

    // Probe that simulates a hanging probe (200ms delay)
    AuditHealthEvaluator evaluator(
        *health_manager_,
        [](std::chrono::milliseconds) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            return true;
        },
        [](uint32_t& out_pct) {
            out_pct = 10;
            return true;
        },
        config);

    evaluator.evaluate_once();

    // Query status concurrently while probe thread runs
    auto start_time = std::chrono::steady_clock::now();
    auto fut = std::async(std::launch::async, [&evaluator]() { return evaluator.is_ready(); });

    bool status = fut.get();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time);

    EXPECT_TRUE(status);
    EXPECT_LT(duration.count(), 50); // Status query must return almost instantly (< 50ms)
}

} // namespace securecloud::audit::health::testing
