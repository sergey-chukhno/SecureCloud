#include "health/audit_health_evaluator.hpp"
#include "lifecycle/audit_service_state.hpp"
#include "securecloud/health/health_status_manager.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>

namespace securecloud::audit::lifecycle::testing {

class AuditServiceStateTest : public ::testing::Test {
  protected:
    void SetUp() override {
        health_manager_ = std::make_unique<common::health::HealthStatusManager>("audit");
        health_manager_->set_live(true);
    }

    std::unique_ptr<common::health::HealthStatusManager> health_manager_;
};

TEST_F(AuditServiceStateTest, StateToStringConversions) {
    EXPECT_EQ(to_string(DetailedServiceState::Ready), "Ready");
    EXPECT_EQ(to_string(DetailedServiceState::Degraded), "Degraded");
    EXPECT_EQ(to_string(DetailedServiceState::NotReady), "NotReady");
    EXPECT_EQ(to_string(DetailedServiceState::Draining), "Draining");

    EXPECT_EQ(to_string(StateTransitionReason::ClickHousePingTimeout), "ClickHousePingTimeout");
    EXPECT_EQ(to_string(StateTransitionReason::QueueSaturated), "QueueSaturated");
}

TEST_F(AuditServiceStateTest, HysteresisPreventsFlappingOnSingleFailure) {
    health::AuditHealthEvaluatorConfig config;
    config.auto_start = false;
    config.consecutive_failures_threshold = 3;

    health::AuditHealthEvaluator evaluator(
        *health_manager_, [](std::chrono::milliseconds) { return false; },
        [](uint32_t& out_pct) {
            out_pct = 10;
            return true;
        },
        config);

    // Initial evaluation passes by default (failures = 1)
    evaluator.evaluate_once();
    EXPECT_EQ(evaluator.detailed_state(), DetailedServiceState::Ready);

    // Second failure
    evaluator.evaluate_once();
    EXPECT_EQ(evaluator.detailed_state(), DetailedServiceState::Ready);

    // Third failure triggers Degraded transition
    evaluator.evaluate_once();
    EXPECT_EQ(evaluator.detailed_state(), DetailedServiceState::Degraded);
    EXPECT_EQ(evaluator.last_transition_reason(), StateTransitionReason::ClickHousePingTimeout);
}

TEST_F(AuditServiceStateTest, HysteresisRequiresConsecutiveSuccessesToRecover) {
    health::AuditHealthEvaluatorConfig config;
    config.auto_start = false;
    config.consecutive_failures_threshold = 1;
    config.consecutive_successes_threshold = 2;

    std::atomic<bool> ch_healthy{false};

    health::AuditHealthEvaluator evaluator(
        *health_manager_, [&ch_healthy](std::chrono::milliseconds) { return ch_healthy.load(); },
        [](uint32_t& out_pct) {
            out_pct = 10;
            return true;
        },
        config);

    // Immediately degraded
    evaluator.evaluate_once();
    EXPECT_EQ(evaluator.detailed_state(), DetailedServiceState::Degraded);

    // Single success is not enough
    ch_healthy.store(true);
    evaluator.evaluate_once();
    EXPECT_EQ(evaluator.detailed_state(), DetailedServiceState::Degraded);

    // Second consecutive success restores Ready
    evaluator.evaluate_once();
    EXPECT_EQ(evaluator.detailed_state(), DetailedServiceState::Ready);
    EXPECT_EQ(evaluator.last_transition_reason(), StateTransitionReason::ClickHouseRecovered);
}

TEST_F(AuditServiceStateTest, QueueHighWaterAndLowWaterHysteresis) {
    health::AuditHealthEvaluatorConfig config;
    config.auto_start = false;
    config.queue_high_water_pct = 90;
    config.queue_low_water_pct = 80;

    std::atomic<uint32_t> occupancy{50};

    health::AuditHealthEvaluator evaluator(
        *health_manager_, [](std::chrono::milliseconds) { return true; },
        [&occupancy](uint32_t& out_pct) {
            out_pct = occupancy.load();
            return true;
        },
        config);

    evaluator.evaluate_once();
    EXPECT_EQ(evaluator.detailed_state(), DetailedServiceState::Ready);

    // Exceed high water -> Immediate degradation
    occupancy.store(92);
    evaluator.evaluate_once();
    EXPECT_EQ(evaluator.detailed_state(), DetailedServiceState::Degraded);
    EXPECT_EQ(evaluator.last_transition_reason(), StateTransitionReason::QueueSaturated);

    // Drop to 85% (between low and high water) -> Remains Degraded
    occupancy.store(85);
    evaluator.evaluate_once();
    EXPECT_EQ(evaluator.detailed_state(), DetailedServiceState::Degraded);

    // Drop below low water (< 80%) -> Restores Ready
    occupancy.store(75);
    evaluator.evaluate_once();
    EXPECT_EQ(evaluator.detailed_state(), DetailedServiceState::Ready);
    EXPECT_EQ(evaluator.last_transition_reason(), StateTransitionReason::QueueDrained);
}

} // namespace securecloud::audit::lifecycle::testing
