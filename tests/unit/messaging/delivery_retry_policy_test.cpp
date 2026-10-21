#include "domain/delivery_types.hpp"
#include "service/delivery_retry_policy.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <vector>

namespace securecloud::messaging::service {
namespace {

using domain::DeliveryAttemptResult;
using namespace std::chrono_literals;

class MockRandomGenerator : public IRandomGenerator {
  public:
    enum class Mode { Min, Mid, Max };
    explicit MockRandomGenerator(Mode mode = Mode::Mid) : mode_(mode) {}

    void set_mode(Mode mode) { mode_ = mode; }

    double generate_uniform(double min, double max) override {
        switch (mode_) {
        case Mode::Min:
            return min;
        case Mode::Mid:
            return (min + max) / 2.0;
        case Mode::Max:
            return max;
        }
        return (min + max) / 2.0;
    }

  private:
    Mode mode_;
};

TEST(DeliveryRetryConfigTest, DefaultConfigIsValid) {
    DeliveryRetryConfig config;
    EXPECT_TRUE(config.validate());
    EXPECT_EQ(config.initial_backoff, 500ms);
    EXPECT_EQ(config.max_backoff, 60000ms);
    EXPECT_DOUBLE_EQ(config.backoff_multiplier, 2.0);
    EXPECT_EQ(config.max_retry_attempts, 10);
    EXPECT_DOUBLE_EQ(config.jitter_factor, 0.25);
}

TEST(DeliveryRetryConfigTest, InvalidParametersRejected) {
    {
        DeliveryRetryConfig cfg;
        cfg.initial_backoff = 0ms;
        EXPECT_FALSE(cfg.validate());
        EXPECT_THROW((void)DeliveryRetryPolicy(cfg), std::invalid_argument);
    }
    {
        DeliveryRetryConfig cfg;
        cfg.max_backoff = 100ms;
        cfg.initial_backoff = 500ms;
        EXPECT_FALSE(cfg.validate());
        EXPECT_THROW((void)DeliveryRetryPolicy(cfg), std::invalid_argument);
    }
    {
        DeliveryRetryConfig cfg;
        cfg.backoff_multiplier = 0.5;
        EXPECT_FALSE(cfg.validate());
        EXPECT_THROW((void)DeliveryRetryPolicy(cfg), std::invalid_argument);
    }
    {
        DeliveryRetryConfig cfg;
        cfg.max_retry_attempts = -1;
        EXPECT_FALSE(cfg.validate());
        EXPECT_THROW((void)DeliveryRetryPolicy(cfg), std::invalid_argument);
    }
    {
        DeliveryRetryConfig cfg;
        cfg.jitter_factor = -0.1;
        EXPECT_FALSE(cfg.validate());
        EXPECT_THROW((void)DeliveryRetryPolicy(cfg), std::invalid_argument);
    }
    {
        DeliveryRetryConfig cfg;
        cfg.jitter_factor = 1.1;
        EXPECT_FALSE(cfg.validate());
        EXPECT_THROW((void)DeliveryRetryPolicy(cfg), std::invalid_argument);
    }
}

TEST(DeliveryRetryPolicyTest, ExponentialProgressionWithoutJitter) {
    auto mock_rng = std::make_shared<MockRandomGenerator>(MockRandomGenerator::Mode::Mid);
    DeliveryRetryConfig cfg;
    cfg.initial_backoff = 500ms;
    cfg.max_backoff = 60000ms;
    cfg.backoff_multiplier = 2.0;
    cfg.jitter_factor = 0.25;

    DeliveryRetryPolicy policy(cfg, mock_rng);

    EXPECT_EQ(policy.compute_next_delay(0), 500ms);
    EXPECT_EQ(policy.compute_next_delay(1), 1000ms);
    EXPECT_EQ(policy.compute_next_delay(2), 2000ms);
    EXPECT_EQ(policy.compute_next_delay(3), 4000ms);
    EXPECT_EQ(policy.compute_next_delay(4), 8000ms);
    EXPECT_EQ(policy.compute_next_delay(5), 16000ms);
    EXPECT_EQ(policy.compute_next_delay(6), 32000ms);
    EXPECT_EQ(policy.compute_next_delay(7), 60000ms);   // Capped at max_backoff
    EXPECT_EQ(policy.compute_next_delay(8), 60000ms);   // Remains capped
    EXPECT_EQ(policy.compute_next_delay(100), 60000ms); // Clamped without integer overflow
    EXPECT_EQ(policy.compute_next_delay(-5), 500ms);    // Clamped negative attempt to 0
}

TEST(DeliveryRetryPolicyTest, JitterBoundsEnforcement) {
    auto mock_rng = std::make_shared<MockRandomGenerator>();
    DeliveryRetryConfig cfg;
    cfg.initial_backoff = 1000ms;
    cfg.max_backoff = 10000ms;
    cfg.backoff_multiplier = 2.0;
    cfg.jitter_factor = 0.20; // +/- 20%

    DeliveryRetryPolicy policy(cfg, mock_rng);

    // Attempt 0: base 1000ms, window [800ms, 1200ms]
    mock_rng->set_mode(MockRandomGenerator::Mode::Min);
    EXPECT_EQ(policy.compute_next_delay(0), 800ms);

    mock_rng->set_mode(MockRandomGenerator::Mode::Max);
    EXPECT_EQ(policy.compute_next_delay(0), 1200ms);

    mock_rng->set_mode(MockRandomGenerator::Mode::Mid);
    EXPECT_EQ(policy.compute_next_delay(0), 1000ms);

    // Attempt 1: base 2000ms, window [1600ms, 2400ms]
    mock_rng->set_mode(MockRandomGenerator::Mode::Min);
    EXPECT_EQ(policy.compute_next_delay(1), 1600ms);

    mock_rng->set_mode(MockRandomGenerator::Mode::Max);
    EXPECT_EQ(policy.compute_next_delay(1), 2400ms);
}

TEST(DeliveryRetryPolicyTest, StandardRngGeneratesValuesWithinDecorrelatedBounds) {
    DeliveryRetryConfig cfg;
    cfg.initial_backoff = 1000ms;
    cfg.max_backoff = 10000ms;
    cfg.backoff_multiplier = 2.0;
    cfg.jitter_factor = 0.25;

    DeliveryRetryPolicy policy(cfg);

    for (int i = 0; i < 100; ++i) {
        auto delay = policy.compute_next_delay(1); // base 2000ms, window [1500ms, 2500ms]
        EXPECT_GE(delay, 1500ms);
        EXPECT_LE(delay, 2500ms);
    }
}

TEST(DeliveryRetryPolicyTest, IsRetryableRules) {
    DeliveryRetryConfig cfg;
    cfg.max_retry_attempts = 3;
    DeliveryRetryPolicy policy(cfg);

    const auto now = std::chrono::system_clock::now();
    const auto future = now + 1h;
    const auto past = now - 10s;

    // Success and Terminal Failure are never retryable
    EXPECT_FALSE(policy.is_retryable(DeliveryAttemptResult::Success, 0, future, now));
    EXPECT_FALSE(policy.is_retryable(DeliveryAttemptResult::TerminalFailure, 0, future, now));

    // Transient failure is retryable when within attempt and expiry limits
    EXPECT_TRUE(policy.is_retryable(DeliveryAttemptResult::TransientFailure, 0, future, now));
    EXPECT_TRUE(policy.is_retryable(DeliveryAttemptResult::TransientFailure, 1, future, now));
    EXPECT_TRUE(policy.is_retryable(DeliveryAttemptResult::TransientFailure, 2, future, now));
    EXPECT_FALSE(policy.is_retryable(DeliveryAttemptResult::TransientFailure, 3, future, now)); // Reached max
    EXPECT_FALSE(policy.is_retryable(DeliveryAttemptResult::TransientFailure, 4, future, now));

    // Recipient offline is retryable when within attempt and expiry limits
    EXPECT_TRUE(policy.is_retryable(DeliveryAttemptResult::RecipientOffline, 0, future, now));
    EXPECT_TRUE(policy.is_retryable(DeliveryAttemptResult::RecipientOffline, 2, future, now));
    EXPECT_FALSE(policy.is_retryable(DeliveryAttemptResult::RecipientOffline, 3, future, now));

    // Expiration checks
    EXPECT_FALSE(policy.is_retryable(DeliveryAttemptResult::TransientFailure, 0, past, now));
    EXPECT_FALSE(policy.is_retryable(DeliveryAttemptResult::TransientFailure, 0, now, now));
    EXPECT_TRUE(policy.is_retryable(DeliveryAttemptResult::TransientFailure, 0, std::nullopt, now));
}

} // namespace
} // namespace securecloud::messaging::service
