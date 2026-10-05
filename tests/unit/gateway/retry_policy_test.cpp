#include "grpc/dependency_error.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/retry_policy.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <vector>

namespace securecloud::gateway::http {
namespace {

TEST(RetryPolicyTest, DefaultConfigValues) {
    RetryPolicy policy;
    const auto& cfg = policy.config();

    EXPECT_EQ(cfg.max_attempts, 3u);
    EXPECT_EQ(cfg.initial_backoff_ms, 100u);
    EXPECT_DOUBLE_EQ(cfg.backoff_multiplier, 2.0);
    EXPECT_EQ(cfg.max_backoff_ms, 1000u);
    EXPECT_DOUBLE_EQ(cfg.jitter_ratio, 0.25);
    EXPECT_FALSE(cfg.retry_on_deadline_exceeded);
}

TEST(RetryPolicyTest, StatusRetryabilityMatrix) {
    RetryPolicy policy;

    // Transient failure is retryable
    EXPECT_TRUE(policy.is_status_retryable(::grpc::StatusCode::UNAVAILABLE));

    // Deadline exceeded is not retryable by default
    EXPECT_FALSE(policy.is_status_retryable(::grpc::StatusCode::DEADLINE_EXCEEDED));

    // Permanent errors are non-retryable
    EXPECT_FALSE(policy.is_status_retryable(::grpc::StatusCode::INVALID_ARGUMENT));
    EXPECT_FALSE(policy.is_status_retryable(::grpc::StatusCode::NOT_FOUND));
    EXPECT_FALSE(policy.is_status_retryable(::grpc::StatusCode::ALREADY_EXISTS));
    EXPECT_FALSE(policy.is_status_retryable(::grpc::StatusCode::PERMISSION_DENIED));
    EXPECT_FALSE(policy.is_status_retryable(::grpc::StatusCode::UNAUTHENTICATED));
    EXPECT_FALSE(policy.is_status_retryable(::grpc::StatusCode::FAILED_PRECONDITION));
    EXPECT_FALSE(policy.is_status_retryable(::grpc::StatusCode::INTERNAL));
    EXPECT_FALSE(policy.is_status_retryable(::grpc::StatusCode::OK));

    // When deadline retry is explicitly enabled
    RetryPolicyConfig cfg;
    cfg.retry_on_deadline_exceeded = true;
    RetryPolicy deadline_policy(cfg);
    EXPECT_TRUE(deadline_policy.is_status_retryable(::grpc::StatusCode::DEADLINE_EXCEEDED));
}

TEST(RetryPolicyTest, ShouldRetryDecisions) {
    RetryPolicy policy;

    // Safe read-only retries on UNAVAILABLE if attempts remaining
    EXPECT_TRUE(policy.should_retry(OperationIdempotency::SAFE_READONLY, ::grpc::StatusCode::UNAVAILABLE, 1));
    EXPECT_TRUE(policy.should_retry(OperationIdempotency::SAFE_READONLY, ::grpc::StatusCode::UNAVAILABLE, 2));
    EXPECT_FALSE(policy.should_retry(OperationIdempotency::SAFE_READONLY, ::grpc::StatusCode::UNAVAILABLE, 3));

    // Idempotent mutation retries on UNAVAILABLE if attempts remaining
    EXPECT_TRUE(policy.should_retry(OperationIdempotency::IDEMPOTENT_MUTATION, ::grpc::StatusCode::UNAVAILABLE, 1));
    EXPECT_TRUE(policy.should_retry(OperationIdempotency::IDEMPOTENT_MUTATION, ::grpc::StatusCode::UNAVAILABLE, 2));
    EXPECT_FALSE(policy.should_retry(OperationIdempotency::IDEMPOTENT_MUTATION, ::grpc::StatusCode::UNAVAILABLE, 3));

    // Non-idempotent operations NEVER retry even on first attempt
    EXPECT_FALSE(policy.should_retry(OperationIdempotency::NON_IDEMPOTENT, ::grpc::StatusCode::UNAVAILABLE, 1));
    EXPECT_FALSE(policy.should_retry(OperationIdempotency::NON_IDEMPOTENT, ::grpc::StatusCode::UNAVAILABLE, 2));

    // Safe read-only does NOT retry permanent errors
    EXPECT_FALSE(policy.should_retry(OperationIdempotency::SAFE_READONLY, ::grpc::StatusCode::INVALID_ARGUMENT, 1));
    EXPECT_FALSE(policy.should_retry(OperationIdempotency::SAFE_READONLY, ::grpc::StatusCode::UNAUTHENTICATED, 1));
}

TEST(RetryPolicyTest, BackoffDelayExponentialAndJitterBounds) {
    RetryPolicyConfig cfg;
    cfg.initial_backoff_ms = 100;
    cfg.backoff_multiplier = 2.0;
    cfg.max_backoff_ms = 1000;
    cfg.jitter_ratio = 0.25;

    // Zero jitter test
    RetryPolicy zero_jitter_policy(cfg, nullptr, [] { return 0.0; });
    EXPECT_EQ(zero_jitter_policy.compute_backoff_delay(1).count(), 100);
    EXPECT_EQ(zero_jitter_policy.compute_backoff_delay(2).count(), 200);
    EXPECT_EQ(zero_jitter_policy.compute_backoff_delay(3).count(), 400);
    EXPECT_EQ(zero_jitter_policy.compute_backoff_delay(4).count(), 800);
    EXPECT_EQ(zero_jitter_policy.compute_backoff_delay(5).count(), 1000); // capped at 1000ms

    // Max positive jitter test (+25%)
    RetryPolicy max_pos_jitter(cfg, nullptr, [] { return 1.0; });
    EXPECT_EQ(max_pos_jitter.compute_backoff_delay(1).count(), 125);
    EXPECT_EQ(max_pos_jitter.compute_backoff_delay(2).count(), 250);

    // Max negative jitter test (-25%)
    RetryPolicy max_neg_jitter(cfg, nullptr, [] { return -1.0; });
    EXPECT_EQ(max_neg_jitter.compute_backoff_delay(1).count(), 75);
    EXPECT_EQ(max_neg_jitter.compute_backoff_delay(2).count(), 150);
}

TEST(RetryPolicyTest, ExecuteSucceedsOnFirstAttempt) {
    DeadlineManager deadline_mgr;
    RetryPolicy policy;

    const auto start_tp = deadline_mgr.now();
    const auto effective_deadline = std::chrono::milliseconds(5000);
    const auto service_timeout = std::chrono::milliseconds(1000);

    int invocations = 0;
    auto res =
        policy.execute(deadline_mgr, start_tp, effective_deadline, service_timeout, OperationIdempotency::SAFE_READONLY,
                       [&](std::chrono::milliseconds budget) -> grpc::Result<std::string> {
                           ++invocations;
                           EXPECT_GT(budget.count(), 0);
                           return grpc::Result<std::string>(std::string("hello"));
                       });

    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value(), "hello");
    EXPECT_EQ(invocations, 1);
}

TEST(RetryPolicyTest, ExecuteRetriesOnTransientUnavailableAndSucceeds) {
    DeadlineManager deadline_mgr;
    std::vector<std::chrono::milliseconds> slept_durations;
    auto sleep_fn = [&](std::chrono::milliseconds d) { slept_durations.push_back(d); };

    RetryPolicy policy({}, sleep_fn, [] { return 0.0; });

    const auto start_tp = deadline_mgr.now();
    const auto effective_deadline = std::chrono::milliseconds(5000);
    const auto service_timeout = std::chrono::milliseconds(1000);

    int invocations = 0;
    auto res =
        policy.execute(deadline_mgr, start_tp, effective_deadline, service_timeout, OperationIdempotency::SAFE_READONLY,
                       [&](std::chrono::milliseconds /*budget*/) -> grpc::Result<std::string> {
                           ++invocations;
                           if (invocations == 1) {
                               return grpc::Result<std::string>(grpc::DependencyError{
                                   .kind = grpc::DependencyErrorKind::ServiceUnavailable,
                                   .message = "Transient connection reset",
                                   .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
                               });
                           }
                           return grpc::Result<std::string>(std::string("success-after-retry"));
                       });

    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value(), "success-after-retry");
    EXPECT_EQ(invocations, 2);
    ASSERT_EQ(slept_durations.size(), 1u);
    EXPECT_EQ(slept_durations[0].count(), 100);
}

TEST(RetryPolicyTest, ExecuteExhaustsMaxAttemptsAndReturnsLastError) {
    DeadlineManager deadline_mgr;
    std::vector<std::chrono::milliseconds> slept_durations;
    auto sleep_fn = [&](std::chrono::milliseconds d) { slept_durations.push_back(d); };

    RetryPolicy policy({}, sleep_fn, [] { return 0.0; });

    const auto start_tp = deadline_mgr.now();
    const auto effective_deadline = std::chrono::milliseconds(5000);
    const auto service_timeout = std::chrono::milliseconds(1000);

    int invocations = 0;
    auto res =
        policy.execute(deadline_mgr, start_tp, effective_deadline, service_timeout, OperationIdempotency::SAFE_READONLY,
                       [&](std::chrono::milliseconds /*budget*/) -> grpc::Result<std::string> {
                           ++invocations;
                           return grpc::Result<std::string>(grpc::DependencyError{
                               .kind = grpc::DependencyErrorKind::ServiceUnavailable,
                               .message = "Persistent outage",
                               .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
                           });
                       });

    ASSERT_TRUE(res.has_error());
    EXPECT_EQ(res.error().grpc_code, ::grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(invocations, 3);             // Max attempts is 3
    EXPECT_EQ(slept_durations.size(), 2u); // Slept twice (before attempt 2 and attempt 3)
}

TEST(RetryPolicyTest, ExecuteNonIdempotentFailsFastWithoutRetrying) {
    DeadlineManager deadline_mgr;
    std::vector<std::chrono::milliseconds> slept_durations;
    auto sleep_fn = [&](std::chrono::milliseconds d) { slept_durations.push_back(d); };

    RetryPolicy policy({}, sleep_fn, [] { return 0.0; });

    const auto start_tp = deadline_mgr.now();
    const auto effective_deadline = std::chrono::milliseconds(5000);
    const auto service_timeout = std::chrono::milliseconds(1000);

    int invocations = 0;
    auto res = policy.execute(deadline_mgr, start_tp, effective_deadline, service_timeout,
                              OperationIdempotency::NON_IDEMPOTENT,
                              [&](std::chrono::milliseconds /*budget*/) -> grpc::Result<std::string> {
                                  ++invocations;
                                  return grpc::Result<std::string>(grpc::DependencyError{
                                      .kind = grpc::DependencyErrorKind::ServiceUnavailable,
                                      .message = "Unavailable during mutation",
                                      .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
                                  });
                              });

    ASSERT_TRUE(res.has_error());
    EXPECT_EQ(res.error().grpc_code, ::grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(invocations, 1); // Strictly 1 attempt!
    EXPECT_TRUE(slept_durations.empty());
}

TEST(RetryPolicyTest, ExecuteAbortsRetryWhenDeadlineBudgetIsExhausted) {
    auto t0 = std::chrono::steady_clock::now();
    int clock_calls = 0;
    auto clock_fn = [t0, clock_calls]() mutable -> std::chrono::steady_clock::time_point {
        ++clock_calls;
        if (clock_calls == 1) {
            return t0;
        }
        // Advance clock so that remaining budget is smaller than backoff + floor
        return t0 + std::chrono::milliseconds(450);
    };

    DeadlineManager deadline_mgr({}, clock_fn);

    std::vector<std::chrono::milliseconds> slept_durations;
    auto sleep_fn = [&](std::chrono::milliseconds d) { slept_durations.push_back(d); };
    RetryPolicy policy({}, sleep_fn, [] { return 0.0; });

    const auto start_tp = t0;
    const auto effective_deadline = std::chrono::milliseconds(500); // 500ms total deadline
    const auto service_timeout = std::chrono::milliseconds(500);

    int invocations = 0;
    auto res =
        policy.execute(deadline_mgr, start_tp, effective_deadline, service_timeout, OperationIdempotency::SAFE_READONLY,
                       [&](std::chrono::milliseconds /*budget*/) -> grpc::Result<std::string> {
                           ++invocations;
                           return grpc::Result<std::string>(grpc::DependencyError{
                               .kind = grpc::DependencyErrorKind::ServiceUnavailable,
                               .message = "Unavailable near deadline expiration",
                               .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
                           });
                       });

    ASSERT_TRUE(res.has_error());
    // Only 1 attempt because after attempt 1 elapsed time (450ms) + backoff (100ms) + min floor (50ms) > 500ms
    EXPECT_EQ(invocations, 1);
    EXPECT_TRUE(slept_durations.empty());
}

} // namespace
} // namespace securecloud::gateway::http
