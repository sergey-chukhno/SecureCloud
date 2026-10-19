#pragma once

#include "grpc/dependency_error.hpp"
#include "http/resilience/deadline_manager.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <functional>
#include <grpcpp/support/status_code_enum.h>
#include <memory>
#include <random>
#include <utility>

namespace securecloud::gateway::http {

/**
 * @brief Idempotency classification of gateway operations (ADR-009, GW-008-T03).
 */
enum class OperationIdempotency {
    SAFE_READONLY,       ///< Read-only query (e.g. GetUser), 100% safe to retry on transient failure.
    IDEMPOTENT_MUTATION, ///< Mutation with unique idempotency key or inherently idempotent state update.
    NON_IDEMPOTENT ///< Non-idempotent mutation (e.g. Authenticate, Refresh, Revoke, RegisterDevice). NEVER retried.
};

/**
 * @brief Configuration parameters for exponential backoff and jitter retry policy (ADR-009).
 */
struct RetryPolicyConfig {
    uint32_t max_attempts{3};         ///< Total attempts (1 initial + up to 2 retries)
    uint32_t initial_backoff_ms{100}; ///< Initial backoff delay (100ms)
    double backoff_multiplier{2.0};   ///< Exponential factor (2.0)
    uint32_t max_backoff_ms{1000};    ///< Ceiling backoff limit (1000ms)
    double jitter_ratio{0.25};        ///< Jitter window (+/-25%)
    bool retry_on_deadline_exceeded{
        false}; ///< By default, do NOT retry deadline exceeded (prevents cascading overload)
};

/**
 * @brief Evaluates operation retryability and executes bounded backoff retries within request deadlines.
 */
class RetryPolicy {
  public:
    using SleepFn = std::function<void(std::chrono::milliseconds)>;
    using RandomFn = std::function<double()>; // Returns a double in [-1.0, 1.0]

    explicit RetryPolicy(RetryPolicyConfig config = {}, SleepFn sleep_fn = nullptr,
                         RandomFn random_fn = nullptr) noexcept;
    virtual ~RetryPolicy() = default;

    /// Checks if the gRPC status code is considered transient and eligible for retry.
    [[nodiscard]] bool is_status_retryable(::grpc::StatusCode code) const noexcept;

    /// Checks if a retry should be attempted given the operation idempotency, status code, and attempt index.
    [[nodiscard]] bool should_retry(OperationIdempotency idempotency, ::grpc::StatusCode code,
                                    uint32_t current_attempt) const noexcept;

    /// Computes exponential backoff with pseudo-random jitter for the given retry attempt (1-based index).
    [[nodiscard]] std::chrono::milliseconds compute_backoff_delay(uint32_t attempt) const noexcept;

    /// Pauses execution for the calculated delay using configured sleep provider.
    void sleep_for(std::chrono::milliseconds delay) const;

    [[nodiscard]] const RetryPolicyConfig& config() const noexcept { return config_; }

    void set_sleep_fn(SleepFn sleep_fn) noexcept { sleep_fn_ = std::move(sleep_fn); }
    void set_random_fn(RandomFn random_fn) noexcept { random_fn_ = std::move(random_fn); }

    /**
     * @brief Executes a downstream gRPC call with retry policy enforcement and deadline budget management.
     *
     * @tparam InvokerFn Callable with signature: Result<T>(std::chrono::milliseconds call_budget)
     */
    // clang-format off
    template <typename InvokerFn>
    auto execute(const DeadlineManager& deadline_mgr, std::chrono::steady_clock::time_point start_tp,
                 std::chrono::milliseconds effective_deadline, std::chrono::milliseconds service_timeout,
                 OperationIdempotency idempotency, InvokerFn&& invoker_fn) const
        -> decltype(invoker_fn(std::chrono::milliseconds{})) {
        // clang-format on
        using ResultType = decltype(invoker_fn(std::chrono::milliseconds{}));

        uint32_t attempt = 0;
        while (true) {
            ++attempt;

            // 1. Calculate remaining call budget for this attempt
            auto call_budget = deadline_mgr.compute_downstream_budget(start_tp, effective_deadline, service_timeout);
            if (call_budget.count() <= 0) {
                return ResultType(grpc::DependencyError{
                    .kind = grpc::DependencyErrorKind::Timeout,
                    .message = "Request deadline exhausted before dispatch",
                    .grpc_code = ::grpc::StatusCode::DEADLINE_EXCEEDED,
                });
            }

            // 2. Invoke downstream call
            auto result = invoker_fn(call_budget);
            if (result) {
                return result;
            }

            // 3. Evaluate retry eligibility
            const auto grpc_code = result.error().grpc_code;
            if (!should_retry(idempotency, grpc_code, attempt)) {
                return result;
            }

            // 4. Calculate backoff delay
            auto backoff_delay = compute_backoff_delay(attempt);

            // 5. Verify deadline budget can accommodate backoff + minimum floor
            auto current_tp = deadline_mgr.now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_tp - start_tp);
            auto min_floor = std::chrono::milliseconds(deadline_mgr.config().min_request_deadline_ms);
            if (elapsed + backoff_delay + min_floor > effective_deadline) {
                // Insufficient budget remaining for backoff + call; abort retries
                return result;
            }

            // 6. Sleep for backoff delay and loop
            sleep_for(backoff_delay);
        }
    }

  private:
    RetryPolicyConfig config_;
    SleepFn sleep_fn_;
    RandomFn random_fn_;
    mutable std::mt19937 rng_;
};

} // namespace securecloud::gateway::http
