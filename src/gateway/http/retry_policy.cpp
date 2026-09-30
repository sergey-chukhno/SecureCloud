#include "http/retry_policy.hpp"

#include <algorithm>
#include <cmath>
#include <thread>

namespace securecloud::gateway::http {

RetryPolicy::RetryPolicy(RetryPolicyConfig config, SleepFn sleep_fn, RandomFn random_fn) noexcept
    : config_(config),
      sleep_fn_(std::move(sleep_fn)),
      random_fn_(std::move(random_fn)),
      rng_(std::random_device{}()) {}

bool RetryPolicy::is_status_retryable(::grpc::StatusCode code) const noexcept {
    if (code == ::grpc::StatusCode::UNAVAILABLE) {
        return true;
    }
    if (config_.retry_on_deadline_exceeded && code == ::grpc::StatusCode::DEADLINE_EXCEEDED) {
        return true;
    }
    return false;
}

bool RetryPolicy::should_retry(OperationIdempotency idempotency,
                               ::grpc::StatusCode code,
                               uint32_t current_attempt) const noexcept {
    if (idempotency == OperationIdempotency::NON_IDEMPOTENT) {
        return false;
    }
    if (current_attempt >= config_.max_attempts) {
        return false;
    }
    return is_status_retryable(code);
}

std::chrono::milliseconds RetryPolicy::compute_backoff_delay(uint32_t attempt) const noexcept {
    if (attempt == 0) {
        return std::chrono::milliseconds{0};
    }

    const double exp_factor = std::pow(config_.backoff_multiplier, static_cast<double>(attempt - 1));
    const double raw_backoff = static_cast<double>(config_.initial_backoff_ms) * exp_factor;
    const double capped_backoff = std::min(raw_backoff, static_cast<double>(config_.max_backoff_ms));

    double rand_jitter_norm = 0.0;
    if (random_fn_) {
        rand_jitter_norm = random_fn_();
    } else {
        std::uniform_real_distribution<double> dist(-1.0, 1.0);
        rand_jitter_norm = dist(rng_);
    }

    rand_jitter_norm = std::clamp(rand_jitter_norm, -1.0, 1.0);

    const double jitter = capped_backoff * config_.jitter_ratio * rand_jitter_norm;
    const double final_delay = std::max(1.0, capped_backoff + jitter);

    return std::chrono::milliseconds(static_cast<uint64_t>(final_delay));
}

void RetryPolicy::sleep_for(std::chrono::milliseconds delay) const {
    if (delay.count() <= 0) {
        return;
    }
    if (sleep_fn_) {
        sleep_fn_(delay);
    } else {
        std::this_thread::sleep_for(delay);
    }
}

} // namespace securecloud::gateway::http
