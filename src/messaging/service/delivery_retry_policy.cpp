#include "service/delivery_retry_policy.hpp"

#include <algorithm>
#include <cmath>
#include <random>
#include <stdexcept>

namespace securecloud::messaging::service {

namespace {

class StandardRandomGenerator : public IRandomGenerator {
  public:
    double generate_uniform(double min, double max) override {
        if (min >= max) {
            return min;
        }
        thread_local std::random_device rd;
        thread_local std::mt19937_64 gen(rd());
        std::uniform_real_distribution<double> dist(min, max);
        return dist(gen);
    }
};

} // namespace

DeliveryRetryPolicy::DeliveryRetryPolicy(DeliveryRetryConfig config)
    : config_(config), rng_(std::make_shared<StandardRandomGenerator>()) {
    if (!config_.validate()) {
        throw std::invalid_argument("Invalid DeliveryRetryConfig parameters");
    }
}

DeliveryRetryPolicy::DeliveryRetryPolicy(DeliveryRetryConfig config, std::shared_ptr<IRandomGenerator> rng)
    : config_(config), rng_(std::move(rng)) {
    if (!config_.validate()) {
        throw std::invalid_argument("Invalid DeliveryRetryConfig parameters");
    }
    if (!rng_) {
        rng_ = std::make_shared<StandardRandomGenerator>();
    }
}

std::chrono::milliseconds DeliveryRetryPolicy::compute_next_delay(int32_t attempt_count) const {
    // Clamp attempt_count to non-negative and prevent floating point overflow
    const int32_t effective_attempt = std::clamp(attempt_count, 0, 30);

    const double initial_ms = static_cast<double>(config_.initial_backoff.count());
    const double max_ms = static_cast<double>(config_.max_backoff.count());

    const double exponential_backoff = initial_ms * std::pow(config_.backoff_multiplier, effective_attempt);
    const double bounded_backoff = std::min(max_ms, exponential_backoff);

    const double min_window = bounded_backoff * (1.0 - config_.jitter_factor);
    const double max_window = bounded_backoff * (1.0 + config_.jitter_factor);

    const double sample = rng_->generate_uniform(min_window, max_window);
    const double clamped_sample = std::clamp(sample, 0.0, max_ms);

    return std::chrono::milliseconds(static_cast<int64_t>(std::round(clamped_sample)));
}

bool DeliveryRetryPolicy::is_retryable(domain::DeliveryAttemptResult result, int32_t attempt_count,
                                       std::optional<std::chrono::system_clock::time_point> expires_at,
                                       std::chrono::system_clock::time_point now) const noexcept {
    if (result == domain::DeliveryAttemptResult::Success || result == domain::DeliveryAttemptResult::TerminalFailure) {
        return false;
    }

    if (attempt_count >= config_.max_retry_attempts) {
        return false;
    }

    if (expires_at.has_value() && now >= *expires_at) {
        return false;
    }

    return true;
}

} // namespace securecloud::messaging::service
