#pragma once

#include "domain/delivery_types.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>

namespace securecloud::messaging::service {

/// Configuration for delivery retry backoff with decorrelated jitter (ADR-007, ADR-009).
struct DeliveryRetryConfig {
    std::chrono::milliseconds initial_backoff{500};
    std::chrono::milliseconds max_backoff{60000};
    double backoff_multiplier{2.0};
    int32_t max_retry_attempts{10};
    double jitter_factor{0.25}; // +/- 25% around exponential curve

    [[nodiscard]] bool validate() const noexcept {
        return initial_backoff.count() > 0 && max_backoff >= initial_backoff && backoff_multiplier >= 1.0 &&
               max_retry_attempts >= 0 && jitter_factor >= 0.0 && jitter_factor <= 1.0;
    }
};

/// Interface for uniform random number generation (allows deterministic injection in unit tests).
class IRandomGenerator {
  public:
    virtual ~IRandomGenerator() = default;
    [[nodiscard]] virtual double generate_uniform(double min, double max) = 0;
};

/// Implements exponential backoff with decorrelated jitter and retry eligibility guards.
class DeliveryRetryPolicy {
  public:
    explicit DeliveryRetryPolicy(DeliveryRetryConfig config = {});
    DeliveryRetryPolicy(DeliveryRetryConfig config, std::shared_ptr<IRandomGenerator> rng);

    [[nodiscard]] const DeliveryRetryConfig& config() const noexcept { return config_; }

    /// Computes the next retry delay using decorrelated jitter:
    ///   T_backoff = min(T_max, T_initial * multiplier^attempt)
    ///   Window = [(1 - jitter) * T_backoff, (1 + jitter) * T_backoff]
    ///   Delay = UniformRandom(Window_min, Window_max), clamped to [0, T_max]
    [[nodiscard]] std::chrono::milliseconds compute_next_delay(int32_t attempt_count) const;

    /// Determines whether a delivery attempt qualifies for a subsequent retry attempt:
    ///   - TerminalFailure or Success: returns false immediately.
    ///   - attempt_count >= max_retry_attempts: returns false.
    ///   - expires_at.has_value() && now >= *expires_at: returns false.
    ///   - TransientFailure or RecipientOffline: returns true if bounds hold.
    [[nodiscard]] bool
    is_retryable(domain::DeliveryAttemptResult result, int32_t attempt_count,
                 std::optional<std::chrono::system_clock::time_point> expires_at = std::nullopt,
                 std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) const noexcept;

  private:
    DeliveryRetryConfig config_;
    std::shared_ptr<IRandomGenerator> rng_;
};

} // namespace securecloud::messaging::service
