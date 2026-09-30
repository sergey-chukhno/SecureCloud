#pragma once

#include "gateway_config.hpp"

#include <chrono>
#include <functional>
#include <grpcpp/support/status_code_enum.h>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace httplib {
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

/**
 * @brief Discrete operational states of the Circuit Breaker FSM (ADR-009, GW-009-T03).
 */
enum class CircuitState {
    Closed,  ///< Normal operation; all requests are forwarded to downstream service.
    Open,    ///< Service is failing; requests fail fast at Gateway perimeter with HTTP 503.
    HalfOpen ///< Recovery trial; limited probe requests allowed to test downstream health.
};

/**
 * @brief Converts CircuitState enum to string representation for logging and metrics.
 */
[[nodiscard]] std::string_view to_string(CircuitState state) noexcept;

/**
 * @brief Thread-safe Finite State Machine (FSM) Circuit Breaker per downstream microservice.
 *
 * Implements the standard Michael Nygard Circuit Breaker pattern with transient error filtering:
 * - CLOSED: Tracks consecutive transient failures (UNAVAILABLE, DEADLINE_EXCEEDED).
 *   When threshold is reached, trips to OPEN.
 * - OPEN: Immediately rejects all requests without dispatching downstream RPCs.
 *   After recovery_timeout_ms has elapsed, transitions to HALF_OPEN.
 * - HALF_OPEN: Allows a configured number of probe requests.
 *   If probe succeeds -> resets to CLOSED.
 *   If probe fails -> immediately reverts to OPEN for another recovery window.
 *
 * Non-transient errors (such as INVALID_ARGUMENT, NOT_FOUND, UNAUTHENTICATED) do not trip the breaker.
 */
class CircuitBreaker {
  public:
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    explicit CircuitBreaker(std::string service_name, GatewayCircuitBreakerConfig config,
                            ClockFn clock_fn = nullptr) noexcept;

    ~CircuitBreaker() = default;
    CircuitBreaker(const CircuitBreaker&) = delete;
    CircuitBreaker& operator=(const CircuitBreaker&) = delete;
    CircuitBreaker(CircuitBreaker&&) = delete;
    CircuitBreaker& operator=(CircuitBreaker&&) = delete;

    /**
     * @brief Checks if an inbound request is permitted to proceed downstream.
     * @return true if permitted, false if circuit is OPEN or HALF_OPEN probe budget exhausted.
     */
    [[nodiscard]] bool allow_request();

    /**
     * @brief Records a successful downstream RPC execution.
     * In HALF_OPEN: Resets circuit to CLOSED and clears failure counter.
     * In CLOSED: Resets consecutive failure counter to 0.
     */
    void record_success();

    /**
     * @brief Records a downstream RPC failure.
     * @param is_transient_failure Whether failure is transient (UNAVAILABLE, DEADLINE_EXCEEDED).
     * If not transient (e.g. client validation error), does not count toward tripping breaker.
     */
    void record_failure(bool is_transient_failure = true);

    /**
     * @brief Convenient helper to record gRPC status directly, classifying transient errors.
     */
    void record_status(::grpc::StatusCode status);

    /**
     * @brief Classifies whether a gRPC status code is transient and counts towards tripping.
     */
    [[nodiscard]] static bool is_transient_failure(::grpc::StatusCode status) noexcept;

    /**
     * @brief Emits a standard RFC 7807 503 SERVICE_UNAVAILABLE error for an OPEN circuit breaker.
     */
    static void write_rejection(httplib::Response& res, const std::string& request_id, uint32_t retry_after_sec = 5);

    [[nodiscard]] CircuitState state() const;
    [[nodiscard]] uint32_t consecutive_failures() const;
    [[nodiscard]] const std::string& service_name() const noexcept { return service_name_; }
    [[nodiscard]] const GatewayCircuitBreakerConfig& config() const noexcept { return config_; }
    [[nodiscard]] uint32_t remaining_recovery_time_sec() const;

    /// Resets the circuit breaker to CLOSED with 0 failures.
    void reset();

  private:
    [[nodiscard]] std::chrono::steady_clock::time_point now() const;

    std::string service_name_;
    GatewayCircuitBreakerConfig config_;
    ClockFn clock_fn_;

    mutable std::mutex mutex_;
    CircuitState state_{CircuitState::Closed};
    uint32_t consecutive_failures_{0};
    uint32_t half_open_probes_in_flight_{0};
    std::chrono::steady_clock::time_point open_time_{};
};

/**
 * @brief Registry managing independent CircuitBreaker instances across downstream microservices.
 */
class CircuitBreakerRegistry {
  public:
    explicit CircuitBreakerRegistry(GatewayCircuitBreakerConfig default_config,
                                    CircuitBreaker::ClockFn clock_fn = nullptr);
    ~CircuitBreakerRegistry() = default;

    [[nodiscard]] std::shared_ptr<CircuitBreaker> get(const std::string& service_name);
    [[nodiscard]] std::shared_ptr<CircuitBreaker> get_or_create(const std::string& service_name);

    void reset_all();

  private:
    GatewayCircuitBreakerConfig default_config_;
    CircuitBreaker::ClockFn clock_fn_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<CircuitBreaker>> breakers_;
};

} // namespace securecloud::gateway::http
