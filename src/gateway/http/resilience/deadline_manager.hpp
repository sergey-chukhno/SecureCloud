#pragma once

#include "gateway_config.hpp"

#include <chrono>
#include <functional>
#include <optional>
#include <string_view>

namespace httplib {
struct Request;
}

namespace securecloud::gateway::http {

/**
 * @brief Manages request deadlines, client timeout header ingestion, and downstream call budgets (ADR-009, GW-008-T02).
 *
 * Implements strict deadline propagation:
 * - Ingests client-specified headers (X-Request-Timeout, Request-Timeout).
 * - Enforces minimum viable floor (50ms) and maximum ceiling (10s) clamps.
 * - Propagates strictly shrinking remaining budgets to downstream child calls.
 * - Detects exhausted budgets before RPC dispatch to support immediate 504 fast-fail.
 */
class DeadlineManager {
  public:
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    explicit DeadlineManager(GatewayServiceDeadlinesConfig config = {}, ClockFn clock_fn = nullptr) noexcept;
    ~DeadlineManager() = default;

    /// Ingests client-specified timeout from headers (X-Request-Timeout or Request-Timeout).
    /// Supports milliseconds (e.g. "1500", "500ms") or seconds (e.g. "2s", "1.5s").
    [[nodiscard]] static std::optional<std::chrono::milliseconds>
    extract_client_timeout(const httplib::Request& req) noexcept;

    /// Parses a duration string (e.g. "500", "500ms", "2s", "1.5s") into milliseconds.
    [[nodiscard]] static std::optional<std::chrono::milliseconds> parse_duration_string(std::string_view str) noexcept;

    /// Returns current monotonic timestamp according to clock provider (useful for deterministic tests).
    [[nodiscard]] std::chrono::steady_clock::time_point now() const noexcept;

    /// Overrides clock provider for testing.
    void set_clock_fn(ClockFn clock_fn) noexcept { clock_fn_ = std::move(clock_fn); }

    /// Computes overall effective deadline clamped to [min_request_deadline_ms, max_request_deadline_ms].
    /// If no client timeout is provided, falls back to default_timeout.
    [[nodiscard]] std::chrono::milliseconds
    compute_effective_deadline(const httplib::Request& req, std::chrono::milliseconds default_timeout) const noexcept;

    /// Computes downstream gRPC call budget bounded by the remaining request lifetime:
    /// downstream_budget = min(service_timeout, remaining_budget)
    [[nodiscard]] std::chrono::milliseconds
    compute_downstream_budget(std::chrono::steady_clock::time_point start_tp,
                              std::chrono::milliseconds effective_deadline,
                              std::chrono::milliseconds service_timeout) const noexcept;

    /// Checks if sufficient budget remains for downstream invocation.
    /// Returns false if remaining budget is <= 0 or below minimum floor.
    [[nodiscard]] bool
    has_sufficient_budget(std::chrono::steady_clock::time_point start_tp, std::chrono::milliseconds effective_deadline,
                          std::chrono::milliseconds minimum_required = std::chrono::milliseconds{1}) const noexcept;

    [[nodiscard]] const GatewayServiceDeadlinesConfig& config() const noexcept { return config_; }

  private:
    GatewayServiceDeadlinesConfig config_;
    ClockFn clock_fn_;
};

} // namespace securecloud::gateway::http
