#pragma once

#include "auth/audit/auth_outbox_metrics.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <ostream>
#include <string>
#include <string_view>
#include <unordered_map>

namespace securecloud::auth::audit {

/// Structured, zero-PII / zero-secret diagnostic logger for the Auth Outbox Relay pipeline.
/// Mirrors AUDIT-011 AuditDiagnostics conventions with per-category rate limiting and credential scrubbing.
class AuthOutboxDiagnostics {
  public:
    AuthOutboxDiagnostics() = default;
    ~AuthOutboxDiagnostics() = default;

    AuthOutboxDiagnostics(const AuthOutboxDiagnostics&) = delete;
    AuthOutboxDiagnostics& operator=(const AuthOutboxDiagnostics&) = delete;

    [[nodiscard]] static AuthOutboxDiagnostics& instance() noexcept;

    /// Scrubs all PII and secret material (passwords, tokens, JWTs, PEM keys, TOTP/recovery codes, emails)
    /// from arbitrary diagnostic strings before emission.
    [[nodiscard]] static std::string scrub_sensitive_data(std::string_view raw) noexcept;

    /// Logs a batch dispatch outcome with correlation ID and scrubbed detail.
    void log_batch_outcome(BatchOutcome outcome, size_t batch_size, size_t accepted_count, size_t rejected_count,
                           std::string_view correlation_id, std::string_view detail = "") noexcept;

    /// Logs a circuit-trip / consecutive failure backoff escalation event.
    void log_circuit_trip(uint32_t consecutive_failures, std::chrono::milliseconds backoff_delay,
                          std::string_view correlation_id, std::string_view detail) noexcept;

    /// Logs a permanent quarantine action on a poison-pill or rejected outbox event.
    void log_quarantine_action(std::string_view event_id, std::string_view correlation_id, QuarantineReason reason,
                               std::string_view detail) noexcept;

    /// Logs a bounded retention purge execution.
    void log_retention_purge(size_t purged_count, std::chrono::hours retention) noexcept;

    /// Overrides output stream (primarily for deterministic unit testing; pass nullptr to restore std::cout).
    void set_output_stream(std::ostream* os) noexcept;

    /// Resets per-category rate-limiting state (for deterministic unit test isolation).
    void reset_rate_limiters() noexcept;

  private:
    [[nodiscard]] bool should_log(std::string_view category) noexcept;
    [[nodiscard]] std::ostream& stream_unlocked() noexcept;

    std::mutex mutex_;
    std::ostream* output_stream_{nullptr};
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_logged_map_;
};

} // namespace securecloud::auth::audit
