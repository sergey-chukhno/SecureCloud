#pragma once

#include "lifecycle/audit_service_state.hpp"

#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace securecloud::audit::telemetry {

/// High-performance, zero-PII structured diagnostic logger with rate limiting.
class AuditDiagnostics {
  public:
    AuditDiagnostics() = default;
    ~AuditDiagnostics() = default;

    AuditDiagnostics(const AuditDiagnostics&) = delete;
    AuditDiagnostics& operator=(const AuditDiagnostics&) = delete;

    [[nodiscard]] static AuditDiagnostics& instance() noexcept;

    /// Updates the cached service detailed state for correlation.
    void set_service_state(lifecycle::DetailedServiceState state) noexcept;

    /// Logs an ingestion rejection event with zero PII and rate-limiting.
    void log_ingestion_rejection(std::string_view reason, std::string_view producer, std::string_view rpc_method,
                                 const std::optional<std::string>& correlation_id, std::string_view detail) noexcept;

    /// Logs a persistence failure event with zero PII and rate-limiting.
    void log_persistence_failure(std::string_view error_code, size_t batch_size, std::string_view sanitized_error,
                                 uint32_t retry_attempt) noexcept;

    /// Logs a queue saturation backpressure event with rate-limiting.
    void log_queue_saturation(size_t current_depth, size_t capacity, std::string_view producer) noexcept;

    /// Sanitizes arbitrary text by redacting credential keywords and sensitive details.
    [[nodiscard]] static std::string sanitize_detail(std::string_view detail) noexcept;

    /// Resets rate-limiting timestamps (used for test isolation).
    void reset_rate_limiters() noexcept;

  private:
    [[nodiscard]] bool should_log(std::string_view category) noexcept;

    std::mutex mutex_;
    lifecycle::DetailedServiceState current_state_{lifecycle::DetailedServiceState::Starting};
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_logged_map_;
};

// Convenience API wrappers matching technical spec:

void log_ingestion_rejection(std::string_view reason, std::string_view producer, std::string_view rpc_method,
                             const std::optional<std::string>& correlation_id,
                             std::string_view sanitized_detail) noexcept;

void log_persistence_failure(std::string_view error_code, size_t batch_size, std::string_view sanitized_error,
                             uint32_t retry_attempt) noexcept;

void log_queue_saturation(size_t current_depth, size_t capacity, std::string_view producer) noexcept;

} // namespace securecloud::audit::telemetry
