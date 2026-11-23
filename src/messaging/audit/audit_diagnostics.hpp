#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace securecloud::messaging::audit {

/**
 * @brief Zero-PII structured JSON diagnostic logger and Prometheus exposition helper
 *        for the Messaging Audit Outbox Relay (AUDIT-014-T06).
 *
 * Guarantees that all emitted logs are sanitized via ZeroPlaintextGuard before leaving
 * the process boundary (ADR-008).
 */
class AuditDiagnostics {
  public:
    using LogSink = std::function<void(std::string_view json_line)>;

    /// Sets a custom log sink (defaults to stdout/stderr structured JSON emission).
    static void set_log_sink(LogSink sink);
    static void reset_log_sink();

    /// Emits a structured JSON log for relay lifecycle transitions (started, draining, stopped).
    static void log_relay_state_change(std::string_view state, uint32_t worker_threads, uint32_t total_shards);

    /// Emits a structured JSON security alert when an outbox event is quarantined.
    static void log_quarantine_event(std::string_view outbox_bucket, int32_t shard_id, std::string_view event_id,
                                     std::string_view event_type, int32_t attempt_count, std::string_view raw_reason);

    /// Emits a structured JSON warning on transient gRPC dispatch failures.
    static void log_connection_failure(std::string_view outbox_bucket, int32_t shard_id, size_t batch_size,
                                       int32_t grpc_status_code, std::string_view raw_error,
                                       std::chrono::milliseconds backoff);

    /// Renders the complete Prometheus text payload for the internal diagnostics listener (127.0.0.1:9095/metrics).
    [[nodiscard]] static std::string render_prometheus_metrics();
};

} // namespace securecloud::messaging::audit
