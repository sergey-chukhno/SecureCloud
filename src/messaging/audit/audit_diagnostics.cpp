#include "audit/audit_diagnostics.hpp"

#include "audit/messaging_audit_metrics.hpp"
#include "util/zero_plaintext_guard.hpp"

#include <array>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>

namespace securecloud::messaging::audit {

namespace {

std::mutex g_sink_mutex;
AuditDiagnostics::LogSink g_custom_sink = nullptr;

std::string current_utc_iso8601() {
    const auto now = std::chrono::system_clock::now();
    const auto time_t_val = std::chrono::system_clock::to_time_t(now);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm tm_buf{};
#if defined(_WIN32)
    gmtime_s(&tm_buf, &time_t_val);
#else
    gmtime_r(&time_t_val, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return oss.str();
}

std::string sanitize_diagnostic_text(std::string_view raw) {
    std::string sanitized = util::ZeroPlaintextGuard::sanitize_error_message(raw);

    // Also redact unprefixed Bearer tokens (e.g., "Bearer eyJ...")
    static constexpr std::array<std::string_view, 2> kBearerPrefixes = {"Bearer ", "bearer "};
    for (std::string_view prefix : kBearerPrefixes) {
        size_t pos = 0;
        while ((pos = sanitized.find(prefix, pos)) != std::string::npos) {
            const size_t val_start = pos + prefix.size();
            size_t val_end = sanitized.find_first_of(" \t\n\r,;)}", val_start);
            if (val_end == std::string::npos) {
                val_end = sanitized.size();
            }
            if (val_end > val_start) {
                sanitized.replace(val_start, val_end - val_start, util::ZeroPlaintextGuard::kRedactedPlaceholder);
                pos = val_start + util::ZeroPlaintextGuard::kRedactedPlaceholder.size();
            } else {
                pos = val_start;
            }
        }
    }

    return sanitized;
}

void emit_json(const nlohmann::json& payload, bool is_error_stream) {
    const std::string serialized = payload.dump();

    std::lock_guard<std::mutex> lock(g_sink_mutex);
    if (g_custom_sink) {
        g_custom_sink(serialized);
        return;
    }

    if (is_error_stream) {
        std::cerr << serialized << '\n';
    } else {
        std::cout << serialized << '\n';
    }
}

} // namespace

void AuditDiagnostics::set_log_sink(LogSink sink) {
    std::lock_guard<std::mutex> lock(g_sink_mutex);
    g_custom_sink = std::move(sink);
}

void AuditDiagnostics::reset_log_sink() {
    std::lock_guard<std::mutex> lock(g_sink_mutex);
    g_custom_sink = nullptr;
}

void AuditDiagnostics::log_relay_state_change(std::string_view state, uint32_t worker_threads, uint32_t total_shards) {
    nlohmann::json log_entry = {
        {"timestamp", current_utc_iso8601()},
        {"level", "INFO"},
        {"service", "securecloud-messaging"},
        {"component", "audit_relay"},
        {"event", "relay.state_changed"},
        {"state", sanitize_diagnostic_text(state)},
        {"worker_threads", worker_threads},
        {"total_shards", total_shards},
    };
    emit_json(log_entry, false);
}

void AuditDiagnostics::log_quarantine_event(std::string_view outbox_bucket, int32_t shard_id, std::string_view event_id,
                                            std::string_view event_type, int32_t attempt_count,
                                            std::string_view raw_reason) {
    nlohmann::json log_entry = {
        {"timestamp", current_utc_iso8601()},
        {"level", "ERROR"},
        {"security_alert", true},
        {"service", "securecloud-messaging"},
        {"component", "audit_relay"},
        {"event", "outbox.event_quarantined"},
        {"outbox_bucket", sanitize_diagnostic_text(outbox_bucket)},
        {"shard_id", shard_id},
        {"event_id", sanitize_diagnostic_text(event_id)},
        {"event_type", sanitize_diagnostic_text(event_type)},
        {"attempt_count", attempt_count},
        {"reason", sanitize_diagnostic_text(raw_reason)},
    };
    emit_json(log_entry, true);
}

void AuditDiagnostics::log_connection_failure(std::string_view outbox_bucket, int32_t shard_id, size_t batch_size,
                                              int32_t grpc_status_code, std::string_view raw_error,
                                              std::chrono::milliseconds backoff) {
    nlohmann::json log_entry = {
        {"timestamp", current_utc_iso8601()},
        {"level", "WARN"},
        {"service", "securecloud-messaging"},
        {"component", "audit_relay"},
        {"event", "outbox.dispatch_failed"},
        {"outbox_bucket", sanitize_diagnostic_text(outbox_bucket)},
        {"shard_id", shard_id},
        {"batch_size", batch_size},
        {"grpc_status_code", grpc_status_code},
        {"backoff_ms", backoff.count()},
        {"error", sanitize_diagnostic_text(raw_error)},
    };
    emit_json(log_entry, true);
}

std::string AuditDiagnostics::render_prometheus_metrics() {
    return MessagingAuditMetrics::instance().to_prometheus_text();
}

} // namespace securecloud::messaging::audit