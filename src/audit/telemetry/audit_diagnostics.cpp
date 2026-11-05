#include "telemetry/audit_diagnostics.hpp"
#include "domain/sensitive_data_guard.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace securecloud::audit::telemetry {

namespace {

std::string format_iso8601_utc() noexcept {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm tm_buf{};
#if defined(_WIN32) || defined(_WIN64)
    gmtime_s(&tm_buf, &time_t_now);
#else
    gmtime_r(&time_t_now, &tm_buf);
#endif

    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return ss.str();
}

std::string to_lower_copy(std::string_view str) {
    std::string result(str);
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

} // namespace

AuditDiagnostics& AuditDiagnostics::instance() noexcept {
    static AuditDiagnostics instance;
    return instance;
}

void AuditDiagnostics::set_service_state(lifecycle::DetailedServiceState state) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    current_state_ = state;
}

void AuditDiagnostics::reset_rate_limiters() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    last_logged_map_.clear();
}

bool AuditDiagnostics::should_log(std::string_view category) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    std::string key(category);

    auto it = last_logged_map_.find(key);
    if (it != last_logged_map_.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
        if (elapsed.count() < 1) {
            return false;
        }
    }

    last_logged_map_[key] = now;
    return true;
}

std::string AuditDiagnostics::sanitize_detail(std::string_view detail) noexcept {
    if (detail.empty()) {
        return "";
    }

    std::string text(detail);
    std::string lower = to_lower_copy(detail);

    static const std::initializer_list<const char*> sensitive_keywords = {
        "password", "passwd", "secret", "token", "auth", "bearer", "key", "api_key", "credential", "private_key"
    };

    for (const char* kw : sensitive_keywords) {
        if (lower.find(kw) != std::string::npos) {
            return "[REDACTED_SENSITIVE_DATA]";
        }
    }

    try {
        std::string sanitized = domain::SensitiveDataGuard::sanitize_diagnostic(detail);
        if (sanitized != detail) {
            return "[REDACTED_SENSITIVE_DATA]";
        }
    } catch (...) {
        return "[REDACTED_SENSITIVE_DATA]";
    }

    return text;
}

void AuditDiagnostics::log_ingestion_rejection(std::string_view reason,
                                                std::string_view producer,
                                                std::string_view rpc_method,
                                                const std::optional<std::string>& correlation_id,
                                                std::string_view detail) noexcept {
    std::string category = "rejection:" + std::string(reason) + ":" + std::string(producer);
    if (!should_log(category)) {
        return;
    }

    std::string safe_detail = sanitize_detail(detail);
    std::string timestamp = format_iso8601_utc();

    lifecycle::DetailedServiceState state_copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_copy = current_state_;
    }

    std::cout << timestamp << " [SecureCloud] [audit] [WARN] [state=" << lifecycle::to_string(state_copy)
              << "] Ingestion rejection: reason=" << reason << ", producer=" << producer
              << ", rpc=" << rpc_method;

    if (correlation_id.has_value() && !correlation_id->empty()) {
        std::cout << ", correlation_id=" << *correlation_id;
    }

    if (!safe_detail.empty()) {
        std::cout << ", detail=" << safe_detail;
    }

    std::cout << "\n";
}

void AuditDiagnostics::log_persistence_failure(std::string_view error_code,
                                                size_t batch_size,
                                                std::string_view sanitized_error,
                                                uint32_t retry_attempt) noexcept {
    std::string category = "persistence_failure:" + std::string(error_code);
    if (!should_log(category)) {
        return;
    }

    std::string safe_error = sanitize_detail(sanitized_error);
    std::string timestamp = format_iso8601_utc();

    lifecycle::DetailedServiceState state_copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_copy = current_state_;
    }

    std::cout << timestamp << " [SecureCloud] [audit] [ERROR] [state=" << lifecycle::to_string(state_copy)
              << "] ClickHouse persistence failure: error_code=" << error_code
              << ", batch_size=" << batch_size << ", retry_attempt=" << retry_attempt;

    if (!safe_error.empty()) {
        std::cout << ", error_message=" << safe_error;
    }

    std::cout << "\n";
}

void AuditDiagnostics::log_queue_saturation(size_t current_depth,
                                             size_t capacity,
                                             std::string_view producer) noexcept {
    std::string category = "queue_saturation:" + std::string(producer);
    if (!should_log(category)) {
        return;
    }

    std::string timestamp = format_iso8601_utc();

    lifecycle::DetailedServiceState state_copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_copy = current_state_;
    }

    std::cout << timestamp << " [SecureCloud] [audit] [WARN] [state=" << lifecycle::to_string(state_copy)
              << "] Ingestion queue saturation backpressure: depth=" << current_depth
              << ", capacity=" << capacity << ", producer=" << producer << "\n";
}

void log_ingestion_rejection(std::string_view reason,
                             std::string_view producer,
                             std::string_view rpc_method,
                             const std::optional<std::string>& correlation_id,
                             std::string_view sanitized_detail) noexcept {
    AuditDiagnostics::instance().log_ingestion_rejection(reason, producer, rpc_method, correlation_id, sanitized_detail);
}

void log_persistence_failure(std::string_view error_code,
                             size_t batch_size,
                             std::string_view sanitized_error,
                             uint32_t retry_attempt) noexcept {
    AuditDiagnostics::instance().log_persistence_failure(error_code, batch_size, sanitized_error, retry_attempt);
}

void log_queue_saturation(size_t current_depth,
                          size_t capacity,
                          std::string_view producer) noexcept {
    AuditDiagnostics::instance().log_queue_saturation(current_depth, capacity, producer);
}

} // namespace securecloud::audit::telemetry
