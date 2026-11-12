#include "auth/audit/auth_outbox_diagnostics.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace securecloud::auth::audit {

namespace {

[[nodiscard]] std::string format_iso8601_utc() noexcept {
    const auto now = std::chrono::system_clock::now();
    const auto time_t_now = std::chrono::system_clock::to_time_t(now);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm tm_buf{};
#if defined(_WIN32) || defined(_WIN64)
    gmtime_s(&tm_buf, &time_t_now);
#else
    gmtime_r(&tm_buf, &time_t_now);
#endif

    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return ss.str();
}

[[nodiscard]] std::string to_lower_ascii(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (unsigned char ch : input) {
        out.push_back(static_cast<char>(std::tolower(ch)));
    }
    return out;
}

[[nodiscard]] bool contains_email_pii(std::string_view text) noexcept {
    const size_t at_pos = text.find('@');
    if (at_pos == std::string_view::npos || at_pos == 0 || at_pos + 3 >= text.size()) {
        return false;
    }
    const size_t dot_pos = text.find('.', at_pos + 2);
    return dot_pos != std::string_view::npos && dot_pos + 1 < text.size();
}

[[nodiscard]] bool contains_jwt_pattern(std::string_view text) noexcept {
    const size_t jwt_pos = text.find("eyJ");
    if (jwt_pos == std::string_view::npos) {
        return false;
    }
    const std::string_view tail = text.substr(jwt_pos);
    return std::count(tail.begin(), tail.end(), '.') >= 2;
}

} // namespace

AuthOutboxDiagnostics& AuthOutboxDiagnostics::instance() noexcept {
    static AuthOutboxDiagnostics diagnostics;
    return diagnostics;
}

std::string AuthOutboxDiagnostics::scrub_sensitive_data(std::string_view raw) noexcept {
    if (raw.empty()) {
        return "";
    }

    try {
        const std::string lower = to_lower_ascii(raw);

        static constexpr std::array<std::string_view, 28> kForbiddenTerms = {
            "password",      "passwd",        "pwd",         "secret",         "token",       "credential",
            "private_key",   "signing_key",   "master_key",  "encryption_key", "session_key", "api_key",
            "apikey",        "recovery_code", "backup_code", "passphrase",     "mnemonic",    "seed",
            "authorization", "cookie",        "bearer ",     "-----begin ",    "$argon2",     "$2a$",
            "$2b$",          "$2y$",          "totp",        "otp_code",
        };

        for (std::string_view term : kForbiddenTerms) {
            if (lower.find(term) != std::string::npos) {
                return "[REDACTED_SENSITIVE_DATA]";
            }
        }

        if (contains_jwt_pattern(raw) || contains_email_pii(raw)) {
            return "[REDACTED_SENSITIVE_DATA]";
        }

        // Strip newlines/control chars to prevent log injection
        std::string clean;
        clean.reserve(raw.size());
        for (unsigned char ch : raw) {
            if (ch == '\r' || ch == '\n') {
                clean.push_back(' ');
            } else if (ch >= 0x20 && ch != 0x7F) {
                clean.push_back(static_cast<char>(ch));
            }
        }
        return clean;
    } catch (...) {
        return "[REDACTED_SENSITIVE_DATA]";
    }
}

void AuthOutboxDiagnostics::set_output_stream(std::ostream* os) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    output_stream_ = os;
}

void AuthOutboxDiagnostics::reset_rate_limiters() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    last_logged_map_.clear();
}

bool AuthOutboxDiagnostics::should_log(std::string_view category) noexcept {
    const auto now = std::chrono::steady_clock::now();
    std::string key(category);

    const auto it = last_logged_map_.find(key);
    if (it != last_logged_map_.end()) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
        if (elapsed.count() < 1) {
            return false;
        }
    }

    last_logged_map_[key] = now;
    return true;
}

std::ostream& AuthOutboxDiagnostics::stream_unlocked() noexcept {
    return output_stream_ != nullptr ? *output_stream_ : std::cout;
}

void AuthOutboxDiagnostics::log_batch_outcome(BatchOutcome outcome, size_t batch_size, size_t accepted_count,
                                              size_t rejected_count, std::string_view correlation_id,
                                              std::string_view detail) noexcept {
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::string category = "batch:" + std::string(to_string(outcome));
        if (outcome != BatchOutcome::Success && !should_log(category)) {
            return;
        }

        const std::string safe_corr = scrub_sensitive_data(correlation_id);
        const std::string safe_detail = scrub_sensitive_data(detail);
        const std::string_view level = (outcome == BatchOutcome::Success) ? "INFO" : "WARN";

        auto& out = stream_unlocked();
        out << format_iso8601_utc() << " [SecureCloud] [auth] [" << level
            << "] Outbox batch outcome=" << to_string(outcome) << ", batch_size=" << batch_size
            << ", accepted=" << accepted_count << ", rejected=" << rejected_count;

        if (!safe_corr.empty()) {
            out << ", correlation_id=" << safe_corr;
        }
        if (!safe_detail.empty()) {
            out << ", detail=" << safe_detail;
        }
        out << "\n";
    } catch (...) {
    }
}

void AuthOutboxDiagnostics::log_circuit_trip(uint32_t consecutive_failures, std::chrono::milliseconds backoff_delay,
                                             std::string_view correlation_id, std::string_view detail) noexcept {
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!should_log("circuit_trip")) {
            return;
        }

        const std::string safe_corr = scrub_sensitive_data(correlation_id);
        const std::string safe_detail = scrub_sensitive_data(detail);

        auto& out = stream_unlocked();
        out << format_iso8601_utc() << " [SecureCloud] [auth] [ERROR] Outbox relay circuit trip: "
            << "consecutive_failures=" << consecutive_failures << ", backoff_ms=" << backoff_delay.count();

        if (!safe_corr.empty()) {
            out << ", correlation_id=" << safe_corr;
        }
        if (!safe_detail.empty()) {
            out << ", detail=" << safe_detail;
        }
        out << "\n";
    } catch (...) {
    }
}

void AuthOutboxDiagnostics::log_quarantine_action(std::string_view event_id, std::string_view correlation_id,
                                                  QuarantineReason reason, std::string_view detail) noexcept {
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::string category = "quarantine:" + std::string(to_string(reason));
        if (!should_log(category)) {
            return;
        }

        const std::string safe_event_id = scrub_sensitive_data(event_id);
        const std::string safe_corr = scrub_sensitive_data(correlation_id);
        const std::string safe_detail = scrub_sensitive_data(detail);

        auto& out = stream_unlocked();
        out << format_iso8601_utc() << " [SecureCloud] [auth] [WARN] Outbox event quarantined: "
            << "event_id=" << safe_event_id << ", reason=" << to_string(reason);

        if (!safe_corr.empty()) {
            out << ", correlation_id=" << safe_corr;
        }
        if (!safe_detail.empty()) {
            out << ", detail=" << safe_detail;
        }
        out << "\n";
    } catch (...) {
    }
}

void AuthOutboxDiagnostics::log_retention_purge(size_t purged_count, std::chrono::hours retention) noexcept {
    try {
        if (purged_count == 0) {
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        auto& out = stream_unlocked();
        out << format_iso8601_utc() << " [SecureCloud] [auth] [INFO] Outbox retention purge completed: "
            << "purged_count=" << purged_count << ", retention_hours=" << retention.count() << "\n";
    } catch (...) {
    }
}

} // namespace securecloud::auth::audit
