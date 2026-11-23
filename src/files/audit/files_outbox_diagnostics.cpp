#include "files/audit/files_outbox_diagnostics.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <iostream>

namespace securecloud::files::audit {
namespace {
constexpr const char* categories[] = {"batch", "lease", "quarantine", "outage", "recovery", "purge"};
std::string json_escape(std::string_view s) {
    std::string out;
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back(static_cast<char>(c)); }
        else if (c >= 0x20 && c != 0x7f) out.push_back(static_cast<char>(c));
        else if (c == '\n' || c == '\r' || c == '\t') out.push_back(' ');
    }
    return out;
}

}

FilesOutboxDiagnostics& FilesOutboxDiagnostics::instance() noexcept {
    static FilesOutboxDiagnostics diagnostics;
    return diagnostics;
}

std::string FilesOutboxDiagnostics::scrub_sensitive_data(std::string_view raw) noexcept {
    try {
        std::string lower(raw);
        for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        constexpr std::array<std::string_view, 20> secrets = {"password", "passwd", "pwd=", "secret", "token", "bearer ", "authorization", "credential", "private_key", "-----begin", "jwt", "s3_", "access_key", "filename", "encrypted_filename", ".pdf", ".doc", ".jpg", ".png", ".txt"};
        for (auto term : secrets) if (lower.find(term) != std::string::npos) return "[REDACTED_SENSITIVE_DATA]";
        if (lower.find('/') != std::string::npos || lower.find('\\') != std::string::npos) return "[REDACTED_SENSITIVE_DATA]";
        if (lower.find(".jpeg") != std::string::npos || lower.find(".csv") != std::string::npos ||
            lower.find(".zip") != std::string::npos || lower.find(".xlsx") != std::string::npos ||
            lower.find(".pptx") != std::string::npos || lower.find(".json") != std::string::npos ||
            lower.find(".xml") != std::string::npos || lower.find(".log") != std::string::npos ||
            lower.find(".sql") != std::string::npos || lower.find(".pem") != std::string::npos ||
            lower.find(".key") != std::string::npos || lower.find(".mp4") != std::string::npos ||
            lower.find(".mp3") != std::string::npos || lower.find(".gif") != std::string::npos ||
            lower.find(".webp") != std::string::npos) return "[REDACTED_SENSITIVE_DATA]";
        const auto jwt = raw.find("eyJ");
        if (jwt != std::string_view::npos && std::count(raw.begin() + static_cast<std::ptrdiff_t>(jwt), raw.end(), '.') >= 2) return "[REDACTED_SENSITIVE_DATA]";
        return json_escape(raw);
    } catch (...) { return "[REDACTED_SENSITIVE_DATA]"; }
}

void FilesOutboxDiagnostics::set_output_stream(std::ostream* stream) noexcept {
    std::lock_guard<std::mutex> lock(log_mutex_);
    output_stream_ = stream;
}
void FilesOutboxDiagnostics::reset_rate_limiters() noexcept {
    std::lock_guard<std::mutex> lock(log_mutex_);
    for (size_t i = 0; i < static_cast<size_t>(FilesDiagnosticCategory::Count); ++i) {
        last_logged_[i] = {};
        rate_tokens_[i] = 5.0;
    }
}
void FilesOutboxDiagnostics::log_event(FilesDiagnosticCategory category, std::string_view event,
                                       std::string_view correlation_id, std::string_view detail, uint64_t value) noexcept {
    try {
        const auto i = static_cast<size_t>(category);
        if (i >= static_cast<size_t>(FilesDiagnosticCategory::Count)) return;
        std::lock_guard<std::mutex> lock(log_mutex_);
        const auto now = std::chrono::steady_clock::now();
        if (last_logged_[i].time_since_epoch().count() == 0) last_logged_[i] = now;
        const double elapsed = std::chrono::duration<double>(now - last_logged_[i]).count();
        rate_tokens_[i] = std::min(5.0, rate_tokens_[i] + elapsed);
        last_logged_[i] = now;
        if (rate_tokens_[i] < 1.0) return;
        rate_tokens_[i] -= 1.0;
        auto& out = output_stream_ ? *output_stream_ : std::clog;
        out << "{\"service\":\"files\",\"category\":\"" << categories[i] << "\",\"event\":\""
            << scrub_sensitive_data(event) << "\",\"correlation_id\":\"" << scrub_sensitive_data(correlation_id)
            << "\",\"detail\":\"" << scrub_sensitive_data(detail) << "\",\"value\":" << value << "}\n";
    } catch (...) {}
}
} // namespace securecloud::files::audit
