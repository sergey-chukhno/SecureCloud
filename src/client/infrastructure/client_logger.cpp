#include "infrastructure/client_logger.hpp"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <regex>
#include <sstream>

namespace securecloud::client::infrastructure {

namespace {

std::mutex g_log_mutex;
LogLevel g_min_level = LogLevel::Info;
ClientLogger::LogSink g_custom_sink = nullptr;
std::ofstream g_log_file;
std::filesystem::path g_log_file_path;

std::string format_timestamp() {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    const auto timer = system_clock::to_time_t(now);
    std::tm tm_buf{};
#if defined(_WIN32)
    gmtime_s(&tm_buf, &timer);
#else
    gmtime_r(&timer, &tm_buf);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

} // namespace

std::string_view to_string(LogLevel level) noexcept {
    switch (level) {
    case LogLevel::Trace:
        return "TRACE";
    case LogLevel::Debug:
        return "DEBUG";
    case LogLevel::Info:
        return "INFO";
    case LogLevel::Warning:
        return "WARN";
    case LogLevel::Error:
        return "ERROR";
    case LogLevel::Fatal:
        return "FATAL";
    }
    return "UNKNOWN";
}

void ClientLogger::set_min_level(LogLevel level) noexcept {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_min_level = level;
}

LogLevel ClientLogger::min_level() noexcept {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    return g_min_level;
}

void ClientLogger::set_custom_sink(LogSink sink) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_custom_sink = std::move(sink);
}

void ClientLogger::reset_sink() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_custom_sink = nullptr;
}

bool ClientLogger::set_log_file_path(const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file.is_open()) {
        g_log_file.flush();
        g_log_file.close();
    }
    g_log_file_path.clear();

    if (path.empty()) {
        return true;
    }

    std::error_code ec;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            return false;
        }
    }

    g_log_file.open(path, std::ios::out | std::ios::app);
    if (!g_log_file.is_open()) {
        return false;
    }
    g_log_file_path = path;
    return true;
}

std::filesystem::path ClientLogger::log_file_path() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    return g_log_file_path;
}

std::filesystem::path ClientLogger::flush_and_close_log_file() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file.is_open()) {
        g_log_file.flush();
        g_log_file.close();
    }
    std::filesystem::path closed_path = std::move(g_log_file_path);
    g_log_file_path.clear();
    return closed_path;
}

std::string ClientLogger::sanitize(std::string_view raw) {
    std::string text(raw);

    // 1. Redact Private Key blocks
    static const std::regex private_key_regex(
        "-----BEGIN(?: [A-Za-z0-9_-]+)? PRIVATE KEY-----[\\s\\S]*?-----END(?: [A-Za-z0-9_-]+)? PRIVATE KEY-----",
        std::regex::ECMAScript);
    text = std::regex_replace(text, private_key_regex, "[REDACTED_PRIVATE_KEY]");

    // 2. Redact Bearer tokens
    static const std::regex bearer_regex("(Bearer\\s+)[A-Za-z0-9_\\-\\.]+", std::regex::ECMAScript);
    text = std::regex_replace(text, bearer_regex, "$1[REDACTED]");

    // 3. Redact JSON password/duress/salt/hash values
    static const std::regex json_password_regex(
        "(\"(?:password|passphrase|secret|duress_pin|derived_hash_hex|salt_hex)\"\\s*:\\s*\")[^\"]*(\")",
        std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, json_password_regex, "$1[REDACTED]$2");

    // 4. Redact query/form password/duress/salt/hash parameters
    static const std::regex query_password_regex(
        "((?:password|passphrase|secret|duress_pin|derived_hash_hex|salt_hex)=)[^&\\s]+",
        std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, query_password_regex, "$1[REDACTED]");

    // 5. Redact JSON token values
    static const std::regex json_token_regex(
        "(\"(?:token|auth_token|refresh_token|session_token)\"\\s*:\\s*\")[^\"]*(\")",
        std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, json_token_regex, "$1[REDACTED]$2");

    // 6. Redact query/form token parameters
    static const std::regex query_token_regex("((?:token|auth_token|refresh_token|session_token)=)[^&\\s]+",
                                              std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, query_token_regex, "$1[REDACTED]");

    return text;
}

void ClientLogger::log(LogLevel level, std::string_view tag, std::string_view message,
                       std::string_view correlation_id) {
    std::unique_lock<std::mutex> lock(g_log_mutex);
    if (level < g_min_level) {
        return;
    }

    const std::string sanitized_msg = sanitize(message);

    if (g_custom_sink) {
        auto sink = g_custom_sink;
        lock.unlock();
        sink(level, tag, sanitized_msg, correlation_id);
        return;
    }

    const std::string timestamp = format_timestamp();
    std::ostream& out = (level >= LogLevel::Warning) ? std::cerr : std::cout;

    out << "[" << timestamp << "] [" << to_string(level) << "] [" << tag << "]";
    if (!correlation_id.empty()) {
        out << " [cid: " << correlation_id << "]";
    }
    out << " " << sanitized_msg << "\n";

    if (g_log_file.is_open()) {
        g_log_file << "[" << timestamp << "] [" << to_string(level) << "] [" << tag << "]";
        if (!correlation_id.empty()) {
            g_log_file << " [cid: " << correlation_id << "]";
        }
        g_log_file << " " << sanitized_msg << "\n";
        g_log_file.flush();
    }
}

void ClientLogger::trace(std::string_view tag, std::string_view message, std::string_view correlation_id) {
    log(LogLevel::Trace, tag, message, correlation_id);
}

void ClientLogger::debug(std::string_view tag, std::string_view message, std::string_view correlation_id) {
    log(LogLevel::Debug, tag, message, correlation_id);
}

void ClientLogger::info(std::string_view tag, std::string_view message, std::string_view correlation_id) {
    log(LogLevel::Info, tag, message, correlation_id);
}

void ClientLogger::warn(std::string_view tag, std::string_view message, std::string_view correlation_id) {
    log(LogLevel::Warning, tag, message, correlation_id);
}

void ClientLogger::error(std::string_view tag, std::string_view message, std::string_view correlation_id) {
    log(LogLevel::Error, tag, message, correlation_id);
}

} // namespace securecloud::client::infrastructure
