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

    // 2. Redact Bearer tokens (kept ahead of raw JWT detection so "Bearer <jwt>" keeps canonical form)
    static const std::regex bearer_regex("(Bearer\\s+)[A-Za-z0-9_\\-\\.]+", std::regex::ECMAScript);
    text = std::regex_replace(text, bearer_regex, "$1[REDACTED]");

    // 3. Redact bare compact JWTs (eyJ...header.payload.signature)
    static const std::regex jwt_regex("\\beyJ[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]{4,}",
                                      std::regex::ECMAScript);
    text = std::regex_replace(text, jwt_regex, "[REDACTED_JWT]");

    // 4. Redact BIP-39 salted verifier digests
    static const std::regex recovery_verifier_regex("sc-bip39-v1:[^\\s\"'&,;}\\]]+", std::regex::ECMAScript);
    text = std::regex_replace(text, recovery_verifier_regex, "[REDACTED_RECOVERY_VERIFIER]");

    // 5. Redact JSON secret, key-material, recovery, payload, and PII values
    static const std::regex json_secret_regex(
        "(\"(?:password|passphrase|secret|duress_pin|derived_hash_hex|salt_hex|token|auth_token|refresh_token|"
        "session_token|private_key|identity_key|root_key|chain_key|message_key|file_key|master_key|aes_key|"
        "mnemonic|recovery_phrase|recovery_seed|plaintext|body|content|email)\"\\s*:\\s*\")[^\"]*(\")",
        std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, json_secret_regex, "$1[REDACTED]$2");

    // 6. Redact quoted and unquoted key=value secrets, keys, mnemonics, plaintext, and PII
    static const std::regex quoted_kv_secret_regex(
        "((?:password|passphrase|secret|duress_pin|derived_hash_hex|salt_hex|token|auth_token|refresh_token|"
        "session_token|private_key|identity_key|root_key|chain_key|message_key|file_key|master_key|aes_key|"
        "mnemonic|recovery_phrase|recovery_seed|plaintext|body|content|email)=\\s*\")[^\"]*(\")",
        std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, quoted_kv_secret_regex, "$1[REDACTED]$2");

    static const std::regex query_secret_regex(
        "((?:password|passphrase|secret|duress_pin|derived_hash_hex|salt_hex|token|auth_token|refresh_token|"
        "session_token|private_key|identity_key|root_key|chain_key|message_key|file_key|master_key|aes_key|"
        "mnemonic|recovery_phrase|recovery_seed|plaintext|body|content|email)=)[^&\\s,;\"][^&\\s,;]*",
        std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, query_secret_regex, "$1[REDACTED]");

    // 7. Redact raw email addresses (PII)
    static const std::regex email_regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", std::regex::ECMAScript);
    text = std::regex_replace(text, email_regex, "[REDACTED_EMAIL]");

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
