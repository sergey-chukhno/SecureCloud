#include "application/managers/diagnostic_sanitizer.hpp"

#include "infrastructure/client_logger.hpp"

#include <regex>

namespace securecloud::client::application::managers {
namespace {

void replace_all_literal(std::string& target, std::string_view needle, std::string_view replacement) {
    if (needle.size() < 3U) {
        return;
    }
    std::size_t pos = 0U;
    while ((pos = target.find(needle, pos)) != std::string::npos) {
        target.replace(pos, needle.size(), replacement);
        pos += replacement.size();
    }
}

} // namespace

std::string DiagnosticSanitizer::scrub_text(std::string_view raw,
                                            const std::vector<std::string>& extra_sensitive_literals) {
    std::string text(raw);

    // 1. Replace caller-supplied literal secrets/PII (active display name, handle, tokens, etc.)
    for (const auto& literal : extra_sensitive_literals) {
        replace_all_literal(text, literal, "[REDACTED]");
    }

    // 2. Apply baseline ClientLogger sanitization (PEMs, Bearer, JWTs, BIP-39 verifiers, JSON/query keys, emails)
    text = infrastructure::ClientLogger::sanitize(text);

    // 3. Scrub additional diagnostic PII & crypto-key JSON fields
    static const std::regex diag_json_regex(
        "(\"(?:display_name|username|proxy_username|handle|public_handle|bio|bio_status|title|conversation_title|"
        "message|message_text|sqlcipher_key|master_key_hex|seed|x25519_private|ed25519_private|private_key_pem|"
        "local_path|pw|pwd|passwd|api_key|access_token|secret_key)\"\\s*:\\s*\")[^\"]*(\")",
        std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, diag_json_regex, "$1[REDACTED]$2");

    // 4. Scrub quoted and unquoted diagnostic key=value pairs (including short credential aliases with delimiters)
    static const std::regex diag_quoted_kv_regex(
        "((?:display_name|username|proxy_username|handle|public_handle|bio|bio_status|title|conversation_title|"
        "message|message_text|sqlcipher_key|master_key_hex|seed|x25519_private|ed25519_private|private_key_pem|"
        "local_path)=\\s*\")[^\"]*(\")",
        std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, diag_quoted_kv_regex, "$1[REDACTED]$2");

    static const std::regex short_secret_quoted_kv_regex(
        "((?:^|[\\s?&,;(\"':])(?:pw|pwd|passwd|api_key|access_token|secret_key)=\\s*\")[^\"]*(\")",
        std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, short_secret_quoted_kv_regex, "$1[REDACTED]$2");

    static const std::regex diag_query_kv_regex(
        "((?:display_name|username|proxy_username|handle|public_handle|bio|bio_status|title|conversation_title|"
        "message|message_text|sqlcipher_key|master_key_hex|seed|x25519_private|ed25519_private|private_key_pem|"
        "local_path)=)[^&\\s,;\"'][^&\\s,;\"']*",
        std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, diag_query_kv_regex, "$1[REDACTED]");

    static const std::regex short_secret_query_kv_regex(
        "((?:^|[\\s?&,;(\"':])(?:pw|pwd|passwd|api_key|access_token|secret_key)=)[^&\\s,;\"'][^&\\s,;\"']*",
        std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, short_secret_query_kv_regex, "$1[REDACTED]");

    // 5. Scrub ClientConfig safe-string proxy_username lines if non-[NONE]
    static const std::regex config_user_regex("(proxy_username\\s*:\\s*)(?!\\[(?:NONE|EMPTY|REDACTED)\\])[^\\r\\n]+",
                                              std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, config_user_regex, "$1[REDACTED]");

    // 6. Scrub OS home directory user segments across macOS, Linux, and Windows paths
    static const std::regex mac_home_regex("(/Users/)([^/\\s\"'\\\\,;]+)", std::regex::ECMAScript);
    text = std::regex_replace(text, mac_home_regex, "$1[REDACTED_USER]");

    static const std::regex linux_home_regex("(/home/)([^/\\s\"'\\\\,;]+)", std::regex::ECMAScript);
    text = std::regex_replace(text, linux_home_regex, "$1[REDACTED_USER]");

    static const std::regex win_home_regex("([A-Za-z]:(?:\\\\|\\\\\\\\)Users(?:\\\\|\\\\\\\\))([^\\\\\\s\"'/,;]+)",
                                           std::regex::ECMAScript | std::regex::icase);
    text = std::regex_replace(text, win_home_regex, "$1[REDACTED_USER]");

    // 7. Scrub @handles after email redaction
    static const std::regex handle_regex("(^|[\\s\"'(:=])@[A-Za-z0-9_.-]{2,}", std::regex::ECMAScript);
    text = std::regex_replace(text, handle_regex, "$1@[REDACTED_HANDLE]");

    return text;
}

bool DiagnosticSanitizer::contains_unredacted_secret_marker(std::string_view text) noexcept {
    if (text.find("PRIVATE KEY-----") != std::string_view::npos) {
        return true;
    }
    if (text.find("sc-bip39-v1:") != std::string_view::npos) {
        return true;
    }

    std::size_t pos = 0U;
    while ((pos = text.find("Bearer ", pos)) != std::string_view::npos) {
        const std::string_view after = text.substr(pos + 7U);
        if (!after.starts_with("[REDACTED]")) {
            return true;
        }
        pos += 7U;
    }

    try {
        static const std::regex jwt_regex("\\beyJ[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]{4,}",
                                          std::regex::ECMAScript);
        return std::regex_search(text.begin(), text.end(), jwt_regex);
    } catch (...) {
        return true;
    }
}

} // namespace securecloud::client::application::managers
