#include "sensitive_data_guard.hpp"

#include <algorithm>
#include <array>
#include <cctype>

namespace securecloud::audit::domain {

namespace {

constexpr std::array<std::string_view, 13> k_forbidden_key_terms = {
    "password", "passwd", "secret", "token", "credential",
    "private_key", "privkey", "mfa", "totp", "plaintext",
    "seed", "salt", "api_key"
};

constexpr std::array<std::string_view, 3> k_pem_key_headers = {
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----"
};

std::string to_lower_string(std::string_view sv) {
    std::string lower(sv);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lower;
}

bool is_base64url_char(char c) noexcept {
    auto uc = static_cast<unsigned char>(c);
    return std::isalnum(uc) || c == '-' || c == '_';
}

bool contains_jwt_pattern(std::string_view value) noexcept {
    size_t pos = 0;
    while ((pos = value.find("eyJ", pos)) != std::string_view::npos) {
        // First segment starts with "eyJ"
        size_t idx = pos + 3;
        while (idx < value.size() && is_base64url_char(value[idx])) {
            ++idx;
        }

        if (idx < value.size() && value[idx] == '.' && idx > pos + 3) {
            // Second segment
            size_t seg2_start = idx + 1;
            idx = seg2_start;
            while (idx < value.size() && is_base64url_char(value[idx])) {
                ++idx;
            }

            if (idx < value.size() && value[idx] == '.' && idx > seg2_start) {
                // Third segment
                size_t seg3_start = idx + 1;
                idx = seg3_start;
                while (idx < value.size() && is_base64url_char(value[idx])) {
                    ++idx;
                }

                if (idx > seg3_start) {
                    return true; // Valid JWT structure found
                }
            }
        }
        pos += 3;
    }
    return false;
}

bool contains_pem_key_header(std::string_view value) noexcept {
    for (const auto& header : k_pem_key_headers) {
        if (value.find(header) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

} // namespace

AuditValidationResult SensitiveDataGuard::inspect(const AuditEvent& event) noexcept {
    AuditValidationResult result;

    for (const auto& [key, value] : event.metadata) {
        std::string lower_key = to_lower_string(key);

        for (const auto& term : k_forbidden_key_terms) {
            if (lower_key.find(term) != std::string_view::npos) {
                result.add_error({
                    AuditValidationErrorCode::SensitiveDataDetected,
                    "metadata." + key,
                    "Sensitive key forbidden in metadata: '" + key + "' contains prohibited credential term"
                });
                break;
            }
        }

        if (contains_pem_key_header(value) || contains_jwt_pattern(value)) {
            result.add_error({
                AuditValidationErrorCode::SensitiveDataDetected,
                "metadata." + key,
                "Value contains prohibited secret or key material"
            });
        }
    }

    return result;
}

std::string SensitiveDataGuard::sanitize_diagnostic(std::string_view raw) {
    std::string sanitized(raw);

    for (const auto& header : k_pem_key_headers) {
        size_t pos = 0;
        while ((pos = sanitized.find(header, pos)) != std::string::npos) {
            sanitized.replace(pos, header.size(), "[REDACTED]");
            pos += 10;
        }
    }

    std::string lower = to_lower_string(sanitized);
    for (const auto& term : k_forbidden_key_terms) {
        size_t pos = 0;
        while ((pos = lower.find(term, pos)) != std::string::npos) {
            sanitized.replace(pos, term.size(), "[REDACTED]");
            lower.replace(pos, term.size(), "[REDACTED]");
            pos += 10;
        }
    }

    return sanitized;
}

} // namespace securecloud::audit::domain