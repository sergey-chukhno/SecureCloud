#include "http/bearer_token_extractor.hpp"

#include <cctype>
#include <httplib.h>
#include <string>
#include <string_view>

namespace securecloud::gateway::http {

std::string_view BearerTokenExtractor::trim_whitespace(std::string_view sv) noexcept {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' || sv.front() == '\r' || sv.front() == '\n')) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r' || sv.back() == '\n')) {
        sv.remove_suffix(1);
    }
    return sv;
}

bool BearerTokenExtractor::iequals_scheme(std::string_view actual, std::string_view expected) noexcept {
    if (actual.size() != expected.size()) {
        return false;
    }
    for (size_t i = 0; i < actual.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(actual[i])) !=
            std::tolower(static_cast<unsigned char>(expected[i]))) {
            return false;
        }
    }
    return true;
}

bool BearerTokenExtractor::is_valid_b64token_char(char c) noexcept {
    const auto uc = static_cast<unsigned char>(c);
    // RFC 6750 Section 2.1 b64token syntax:
    // 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
    if ((uc >= 'a' && uc <= 'z') || (uc >= 'A' && uc <= 'Z') || (uc >= '0' && uc <= '9')) {
        return true;
    }
    return c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/' || c == '=';
}

TokenExtractionResult<std::string> BearerTokenExtractor::extract(const httplib::Request& req) noexcept {
    const std::string header_name(k_authorization_header);
    if (!req.has_header(header_name)) {
        return TokenExtractionError{
            .kind = TokenExtractionErrorKind::MissingAuthorizationHeader,
            .message = "Missing Authorization header in HTTP request",
        };
    }

    return extract_from_header(req.get_header_value(header_name));
}

TokenExtractionResult<std::string> BearerTokenExtractor::extract_from_header(std::string_view header_value) noexcept {
    const auto trimmed = trim_whitespace(header_value);
    if (trimmed.empty()) {
        return TokenExtractionError{
            .kind = TokenExtractionErrorKind::MissingAuthorizationHeader,
            .message = "Authorization header is empty",
        };
    }

    // Find the whitespace separator between scheme and token parameter
    const size_t separator_pos = trimmed.find_first_of(" \t");
    if (separator_pos == std::string_view::npos) {
        // No whitespace separator found in header
        if (iequals_scheme(trimmed, k_bearer_scheme)) {
            return TokenExtractionError{
                .kind = TokenExtractionErrorKind::EmptyToken,
                .message = "Bearer scheme provided without token payload",
            };
        }
        return TokenExtractionError{
            .kind = TokenExtractionErrorKind::InvalidScheme,
            .message = "Authorization header does not specify a valid Bearer scheme",
        };
    }

    const auto scheme = trimmed.substr(0, separator_pos);
    if (!iequals_scheme(scheme, k_bearer_scheme)) {
        return TokenExtractionError{
            .kind = TokenExtractionErrorKind::InvalidScheme,
            .message = "Unsupported authorization scheme: expected Bearer",
        };
    }

    // Extract token part and trim leading/trailing whitespace
    auto token_part = trimmed.substr(separator_pos);
    token_part = trim_whitespace(token_part);

    if (token_part.empty()) {
        return TokenExtractionError{
            .kind = TokenExtractionErrorKind::EmptyToken,
            .message = "Bearer token payload is empty",
        };
    }

    if (token_part.length() > k_max_token_length) {
        return TokenExtractionError{
            .kind = TokenExtractionErrorKind::TokenTooLarge,
            .message = "Bearer token exceeds maximum allowable length of 4096 bytes",
        };
    }

    // Validate that every character strictly adheres to RFC 6750 b64token character set
    for (size_t i = 0; i < token_part.length(); ++i) {
        const char c = token_part[i];
        if (!is_valid_b64token_char(c)) {
            return TokenExtractionError{
                .kind = TokenExtractionErrorKind::MalformedToken,
                .message = "Bearer token contains invalid or forbidden characters",
            };
        }
    }

    return std::string(token_part);
}

} // namespace securecloud::gateway::http
