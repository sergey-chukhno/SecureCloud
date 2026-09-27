#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace httplib {
struct Request;
}

namespace securecloud::gateway::http {

/// Specific error reason when parsing and extracting a Bearer token.
enum class TokenExtractionErrorKind {
    MissingAuthorizationHeader, ///< HTTP request does not contain an 'Authorization' header
    InvalidScheme,              ///< Scheme is not 'Bearer' (e.g. Basic, Digest, ApiKey)
    EmptyToken,                 ///< 'Bearer' scheme was present but token payload was missing or empty
    MalformedToken,             ///< Token contains invalid characters violating RFC 6750 b64token syntax
    TokenTooLarge,              ///< Token length exceeds the maximum allowable security threshold (4096 bytes)
};

/// Structured error returned when Bearer token extraction fails.
struct TokenExtractionError {
    TokenExtractionErrorKind kind{TokenExtractionErrorKind::MissingAuthorizationHeader};
    std::string message;
};

/// Lightweight monadic result container for token extraction.
template <typename T, typename E = TokenExtractionError> class TokenExtractionResult {
  public:
    TokenExtractionResult(T val) : storage_(std::move(val)) {}
    TokenExtractionResult(E err) : storage_(std::move(err)) {}

    [[nodiscard]] bool has_value() const noexcept { return std::holds_alternative<T>(storage_); }
    [[nodiscard]] bool has_error() const noexcept { return std::holds_alternative<E>(storage_); }
    [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

    [[nodiscard]] const T& value() const& { return std::get<T>(storage_); }
    [[nodiscard]] T& value() & { return std::get<T>(storage_); }
    [[nodiscard]] T&& value() && { return std::get<T>(std::move(storage_)); }

    [[nodiscard]] const E& error() const& { return std::get<E>(storage_); }
    [[nodiscard]] E& error() & { return std::get<E>(storage_); }
    [[nodiscard]] E&& error() && { return std::get<E>(std::move(storage_)); }

  private:
    std::variant<T, E> storage_;
};

/**
 * @brief RFC 6750 Section 2.1 Bearer Token Extractor and Normalizer.
 *
 * Implements strict defense-in-depth extraction of Bearer authentication tokens:
 *
 * 1. Header Injection / CRLF Defense:
 *    Rejects all carriage returns (\r), newlines (\n), and control characters (\0 to \x1f, DEL).
 *
 * 2. Whitespace Tampering / Smuggling Defense:
 *    Normalizes leading/trailing linear whitespace; strictly enforces that exactly one token is present
 *    without embedded spaces, tabs, or multi-token smuggling.
 *
 * 3. Character Whitelist Enforcement (RFC 6750 b64token):
 *    Validates every character against:
 *      ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" and optional "=" padding.
 *    Rejects null bytes, quotes, semicolons, brackets, and non-ASCII/Unicode homoglyphs.
 *
 * 4. Denial of Service (DoS) Defense:
 *    Caps token length at 4096 bytes to prevent memory bloat and CPU exhaustion.
 */
class BearerTokenExtractor {
  public:
    static constexpr std::string_view k_authorization_header = "Authorization";
    static constexpr std::string_view k_bearer_scheme = "Bearer";
    static constexpr size_t k_max_token_length = 4096;

    /**
     * @brief Extract and normalize bearer token from an incoming HTTP request.
     * @param req Incoming HTTP request.
     * @return Extracted token or TokenExtractionError.
     */
    [[nodiscard]] static TokenExtractionResult<std::string> extract(const httplib::Request& req) noexcept;

    /**
     * @brief Extract and normalize bearer token from a raw Authorization header string.
     * @param header_value Full value of the HTTP Authorization header.
     * @return Extracted token or TokenExtractionError.
     */
    [[nodiscard]] static TokenExtractionResult<std::string> extract_from_header(std::string_view header_value) noexcept;

    /**
     * @brief Validates whether a character conforms to RFC 6750 b64token syntax.
     * @param c Character to test.
     * @return true if character is in RFC 6750 b64token set.
     */
    [[nodiscard]] static bool is_valid_b64token_char(char c) noexcept;

  private:
    [[nodiscard]] static std::string_view trim_whitespace(std::string_view sv) noexcept;
    [[nodiscard]] static bool iequals_scheme(std::string_view actual, std::string_view expected) noexcept;
};

} // namespace securecloud::gateway::http
