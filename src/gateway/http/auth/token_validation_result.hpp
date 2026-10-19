#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace securecloud::gateway::http {

/// Specific error reason when validating an access token or session.
enum class TokenValidationErrorKind {
    TokenExpired,       ///< Token expiration timestamp is in the past
    SessionRevoked,     ///< Session was revoked or marked inactive in Auth authority
    InvalidSignature,   ///< Token signature verification failed or token is forged
    MfaRequired,        ///< Route requires MFA assurance but token is PRIMARY only
    InsufficientScope,  ///< Token does not contain required scope for the route
    ServiceUnavailable, ///< Downstream Auth service outage or communication failure
    MalformedToken,     ///< Token claims missing, invalid format, or unparseable
    InternalError,      ///< Internal unexpected validation failure
};

/// Structured error returned when token validation fails.
struct TokenValidationError {
    TokenValidationErrorKind kind{TokenValidationErrorKind::InternalError};
    std::string message;

    bool operator==(const TokenValidationError& other) const = default;
};

/// Lightweight monadic result container for token validation.
template <typename T, typename E = TokenValidationError> class TokenValidationResult {
  public:
    TokenValidationResult(T val) : storage_(std::move(val)) {}
    TokenValidationResult(E err) : storage_(std::move(err)) {}

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

} // namespace securecloud::gateway::http
