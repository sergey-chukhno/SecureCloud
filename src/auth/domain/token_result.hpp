#pragma once

#include "domain/entities.hpp"
#include "domain/timestamp.hpp"

#include <chrono>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace securecloud::auth::domain {

// Forward declaration
struct AccessTokenClaims;

/**
 * @brief RAII wrapper for sensitive refresh token secrets to prevent accidental logging.
 */
class SecretTokenString {
  public:
    SecretTokenString() = default;
    explicit SecretTokenString(std::string secret) : secret_(std::move(secret)) {}

    [[nodiscard]] const std::string& raw_secret() const noexcept { return secret_; }
    [[nodiscard]] std::string_view raw_view() const noexcept { return secret_; }
    [[nodiscard]] bool empty() const noexcept { return secret_.empty(); }
    [[nodiscard]] size_t size() const noexcept { return secret_.size(); }

    [[nodiscard]] std::string masked() const {
        if (secret_.size() <= 8) {
            return "[REDACTED_TOKEN]";
        }
        return secret_.substr(0, 6) + "..." + secret_.substr(secret_.size() - 2);
    }

    bool operator==(const SecretTokenString& other) const noexcept { return secret_ == other.secret_; }
    bool operator!=(const SecretTokenString& other) const noexcept { return secret_ != other.secret_; }

    friend std::ostream& operator<<(std::ostream& os, const SecretTokenString& /*token*/) {
        return os << "[REDACTED_TOKEN]";
    }

  private:
    std::string secret_{};
};

/**
 * @brief Token pair containing an access token and a stateful refresh token.
 */
struct TokenPair {
    std::string access_token{};
    SecretTokenString refresh_token{};
    time_point expires_at{};
};

/**
 * @brief Validation status codes for access tokens.
 */
enum class TokenValidationStatus {
    Valid,
    Expired,
    InvalidSignature,
    Malformed,
    InvalidIssuer,
    InvalidAudience,
    DeviceMismatch,
};

[[nodiscard]] inline constexpr std::string_view to_string(TokenValidationStatus status) noexcept {
    switch (status) {
    case TokenValidationStatus::Valid:
        return "Valid";
    case TokenValidationStatus::Expired:
        return "Expired";
    case TokenValidationStatus::InvalidSignature:
        return "InvalidSignature";
    case TokenValidationStatus::Malformed:
        return "Malformed";
    case TokenValidationStatus::InvalidIssuer:
        return "InvalidIssuer";
    case TokenValidationStatus::InvalidAudience:
        return "InvalidAudience";
    case TokenValidationStatus::DeviceMismatch:
        return "DeviceMismatch";
    }
    return "Unknown";
}

/**
 * @brief Result model for token validation and parsing.
 */
struct TokenValidationResult {
    TokenValidationStatus status{TokenValidationStatus::Malformed};
    std::shared_ptr<AccessTokenClaims> claims{nullptr};
    std::string error_message{};

    [[nodiscard]] bool is_valid() const noexcept { return status == TokenValidationStatus::Valid && claims != nullptr; }

    static TokenValidationResult valid(std::shared_ptr<AccessTokenClaims> parsed_claims) {
        TokenValidationResult res;
        res.status = TokenValidationStatus::Valid;
        res.claims = std::move(parsed_claims);
        res.error_message = "Token is valid";
        return res;
    }

    static TokenValidationResult expired(std::string message = "Access token has expired") {
        TokenValidationResult res;
        res.status = TokenValidationStatus::Expired;
        res.error_message = std::move(message);
        return res;
    }

    static TokenValidationResult invalid_signature(std::string message = "Token cryptographic signature is invalid") {
        TokenValidationResult res;
        res.status = TokenValidationStatus::InvalidSignature;
        res.error_message = std::move(message);
        return res;
    }

    static TokenValidationResult malformed(std::string message = "Token format is malformed or invalid") {
        TokenValidationResult res;
        res.status = TokenValidationStatus::Malformed;
        res.error_message = std::move(message);
        return res;
    }

    static TokenValidationResult invalid_issuer(std::string message = "Token issuer does not match expected issuer") {
        TokenValidationResult res;
        res.status = TokenValidationStatus::InvalidIssuer;
        res.error_message = std::move(message);
        return res;
    }

    static TokenValidationResult
    invalid_audience(std::string message = "Token audience does not match expected audience") {
        TokenValidationResult res;
        res.status = TokenValidationStatus::InvalidAudience;
        res.error_message = std::move(message);
        return res;
    }

    static TokenValidationResult
    device_mismatch(std::string message = "Token bound device does not match requesting device") {
        TokenValidationResult res;
        res.status = TokenValidationStatus::DeviceMismatch;
        res.error_message = std::move(message);
        return res;
    }
};

/**
 * @brief Status codes for refresh token rotation.
 */
enum class TokenRefreshStatus {
    Success,
    InvalidToken,
    ExpiredToken,
    DeviceMismatch,
    SessionRevoked,
    CompromiseDetected,
    DatabaseError,
};

[[nodiscard]] inline constexpr std::string_view to_string(TokenRefreshStatus status) noexcept {
    switch (status) {
    case TokenRefreshStatus::Success:
        return "Success";
    case TokenRefreshStatus::InvalidToken:
        return "InvalidToken";
    case TokenRefreshStatus::ExpiredToken:
        return "ExpiredToken";
    case TokenRefreshStatus::DeviceMismatch:
        return "DeviceMismatch";
    case TokenRefreshStatus::SessionRevoked:
        return "SessionRevoked";
    case TokenRefreshStatus::CompromiseDetected:
        return "CompromiseDetected";
    case TokenRefreshStatus::DatabaseError:
        return "DatabaseError";
    }
    return "Unknown";
}

/**
 * @brief Result model for refresh token rotation.
 */
struct TokenRefreshResult {
    TokenRefreshStatus status{TokenRefreshStatus::InvalidToken};
    std::optional<TokenPair> tokens{std::nullopt};
    std::string error_message{};

    [[nodiscard]] bool is_success() const noexcept {
        return status == TokenRefreshStatus::Success && tokens.has_value();
    }

    static TokenRefreshResult success(TokenPair pair) {
        TokenRefreshResult res;
        res.status = TokenRefreshStatus::Success;
        res.tokens = std::move(pair);
        res.error_message = "Tokens rotated successfully";
        return res;
    }

    static TokenRefreshResult invalid_token(std::string message = "Refresh token is invalid or not found") {
        TokenRefreshResult res;
        res.status = TokenRefreshStatus::InvalidToken;
        res.error_message = std::move(message);
        return res;
    }

    static TokenRefreshResult expired_token(std::string message = "Refresh token has expired") {
        TokenRefreshResult res;
        res.status = TokenRefreshStatus::ExpiredToken;
        res.error_message = std::move(message);
        return res;
    }

    static TokenRefreshResult device_mismatch(std::string message = "Refresh token device does not match request") {
        TokenRefreshResult res;
        res.status = TokenRefreshStatus::DeviceMismatch;
        res.error_message = std::move(message);
        return res;
    }

    static TokenRefreshResult session_revoked(std::string message = "Associated session has been revoked") {
        TokenRefreshResult res;
        res.status = TokenRefreshStatus::SessionRevoked;
        res.error_message = std::move(message);
        return res;
    }

    static TokenRefreshResult
    compromise_detected(std::string message = "Refresh token reuse detected; session revoked") {
        TokenRefreshResult res;
        res.status = TokenRefreshStatus::CompromiseDetected;
        res.error_message = std::move(message);
        return res;
    }

    static TokenRefreshResult database_error(std::string message = "Database error during token rotation") {
        TokenRefreshResult res;
        res.status = TokenRefreshStatus::DatabaseError;
        res.error_message = std::move(message);
        return res;
    }
};

} // namespace securecloud::auth::domain
