#pragma once

#include "auth/crypto/token_crypto.hpp"
#include "domain/enums.hpp"
#include "domain/timestamp.hpp"
#include "domain/token_result.hpp"
#include "domain/uuid.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::auth::domain {

/**
 * @brief Structured, strongly-typed claims model for the Signed Access Token Envelope.
 *
 * Implements the approved zero-trust payload: strictly bound to session_id and device_id,
 * carrying necessary authorization scopes, token version, and authentication assurance.
 */
struct AccessTokenClaims {
    std::string issuer{"https://auth.securecloud.io"};
    std::string audience{"https://gateway.securecloud.io"};
    Uuid user_id{};
    Uuid device_id{};
    Uuid session_id{};
    time_point issued_at{};
    time_point expires_at{};
    Uuid jti{}; // Unique token identifier (RFC 4122 / UUIDv7)
    std::vector<std::string> scopes{};
    uint32_t token_version{1};
    AuthenticationLevel authentication_level{AuthenticationLevel::PrimaryOnly};

    [[nodiscard]] bool is_expired(time_point now,
                                  std::chrono::seconds clock_skew = std::chrono::seconds{30}) const noexcept {
        return now > (expires_at + clock_skew);
    }

    [[nodiscard]] bool has_scope(std::string_view scope) const noexcept {
        for (const auto& s : scopes) {
            if (s == scope) {
                return true;
            }
        }
        return false;
    }
};

/**
 * @brief Serializes AccessTokenClaims into a compact, cryptographically signed token envelope.
 *
 * Wire format: <base64url_header>.<base64url_payload>.<base64url_signature>
 */
class TokenEnvelopeSerializer {
  public:
    [[nodiscard]] static std::string serialize(const AccessTokenClaims& claims, const crypto::ITokenSigner& signer);
};

/**
 * @brief Configuration options for token envelope parsing and validation.
 */
struct TokenParseOptions {
    std::string expected_issuer{"https://auth.securecloud.io"};
    std::string expected_audience{"https://gateway.securecloud.io"};
    std::chrono::seconds clock_skew_tolerance{30};
    time_point current_time{std::chrono::system_clock::now()};
};

/**
 * @brief Validates and parses a signed access token envelope.
 */
class TokenEnvelopeParser {
  public:
    using ParseOptions = TokenParseOptions;

    /**
     * @brief Cryptographically validates the signature and parses all claims.
     */
    [[nodiscard]] static TokenValidationResult parse_and_validate(std::string_view token_string,
                                                                  const crypto::ITokenVerifier& verifier,
                                                                  ParseOptions options = {});

    /**
     * @brief Parses and validates claims without verifying cryptographic signature.
     *
     * Useful for preliminary inspection or debugging before key lookup.
     */
    [[nodiscard]] static TokenValidationResult parse_unverified(std::string_view token_string,
                                                                ParseOptions options = {});
};

} // namespace securecloud::auth::domain
