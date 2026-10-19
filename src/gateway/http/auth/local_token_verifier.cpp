#include "http/auth/local_token_verifier.hpp"

#include <chrono>
#include <stdexcept>
#include <utility>

namespace securecloud::gateway::http {

LocalTokenVerifier::LocalTokenVerifier(std::shared_ptr<securecloud::auth::crypto::ITokenVerifier> verifier,
                                       LocalTokenVerifierOptions options)
    : verifier_(std::move(verifier)), options_(std::move(options)) {
    if (!verifier_) {
        throw std::invalid_argument("LocalTokenVerifier: verifier cannot be null");
    }
}

std::unique_ptr<LocalTokenVerifier> LocalTokenVerifier::from_public_key_pem(std::string_view pem_public_key,
                                                                            std::string key_id,
                                                                            LocalTokenVerifierOptions options) {
    try {
        auto verifier =
            securecloud::auth::crypto::Ed25519TokenVerifier::from_public_key_pem(pem_public_key, std::move(key_id));
        if (!verifier) {
            throw std::invalid_argument("LocalTokenVerifier: failed to parse PEM public key");
        }
        return std::make_unique<LocalTokenVerifier>(std::move(verifier), std::move(options));
    } catch (const std::invalid_argument&) {
        throw;
    } catch (const std::exception& ex) {
        throw std::invalid_argument(std::string("LocalTokenVerifier: failed to parse PEM public key: ") + ex.what());
    }
}

std::unique_ptr<LocalTokenVerifier> LocalTokenVerifier::from_public_key_raw(const std::vector<uint8_t>& raw_public_key,
                                                                            std::string key_id,
                                                                            LocalTokenVerifierOptions options) {
    try {
        auto verifier =
            securecloud::auth::crypto::Ed25519TokenVerifier::from_public_key_raw(raw_public_key, std::move(key_id));
        if (!verifier) {
            throw std::invalid_argument("LocalTokenVerifier: failed to parse raw Ed25519 public key");
        }
        return std::make_unique<LocalTokenVerifier>(std::move(verifier), std::move(options));
    } catch (const std::invalid_argument&) {
        throw;
    } catch (const std::exception& ex) {
        throw std::invalid_argument(std::string("LocalTokenVerifier: failed to parse raw Ed25519 public key: ") +
                                    ex.what());
    }
}

AuthenticatedResult LocalTokenVerifier::validate(const std::string& token, const std::string& session_id,
                                                 const std::string& /*request_id*/) {
    if (token.empty()) {
        return TokenValidationError{TokenValidationErrorKind::MalformedToken, "Bearer token string cannot be empty"};
    }

    securecloud::auth::domain::TokenParseOptions parse_opts;
    parse_opts.expected_issuer = options_.expected_issuer;
    parse_opts.expected_audience = options_.expected_audience;
    parse_opts.clock_skew_tolerance = options_.clock_skew_tolerance;
    parse_opts.current_time = std::chrono::system_clock::now();

    auto parse_res = securecloud::auth::domain::TokenEnvelopeParser::parse_and_validate(token, *verifier_, parse_opts);
    if (!parse_res.is_valid()) {
        switch (parse_res.status) {
        case securecloud::auth::domain::TokenValidationStatus::Expired:
            return TokenValidationError{TokenValidationErrorKind::TokenExpired, parse_res.error_message};
        case securecloud::auth::domain::TokenValidationStatus::InvalidSignature:
            return TokenValidationError{TokenValidationErrorKind::InvalidSignature, parse_res.error_message};
        case securecloud::auth::domain::TokenValidationStatus::Malformed:
            return TokenValidationError{TokenValidationErrorKind::MalformedToken, parse_res.error_message};
        case securecloud::auth::domain::TokenValidationStatus::InvalidIssuer:
        case securecloud::auth::domain::TokenValidationStatus::InvalidAudience:
        case securecloud::auth::domain::TokenValidationStatus::DeviceMismatch:
            return TokenValidationError{TokenValidationErrorKind::MalformedToken, parse_res.error_message};
        default:
            return TokenValidationError{TokenValidationErrorKind::InternalError, parse_res.error_message};
        }
    }

    const auto& claims = *parse_res.claims;

    // Session binding enforcement: if session_id is explicitly presented in request, it must match the claim
    if (!session_id.empty() && claims.session_id.to_string() != session_id) {
        return TokenValidationError{TokenValidationErrorKind::SessionRevoked,
                                    "Session identifier does not match token session claim"};
    }

    // Map domain authentication level to protobuf/gateway authentication level
    securecloud::auth::v1::AuthenticationLevel auth_level =
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY;
    if (claims.authentication_level == securecloud::auth::domain::AuthenticationLevel::MfaVerified) {
        auth_level = securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED;
    }

    const int64_t expires_at_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(claims.expires_at.time_since_epoch()).count();

    AuthenticatedContext context(claims.user_id.to_string(), claims.device_id.to_string(),
                                 claims.session_id.to_string(), auth_level, claims.scopes, expires_at_ms);

    return context;
}

} // namespace securecloud::gateway::http
