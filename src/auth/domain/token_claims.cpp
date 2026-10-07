#include "auth/domain/token_claims.hpp"

#include <chrono>
#include <nlohmann/json.hpp>
#include <sstream>

namespace securecloud::auth::domain {

namespace {

using json = nlohmann::json;

} // namespace

std::string TokenEnvelopeSerializer::serialize(const AccessTokenClaims& claims, const crypto::ITokenSigner& signer) {
    // 1. Header JSON
    json header_json = {{"alg", "EdDSA"}, {"typ", "SC-Token"}, {"kid", signer.get_key_id()}};
    const std::string header_b64 = crypto::Base64Url::encode(header_json.dump());

    // 2. Payload JSON
    const auto iat_sec = std::chrono::duration_cast<std::chrono::seconds>(claims.issued_at.time_since_epoch()).count();
    const auto exp_sec = std::chrono::duration_cast<std::chrono::seconds>(claims.expires_at.time_since_epoch()).count();

    json payload_json = {{"iss", claims.issuer},
                         {"aud", claims.audience},
                         {"sub", claims.user_id.to_string()},
                         {"uid", claims.user_id.to_string()},
                         {"did", claims.device_id.to_string()},
                         {"sid", claims.session_id.to_string()},
                         {"iat", iat_sec},
                         {"exp", exp_sec},
                         {"jti", claims.jti.to_string()},
                         {"scp", claims.scopes},
                         {"ver", claims.token_version},
                         {"aal", std::string(to_string(claims.authentication_level))}};
    const std::string payload_b64 = crypto::Base64Url::encode(payload_json.dump());

    // 3. Signing Input and Cryptographic Signature
    const std::string signing_input = header_b64 + "." + payload_b64;
    const std::string signature_b64 = signer.sign(signing_input);

    return signing_input + "." + signature_b64;
}

namespace {

TokenValidationResult parse_payload_internal(std::string_view payload_b64,
                                             const TokenEnvelopeParser::ParseOptions& options) {
    auto payload_raw = crypto::Base64Url::decode(payload_b64);
    if (!payload_raw.has_value()) {
        return TokenValidationResult::malformed("Payload is not valid Base64URL");
    }

    json j;
    try {
        j = json::parse(*payload_raw);
    } catch (const std::exception& ex) {
        return TokenValidationResult::malformed(std::string("Malformed JSON in token payload: ") + ex.what());
    }

    if (!j.is_object()) {
        return TokenValidationResult::malformed("Token payload JSON must be an object");
    }

    auto claims = std::make_shared<AccessTokenClaims>();

    // Issuer check
    if (!j.contains("iss") || !j["iss"].is_string()) {
        return TokenValidationResult::malformed("Missing or invalid 'iss' claim");
    }
    claims->issuer = j["iss"].get<std::string>();
    if (!options.expected_issuer.empty() && claims->issuer != options.expected_issuer) {
        return TokenValidationResult::invalid_issuer("Issuer '" + claims->issuer + "' does not match expected '" +
                                                     options.expected_issuer + "'");
    }

    // Audience check
    if (!j.contains("aud") || !j["aud"].is_string()) {
        return TokenValidationResult::malformed("Missing or invalid 'aud' claim");
    }
    claims->audience = j["aud"].get<std::string>();
    if (!options.expected_audience.empty() && claims->audience != options.expected_audience) {
        return TokenValidationResult::invalid_audience("Audience '" + claims->audience + "' does not match expected '" +
                                                       options.expected_audience + "'");
    }

    // User ID
    std::string user_id_str;
    if (j.contains("uid") && j["uid"].is_string()) {
        user_id_str = j["uid"].get<std::string>();
    } else if (j.contains("sub") && j["sub"].is_string()) {
        user_id_str = j["sub"].get<std::string>();
    } else {
        return TokenValidationResult::malformed("Missing 'sub' or 'uid' user identifier claim");
    }

    auto uid_res = Uuid::from_string(user_id_str);
    if (!uid_res.has_value()) {
        return TokenValidationResult::malformed("Invalid UUID format for user identifier");
    }
    claims->user_id = *uid_res;

    // Device ID
    if (!j.contains("did") || !j["did"].is_string()) {
        return TokenValidationResult::malformed("Missing or invalid 'did' device identifier claim");
    }
    auto did_res = Uuid::from_string(j["did"].get<std::string>());
    if (!did_res.has_value()) {
        return TokenValidationResult::malformed("Invalid UUID format for device identifier");
    }
    claims->device_id = *did_res;

    // Session ID
    if (!j.contains("sid") || !j["sid"].is_string()) {
        return TokenValidationResult::malformed("Missing or invalid 'sid' session identifier claim");
    }
    auto sid_res = Uuid::from_string(j["sid"].get<std::string>());
    if (!sid_res.has_value()) {
        return TokenValidationResult::malformed("Invalid UUID format for session identifier");
    }
    claims->session_id = *sid_res;

    // Timestamps
    if (!j.contains("iat") || !j["iat"].is_number()) {
        return TokenValidationResult::malformed("Missing or invalid 'iat' issued-at timestamp claim");
    }
    claims->issued_at = time_point{std::chrono::seconds{j["iat"].get<int64_t>()}};

    if (!j.contains("exp") || !j["exp"].is_number()) {
        return TokenValidationResult::malformed("Missing or invalid 'exp' expiration timestamp claim");
    }
    claims->expires_at = time_point{std::chrono::seconds{j["exp"].get<int64_t>()}};

    // Expiration check with clock skew tolerance
    if (options.current_time > (claims->expires_at + options.clock_skew_tolerance)) {
        return TokenValidationResult::expired("Access token expired at epoch " +
                                              std::to_string(j["exp"].get<int64_t>()));
    }

    // Future issuance check with clock skew tolerance
    if (claims->issued_at > (options.current_time + options.clock_skew_tolerance)) {
        return TokenValidationResult::malformed("Token issued in future beyond clock skew tolerance");
    }

    // JTI
    if (j.contains("jti") && j["jti"].is_string()) {
        auto jti_res = Uuid::from_string(j["jti"].get<std::string>());
        if (jti_res.has_value()) {
            claims->jti = *jti_res;
        } else {
            return TokenValidationResult::malformed("Invalid UUID format for 'jti' claim");
        }
    }

    // Scopes
    if (j.contains("scp") && j["scp"].is_array()) {
        for (const auto& item : j["scp"]) {
            if (item.is_string()) {
                claims->scopes.push_back(item.get<std::string>());
            }
        }
    }

    // Token version
    if (j.contains("ver") && j["ver"].is_number_unsigned()) {
        claims->token_version = j["ver"].get<uint32_t>();
    }

    // Authentication Level
    if (j.contains("aal") && j["aal"].is_string()) {
        auto aal_opt = parse_enum<AuthenticationLevel>(j["aal"].get<std::string>());
        if (aal_opt.has_value()) {
            claims->authentication_level = *aal_opt;
        }
    }

    return TokenValidationResult::valid(std::move(claims));
}

} // namespace

TokenValidationResult TokenEnvelopeParser::parse_and_validate(std::string_view token_string,
                                                              const crypto::ITokenVerifier& verifier,
                                                              ParseOptions options) {
    const size_t first_dot = token_string.find('.');
    if (first_dot == std::string_view::npos) {
        return TokenValidationResult::malformed("Missing first segment delimiter in token");
    }

    const size_t second_dot = token_string.find('.', first_dot + 1);
    if (second_dot == std::string_view::npos) {
        return TokenValidationResult::malformed("Missing second segment delimiter in token");
    }

    if (token_string.find('.', second_dot + 1) != std::string_view::npos) {
        return TokenValidationResult::malformed("Extraneous token segments detected; expected 3 segments");
    }

    const std::string_view signing_input = token_string.substr(0, second_dot);
    const std::string_view signature_b64 = token_string.substr(second_dot + 1);

    if (signature_b64.empty()) {
        return TokenValidationResult::invalid_signature("Empty token signature");
    }

    // Cryptographic signature verification
    if (!verifier.verify(signing_input, signature_b64)) {
        return TokenValidationResult::invalid_signature("Cryptographic signature verification failed");
    }

    // Parse and validate claims
    const std::string_view payload_b64 = token_string.substr(first_dot + 1, second_dot - first_dot - 1);
    return parse_payload_internal(payload_b64, options);
}

TokenValidationResult TokenEnvelopeParser::parse_unverified(std::string_view token_string, ParseOptions options) {
    const size_t first_dot = token_string.find('.');
    if (first_dot == std::string_view::npos) {
        return TokenValidationResult::malformed("Missing first segment delimiter in token");
    }

    const size_t second_dot = token_string.find('.', first_dot + 1);
    if (second_dot == std::string_view::npos) {
        return TokenValidationResult::malformed("Missing second segment delimiter in token");
    }

    const std::string_view payload_b64 = token_string.substr(first_dot + 1, second_dot - first_dot - 1);
    return parse_payload_internal(payload_b64, options);
}

} // namespace securecloud::auth::domain
