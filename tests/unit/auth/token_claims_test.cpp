#include "auth/crypto/token_crypto.hpp"
#include "auth/domain/token_claims.hpp"
#include "auth/domain/token_result.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <sstream>

namespace securecloud::auth::domain::test {
namespace {

AccessTokenClaims create_sample_claims() {
    auto now = std::chrono::system_clock::now();
    AccessTokenClaims claims;
    claims.issuer = "https://auth.securecloud.io";
    claims.audience = "https://gateway.securecloud.io";
    claims.user_id = Uuid::generate_v7();
    claims.device_id = Uuid::generate_v7();
    claims.session_id = Uuid::generate_v7();
    claims.issued_at = now;
    claims.expires_at = now + std::chrono::minutes(15);
    claims.jti = Uuid::generate_v7();
    claims.scopes = {"access", "files:read", "files:write"};
    claims.token_version = 1;
    claims.authentication_level = AuthenticationLevel::PrimaryOnly;
    return claims;
}

// ============================================================================
// 1. Serialization and Parsing Fidelity Tests
// ============================================================================

TEST(TokenClaimsTest, RoundTripSerializationAndParsing_Success) {
    crypto::Ed25519TokenSigner signer("sc-key-1");
    auto verifier = crypto::Ed25519TokenVerifier::from_signer(signer);

    auto original_claims = create_sample_claims();
    std::string token_str = TokenEnvelopeSerializer::serialize(original_claims, signer);

    ASSERT_FALSE(token_str.empty());
    EXPECT_NE(token_str.find('.'), std::string::npos);

    auto result = TokenEnvelopeParser::parse_and_validate(token_str, *verifier);
    ASSERT_TRUE(result.is_valid()) << "Parsing failed: " << result.error_message;
    ASSERT_NE(result.claims, nullptr);

    const auto& parsed = *result.claims;
    EXPECT_EQ(parsed.issuer, original_claims.issuer);
    EXPECT_EQ(parsed.audience, original_claims.audience);
    EXPECT_EQ(parsed.user_id, original_claims.user_id);
    EXPECT_EQ(parsed.device_id, original_claims.device_id);
    EXPECT_EQ(parsed.session_id, original_claims.session_id);
    EXPECT_EQ(parsed.jti, original_claims.jti);
    EXPECT_EQ(parsed.token_version, original_claims.token_version);
    EXPECT_EQ(parsed.authentication_level, original_claims.authentication_level);
    EXPECT_EQ(parsed.scopes, original_claims.scopes);
    EXPECT_TRUE(parsed.has_scope("files:read"));
    EXPECT_FALSE(parsed.has_scope("admin:delete"));

    // Timestamps have 1-second resolution in standard epoch encoding
    auto orig_exp_sec =
        std::chrono::duration_cast<std::chrono::seconds>(original_claims.expires_at.time_since_epoch()).count();
    auto parsed_exp_sec =
        std::chrono::duration_cast<std::chrono::seconds>(parsed.expires_at.time_since_epoch()).count();
    EXPECT_EQ(orig_exp_sec, parsed_exp_sec);
}

// ============================================================================
// 2. Expiration and Clock Skew Tests
// ============================================================================

TEST(TokenClaimsTest, ExpiredToken_ReturnsExpiredStatus) {
    crypto::Ed25519TokenSigner signer;
    auto verifier = crypto::Ed25519TokenVerifier::from_signer(signer);

    auto now = std::chrono::system_clock::now();
    auto claims = create_sample_claims();
    claims.issued_at = now - std::chrono::hours(1);
    claims.expires_at = now - std::chrono::minutes(5); // Expired 5 minutes ago

    std::string token_str = TokenEnvelopeSerializer::serialize(claims, signer);

    TokenEnvelopeParser::ParseOptions options;
    options.current_time = now;
    options.clock_skew_tolerance = std::chrono::seconds{30};

    auto result = TokenEnvelopeParser::parse_and_validate(token_str, *verifier, options);
    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, TokenValidationStatus::Expired);
}

TEST(TokenClaimsTest, ClockSkewTolerance_AcceptsMarginallyExpiredToken) {
    crypto::Ed25519TokenSigner signer;
    auto verifier = crypto::Ed25519TokenVerifier::from_signer(signer);

    auto now = std::chrono::system_clock::now();
    auto claims = create_sample_claims();
    claims.issued_at = now - std::chrono::minutes(15);
    claims.expires_at = now - std::chrono::seconds(10); // Expired by 10s

    std::string token_str = TokenEnvelopeSerializer::serialize(claims, signer);

    // 1. With 30s clock skew tolerance, 10s skew is tolerated
    TokenEnvelopeParser::ParseOptions opt_tolerant;
    opt_tolerant.current_time = now;
    opt_tolerant.clock_skew_tolerance = std::chrono::seconds{30};
    auto res_tolerant = TokenEnvelopeParser::parse_and_validate(token_str, *verifier, opt_tolerant);
    EXPECT_TRUE(res_tolerant.is_valid());

    // 2. With 5s clock skew tolerance, 10s skew is rejected
    TokenEnvelopeParser::ParseOptions opt_strict;
    opt_strict.current_time = now;
    opt_strict.clock_skew_tolerance = std::chrono::seconds{5};
    auto res_strict = TokenEnvelopeParser::parse_and_validate(token_str, *verifier, opt_strict);
    EXPECT_FALSE(res_strict.is_valid());
    EXPECT_EQ(res_strict.status, TokenValidationStatus::Expired);
}

TEST(TokenClaimsTest, FutureIssuedTokenBeyondClockSkew_ReturnsMalformed) {
    crypto::Ed25519TokenSigner signer;
    auto verifier = crypto::Ed25519TokenVerifier::from_signer(signer);

    auto now = std::chrono::system_clock::now();
    auto claims = create_sample_claims();
    claims.issued_at = now + std::chrono::minutes(5); // 5 minutes in future
    claims.expires_at = now + std::chrono::minutes(20);

    std::string token_str = TokenEnvelopeSerializer::serialize(claims, signer);

    TokenEnvelopeParser::ParseOptions options;
    options.current_time = now;
    options.clock_skew_tolerance = std::chrono::seconds{30};

    auto result = TokenEnvelopeParser::parse_and_validate(token_str, *verifier, options);
    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, TokenValidationStatus::Malformed);
}

// ============================================================================
// 3. Signature & Cryptographic Integrity Tests
// ============================================================================

TEST(TokenClaimsTest, InvalidSignature_MismatchedKey_ReturnsInvalidSignature) {
    crypto::Ed25519TokenSigner signer1("key-1");
    crypto::Ed25519TokenSigner signer2("key-2");
    auto verifier2 = crypto::Ed25519TokenVerifier::from_signer(signer2);

    auto claims = create_sample_claims();
    std::string token_str = TokenEnvelopeSerializer::serialize(claims, signer1);

    auto result = TokenEnvelopeParser::parse_and_validate(token_str, *verifier2);
    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, TokenValidationStatus::InvalidSignature);
}

TEST(TokenClaimsTest, TamperedPayload_ReturnsInvalidSignature) {
    crypto::Ed25519TokenSigner signer;
    auto verifier = crypto::Ed25519TokenVerifier::from_signer(signer);

    auto claims = create_sample_claims();
    std::string token_str = TokenEnvelopeSerializer::serialize(claims, signer);

    // Tamper with payload segment
    size_t first_dot = token_str.find('.');
    ASSERT_NE(first_dot, std::string::npos);
    token_str[first_dot + 5] = (token_str[first_dot + 5] == 'A') ? 'B' : 'A';

    auto result = TokenEnvelopeParser::parse_and_validate(token_str, *verifier);
    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, TokenValidationStatus::InvalidSignature);
}

// ============================================================================
// 4. Issuer and Audience Enforcement Tests
// ============================================================================

TEST(TokenClaimsTest, InvalidIssuer_ReturnsInvalidIssuerStatus) {
    crypto::Ed25519TokenSigner signer;
    auto verifier = crypto::Ed25519TokenVerifier::from_signer(signer);

    auto claims = create_sample_claims();
    claims.issuer = "https://untrusted-auth.evil.com";

    std::string token_str = TokenEnvelopeSerializer::serialize(claims, signer);

    TokenEnvelopeParser::ParseOptions options;
    options.expected_issuer = "https://auth.securecloud.io";

    auto result = TokenEnvelopeParser::parse_and_validate(token_str, *verifier, options);
    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, TokenValidationStatus::InvalidIssuer);
}

TEST(TokenClaimsTest, InvalidAudience_ReturnsInvalidAudienceStatus) {
    crypto::Ed25519TokenSigner signer;
    auto verifier = crypto::Ed25519TokenVerifier::from_signer(signer);

    auto claims = create_sample_claims();
    claims.audience = "https://untrusted-api.evil.com";

    std::string token_str = TokenEnvelopeSerializer::serialize(claims, signer);

    TokenEnvelopeParser::ParseOptions options;
    options.expected_audience = "https://gateway.securecloud.io";

    auto result = TokenEnvelopeParser::parse_and_validate(token_str, *verifier, options);
    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, TokenValidationStatus::InvalidAudience);
}

// ============================================================================
// 5. Malformed Token Structure Tests
// ============================================================================

TEST(TokenClaimsTest, MalformedSegments_ReturnsMalformedStatus) {
    crypto::Ed25519TokenSigner signer;
    auto verifier = crypto::Ed25519TokenVerifier::from_signer(signer);

    EXPECT_EQ(TokenEnvelopeParser::parse_and_validate("", *verifier).status, TokenValidationStatus::Malformed);
    EXPECT_EQ(TokenEnvelopeParser::parse_and_validate("single-segment", *verifier).status,
              TokenValidationStatus::Malformed);
    EXPECT_EQ(TokenEnvelopeParser::parse_and_validate("header.payload", *verifier).status,
              TokenValidationStatus::Malformed);
    EXPECT_EQ(TokenEnvelopeParser::parse_and_validate("header.payload.sig.extra", *verifier).status,
              TokenValidationStatus::Malformed);
}

// ============================================================================
// 6. SecretTokenString & Result Helpers Tests
// ============================================================================

TEST(TokenClaimsTest, SecretTokenString_RedactsRawSecretInStreams) {
    const std::string raw = "sc_rt_super_secret_refresh_token_abc123xyz789";
    SecretTokenString secret_token(raw);

    EXPECT_EQ(secret_token.raw_secret(), raw);
    EXPECT_EQ(secret_token.raw_view(), raw);
    EXPECT_FALSE(secret_token.empty());
    EXPECT_EQ(secret_token.size(), raw.size());

    // Stream operator MUST output [REDACTED_TOKEN]
    std::ostringstream oss;
    oss << secret_token;
    std::string stream_out = oss.str();

    EXPECT_EQ(stream_out, "[REDACTED_TOKEN]");
    EXPECT_EQ(stream_out.find("super_secret"), std::string::npos);

    // Masked accessor test
    EXPECT_EQ(secret_token.masked(), "sc_rt_...89");

    SecretTokenString copy(raw);
    EXPECT_EQ(secret_token, copy);
}

TEST(TokenClaimsTest, TokenRefreshResult_FactoryMethodsAndStatusStrings) {
    TokenPair pair;
    pair.access_token = "access_token_123";
    pair.refresh_token = SecretTokenString("refresh_token_456");
    pair.expires_at = std::chrono::system_clock::now();

    auto success_res = TokenRefreshResult::success(pair);
    EXPECT_TRUE(success_res.is_success());
    EXPECT_EQ(success_res.status, TokenRefreshStatus::Success);
    EXPECT_EQ(to_string(success_res.status), "Success");

    auto compromise_res = TokenRefreshResult::compromise_detected("Reuse detected!");
    EXPECT_FALSE(compromise_res.is_success());
    EXPECT_EQ(compromise_res.status, TokenRefreshStatus::CompromiseDetected);
    EXPECT_EQ(to_string(compromise_res.status), "CompromiseDetected");

    auto expired_res = TokenRefreshResult::expired_token("Token expired");
    EXPECT_EQ(expired_res.status, TokenRefreshStatus::ExpiredToken);
    EXPECT_EQ(to_string(expired_res.status), "ExpiredToken");
}

} // namespace
} // namespace securecloud::auth::domain::test
