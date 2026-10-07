#include "auth/crypto/token_crypto.hpp"
#include "auth/domain/token_claims.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/auth/local_token_verifier.hpp"
#include "http/auth/token_validation_result.hpp"

#include <chrono>
#include <cmath>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::gateway::http::test {
namespace {

using securecloud::auth::crypto::Ed25519TokenSigner;
using securecloud::auth::crypto::Ed25519TokenVerifier;
using securecloud::auth::domain::AccessTokenClaims;
using securecloud::auth::domain::TokenEnvelopeSerializer;
using securecloud::auth::domain::Uuid;

AccessTokenClaims create_test_claims(std::chrono::seconds validity = std::chrono::minutes(15)) {
    const auto now = std::chrono::system_clock::now();
    AccessTokenClaims claims;
    claims.issuer = "https://auth.securecloud.io";
    claims.audience = "https://gateway.securecloud.io";
    claims.user_id = Uuid::generate_v7();
    claims.device_id = Uuid::generate_v7();
    claims.session_id = Uuid::generate_v7();
    claims.issued_at = now;
    claims.expires_at = now + validity;
    claims.jti = Uuid::generate_v7();
    claims.scopes = {"access", "files:read", "files:write", "messages:read"};
    claims.token_version = 1;
    claims.authentication_level = securecloud::auth::domain::AuthenticationLevel::PrimaryOnly;
    return claims;
}

// ============================================================================
// 1. Successful Local Validation
// ============================================================================

TEST(LocalTokenVerifierTest, ValidationSuccess_ValidToken_ProducesAuthenticatedContext) {
    // 1. Auth Service holds private key and signs access token
    Ed25519TokenSigner auth_signer("sc-auth-v1");
    auto claims = create_test_claims();
    std::string token = TokenEnvelopeSerializer::serialize(claims, auth_signer);

    // 2. Gateway is provisioned ONLY with Auth's public verification key (PEM format)
    std::string public_pem = auth_signer.get_public_key_pem();
    auto gateway_verifier = LocalTokenVerifier::from_public_key_pem(public_pem, "sc-auth-v1");
    ASSERT_NE(gateway_verifier, nullptr);

    // 3. Gateway verifies token locally offline (0 RPCs, 0 database calls)
    auto result = gateway_verifier->validate(token, claims.session_id.to_string());

    ASSERT_TRUE(result.has_value());
    const auto& context = result.value();

    EXPECT_EQ(context.user_id(), claims.user_id.to_string());
    EXPECT_EQ(context.device_id(), claims.device_id.to_string());
    EXPECT_EQ(context.session_id(), claims.session_id.to_string());
    EXPECT_EQ(context.authentication_level(), securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    EXPECT_EQ(context.scopes(), claims.scopes);
    EXPECT_TRUE(context.has_scope("files:read"));
    EXPECT_FALSE(context.has_scope("admin:delete"));

    int64_t expected_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(claims.expires_at.time_since_epoch()).count();
    const int64_t diff_ms = std::abs(context.expires_at_epoch_ms() - expected_ms);
    EXPECT_LE(diff_ms, 1000);
}

TEST(LocalTokenVerifierTest, ValidationSuccess_MfaVerifiedLevelMappedCorrectly) {
    Ed25519TokenSigner auth_signer("sc-auth-v1");
    auto claims = create_test_claims();
    claims.authentication_level = securecloud::auth::domain::AuthenticationLevel::MfaVerified;
    std::string token = TokenEnvelopeSerializer::serialize(claims, auth_signer);

    auto gateway_verifier = LocalTokenVerifier::from_public_key_pem(auth_signer.get_public_key_pem());
    ASSERT_NE(gateway_verifier, nullptr);

    auto result = gateway_verifier->validate(token);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().authentication_level(),
              securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    EXPECT_TRUE(result.value().is_mfa_verified());
}

// ============================================================================
// 2. Validation Rejections: Expiration & Tampering
// ============================================================================

TEST(LocalTokenVerifierTest, ValidationFailure_ExpiredToken_ReturnsTokenExpired) {
    Ed25519TokenSigner auth_signer("sc-auth-v1");
    auto claims = create_test_claims(std::chrono::seconds(-60)); // Expired 60s ago
    std::string token = TokenEnvelopeSerializer::serialize(claims, auth_signer);

    auto gateway_verifier = LocalTokenVerifier::from_public_key_pem(auth_signer.get_public_key_pem());
    auto result = gateway_verifier->validate(token);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, TokenValidationErrorKind::TokenExpired);
    EXPECT_FALSE(result.error().message.empty());
}

TEST(LocalTokenVerifierTest, ValidationFailure_TamperedPayload_ReturnsInvalidSignature) {
    Ed25519TokenSigner auth_signer("sc-auth-v1");
    auto claims = create_test_claims();
    std::string token = TokenEnvelopeSerializer::serialize(claims, auth_signer);

    // Tamper with the payload (modify characters in the middle segment)
    auto first_dot = token.find('.');
    auto second_dot = token.find('.', first_dot + 1);
    ASSERT_NE(first_dot, std::string::npos);
    ASSERT_NE(second_dot, std::string::npos);

    // Flip a character in the payload
    token[first_dot + 2] = (token[first_dot + 2] == 'a') ? 'b' : 'a';

    auto gateway_verifier = LocalTokenVerifier::from_public_key_pem(auth_signer.get_public_key_pem());
    auto result = gateway_verifier->validate(token);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, TokenValidationErrorKind::InvalidSignature);
}

TEST(LocalTokenVerifierTest, ValidationFailure_ForgedToken_SignedByDifferentKey) {
    Ed25519TokenSigner attacker_signer("rogue-key-id");
    auto claims = create_test_claims();
    std::string forged_token = TokenEnvelopeSerializer::serialize(claims, attacker_signer);

    // Gateway only trusts legitimate Auth Service key
    Ed25519TokenSigner auth_signer("sc-auth-v1");
    auto gateway_verifier = LocalTokenVerifier::from_public_key_pem(auth_signer.get_public_key_pem());

    auto result = gateway_verifier->validate(forged_token);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, TokenValidationErrorKind::InvalidSignature);
}

// ============================================================================
// 3. Syntax & Claims Boundary Enforcements
// ============================================================================

TEST(LocalTokenVerifierTest, ValidationFailure_EmptyOrMalformedToken_ReturnsMalformedToken) {
    Ed25519TokenSigner auth_signer("sc-auth-v1");
    auto gateway_verifier = LocalTokenVerifier::from_public_key_pem(auth_signer.get_public_key_pem());

    // Empty token
    auto res_empty = gateway_verifier->validate("");
    ASSERT_TRUE(res_empty.has_error());
    EXPECT_EQ(res_empty.error().kind, TokenValidationErrorKind::MalformedToken);

    // Missing parts
    auto res_malformed = gateway_verifier->validate("not.a.valid.token.envelope");
    ASSERT_TRUE(res_malformed.has_error());
    EXPECT_EQ(res_malformed.error().kind, TokenValidationErrorKind::MalformedToken);
}

TEST(LocalTokenVerifierTest, ValidationFailure_IssuerMismatch_ReturnsMalformedToken) {
    Ed25519TokenSigner auth_signer("sc-auth-v1");
    auto claims = create_test_claims();
    claims.issuer = "https://untrusted-auth.attacker.io"; // Wrong issuer
    std::string token = TokenEnvelopeSerializer::serialize(claims, auth_signer);

    auto gateway_verifier = LocalTokenVerifier::from_public_key_pem(auth_signer.get_public_key_pem());
    auto result = gateway_verifier->validate(token);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, TokenValidationErrorKind::MalformedToken);
}

TEST(LocalTokenVerifierTest, ValidationFailure_AudienceMismatch_ReturnsMalformedToken) {
    Ed25519TokenSigner auth_signer("sc-auth-v1");
    auto claims = create_test_claims();
    claims.audience = "https://internal-service.local"; // Wrong audience
    std::string token = TokenEnvelopeSerializer::serialize(claims, auth_signer);

    auto gateway_verifier = LocalTokenVerifier::from_public_key_pem(auth_signer.get_public_key_pem());
    auto result = gateway_verifier->validate(token);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, TokenValidationErrorKind::MalformedToken);
}

TEST(LocalTokenVerifierTest, ValidationFailure_SessionIdMismatch_ReturnsSessionRevoked) {
    Ed25519TokenSigner auth_signer("sc-auth-v1");
    auto claims = create_test_claims();
    std::string token = TokenEnvelopeSerializer::serialize(claims, auth_signer);

    auto gateway_verifier = LocalTokenVerifier::from_public_key_pem(auth_signer.get_public_key_pem());

    // Client presents a different session_id in request header than bound in token
    std::string forged_session_id = Uuid::generate_v7().to_string();
    auto result = gateway_verifier->validate(token, forged_session_id);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, TokenValidationErrorKind::SessionRevoked);
}

// ============================================================================
// 4. Factory Provisioning & Zero Private Key Exposure
// ============================================================================

TEST(LocalTokenVerifierTest, FactoryMethods_FromPemAndRawBytes_FunctionIdentically) {
    Ed25519TokenSigner auth_signer("sc-auth-v1");
    auto claims = create_test_claims();
    std::string token = TokenEnvelopeSerializer::serialize(claims, auth_signer);

    // Initialize one verifier from PEM and another from raw 32 bytes
    auto verifier_pem = LocalTokenVerifier::from_public_key_pem(auth_signer.get_public_key_pem());
    auto verifier_raw = LocalTokenVerifier::from_public_key_raw(auth_signer.get_public_key_raw());

    ASSERT_NE(verifier_pem, nullptr);
    ASSERT_NE(verifier_raw, nullptr);

    auto res_pem = verifier_pem->validate(token);
    auto res_raw = verifier_raw->validate(token);

    ASSERT_TRUE(res_pem.has_value());
    ASSERT_TRUE(res_raw.has_value());

    EXPECT_EQ(res_pem.value().user_id(), res_raw.value().user_id());
    EXPECT_EQ(res_pem.value().session_id(), res_raw.value().session_id());
}

TEST(LocalTokenVerifierTest, ZeroPrivateKeyExposure_ConstructorEnforcesNonNull) {
    EXPECT_THROW(LocalTokenVerifier(nullptr), std::invalid_argument);
    EXPECT_THROW(LocalTokenVerifier::from_public_key_pem("invalid-pem"), std::invalid_argument);
    EXPECT_THROW(LocalTokenVerifier::from_public_key_raw(std::vector<uint8_t>{1, 2, 3}), std::invalid_argument);
}

} // namespace
} // namespace securecloud::gateway::http::test
