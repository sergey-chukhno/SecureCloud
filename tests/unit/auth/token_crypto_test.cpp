#include "auth/crypto/token_crypto.hpp"

#include <gtest/gtest.h>
#include <string>
#include <unordered_set>
#include <vector>

namespace securecloud::auth::crypto::test {
namespace {

// ============================================================================
// 1. Base64Url Codec Tests
// ============================================================================

TEST(TokenCryptoTest, Base64Url_RoundtripFidelity) {
    const std::vector<std::string> test_strings = {
        "",
        "f",
        "fo",
        "foo",
        "foob",
        "fooba",
        "foobar",
        "SecureCloud-ZeroTrust-Ed25519-Token-Signature-Payload-Test-String",
        "{\n  \"sub\": \"01925b6a-9f5b-7c48-89c0-54415893a201\"\n}",
    };

    for (const auto& original : test_strings) {
        std::string encoded = Base64Url::encode(original);
        // Assert no standard base64 characters that are prohibited in Base64URL
        EXPECT_EQ(encoded.find('+'), std::string::npos);
        EXPECT_EQ(encoded.find('/'), std::string::npos);
        EXPECT_EQ(encoded.find('='), std::string::npos);

        auto decoded = Base64Url::decode(encoded);
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(*decoded, original);
    }
}

TEST(TokenCryptoTest, Base64Url_BinaryDataRoundtrip) {
    std::vector<uint8_t> binary_data(256);
    for (size_t i = 0; i < binary_data.size(); ++i) {
        binary_data[i] = static_cast<uint8_t>(i);
    }

    std::string encoded = Base64Url::encode(binary_data);
    auto decoded_bytes = Base64Url::decode_bytes(encoded);
    ASSERT_TRUE(decoded_bytes.has_value());
    EXPECT_EQ(*decoded_bytes, binary_data);
}

TEST(TokenCryptoTest, Base64Url_InvalidCharacterRejection) {
    EXPECT_FALSE(Base64Url::decode("invalid+char").has_value());
    EXPECT_FALSE(Base64Url::decode("invalid/char").has_value());
    EXPECT_FALSE(Base64Url::decode("invalid char with spaces").has_value());
    EXPECT_FALSE(Base64Url::decode("!@#$%^&*()").has_value());
}

TEST(TokenCryptoTest, Base64Url_ConstantTimeComparison) {
    std::string a = "securecloud-token-secret-hash-1";
    std::string b = "securecloud-token-secret-hash-1";
    std::string c = "securecloud-token-secret-hash-2";
    std::string d = "short";

    EXPECT_TRUE(Base64Url::constant_time_equals(a, b));
    EXPECT_FALSE(Base64Url::constant_time_equals(a, c));
    EXPECT_FALSE(Base64Url::constant_time_equals(a, d));
}

// ============================================================================
// 2. Ed25519 Signer & Verifier Tests
// ============================================================================

TEST(TokenCryptoTest, Ed25519_KeypairGenerationAndPublicKeyExport) {
    Ed25519TokenSigner signer("auth-key-2026-v1");
    EXPECT_EQ(signer.get_key_id(), "auth-key-2026-v1");

    std::string pub_pem = signer.get_public_key_pem();
    EXPECT_NE(pub_pem.find("BEGIN PUBLIC KEY"), std::string::npos);
    EXPECT_NE(pub_pem.find("END PUBLIC KEY"), std::string::npos);

    std::vector<uint8_t> raw_pub = signer.get_public_key_raw();
    // Ed25519 raw public keys are strictly 32 bytes
    EXPECT_EQ(raw_pub.size(), 32u);
}

TEST(TokenCryptoTest, Ed25519_SigningAndVerificationSuccessAcrossAllRepresentations) {
    Ed25519TokenSigner signer("sc-test-key");
    const std::string payload = R"({"iss":"auth.securecloud.io","sub":"user-123","exp":1800000000})";

    std::string signature_b64 = signer.sign(payload);
    ASSERT_FALSE(signature_b64.empty());

    // 1. Verifier from Signer instance
    auto verifier_from_signer = Ed25519TokenVerifier::from_signer(signer);
    ASSERT_NE(verifier_from_signer, nullptr);
    EXPECT_TRUE(verifier_from_signer->verify(payload, signature_b64));

    // 2. Verifier from PEM public key string
    auto verifier_from_pem = Ed25519TokenVerifier::from_public_key_pem(signer.get_public_key_pem(), "sc-test-key");
    ASSERT_NE(verifier_from_pem, nullptr);
    EXPECT_TRUE(verifier_from_pem->verify(payload, signature_b64));

    // 3. Verifier from raw 32-byte public key
    auto verifier_from_raw = Ed25519TokenVerifier::from_public_key_raw(signer.get_public_key_raw(), "sc-test-key");
    ASSERT_NE(verifier_from_raw, nullptr);
    EXPECT_TRUE(verifier_from_raw->verify(payload, signature_b64));
}

TEST(TokenCryptoTest, Ed25519_SignatureTamperingRejection) {
    Ed25519TokenSigner signer("auth-key");
    auto verifier = Ed25519TokenVerifier::from_signer(signer);

    const std::string payload = "authenticated.claims.payload";
    std::string valid_sig = signer.sign(payload);
    ASSERT_TRUE(verifier->verify(payload, valid_sig));

    // Flip 1 character in the signature
    std::string tampered_sig = valid_sig;
    tampered_sig[10] = (tampered_sig[10] == 'A') ? 'B' : 'A';
    EXPECT_FALSE(verifier->verify(payload, tampered_sig));

    // Truncated signature fails
    EXPECT_FALSE(verifier->verify(payload, valid_sig.substr(0, valid_sig.size() - 5)));

    // Empty signature fails
    EXPECT_FALSE(verifier->verify(payload, ""));
}

TEST(TokenCryptoTest, Ed25519_PayloadTamperingRejection) {
    Ed25519TokenSigner signer("auth-key");
    auto verifier = Ed25519TokenVerifier::from_signer(signer);

    const std::string original_payload = R"({"sub":"user_123","role":"member"})";
    std::string sig = signer.sign(original_payload);
    ASSERT_TRUE(verifier->verify(original_payload, sig));

    // Attacker modifies claims to elevate privilege
    const std::string tampered_payload = R"({"sub":"user_123","role":"admin"})";
    EXPECT_FALSE(verifier->verify(tampered_payload, sig));
}

TEST(TokenCryptoTest, Ed25519_MismatchedKeyRejection) {
    Ed25519TokenSigner signer1("key-1");
    Ed25519TokenSigner signer2("key-2");

    auto verifier2 = Ed25519TokenVerifier::from_signer(signer2);

    const std::string payload = "security-sensitive-transaction";
    std::string sig1 = signer1.sign(payload);

    // Verifier 2 must reject signature produced by Signer 1
    EXPECT_FALSE(verifier2->verify(payload, sig1));
}

TEST(TokenCryptoTest, Ed25519_PrivateKeyExportAndReload) {
    Ed25519TokenSigner original_signer("persistent-key-id");
    std::string exported_priv_pem = original_signer.export_private_key_pem();
    ASSERT_FALSE(exported_priv_pem.empty());
    EXPECT_NE(exported_priv_pem.find("BEGIN PRIVATE KEY"), std::string::npos);

    // Reconstruct signer from exported private key PEM
    auto restored_signer = Ed25519TokenSigner::from_private_key_pem(exported_priv_pem, "persistent-key-id");
    ASSERT_NE(restored_signer, nullptr);

    // Compare exported public keys
    EXPECT_EQ(original_signer.get_public_key_raw(), restored_signer->get_public_key_raw());

    // Verify signatures are interchangeable
    const std::string payload = "session-restart-durability-test";
    std::string sig = restored_signer->sign(payload);

    auto verifier = Ed25519TokenVerifier::from_signer(original_signer);
    EXPECT_TRUE(verifier->verify(payload, sig));
}

// ============================================================================
// 3. SecureRandomTokenGenerator & TokenHasher Tests
// ============================================================================

TEST(TokenCryptoTest, SecureRandomTokenGenerator_EntropyAndUniqueness) {
    constexpr size_t kSampleCount = 1000;
    std::unordered_set<std::string> unique_tokens;
    unique_tokens.reserve(kSampleCount);

    for (size_t i = 0; i < kSampleCount; ++i) {
        std::string token = SecureRandomTokenGenerator::generate_refresh_token(32);
        EXPECT_EQ(token.substr(0, 6), "sc_rt_");
        // 32 bytes base64url encoded is 43 chars, + 6 chars prefix = 49 chars
        EXPECT_EQ(token.size(), 49u);
        unique_tokens.insert(token);
    }

    // Zero collisions across 1,000 generated tokens
    EXPECT_EQ(unique_tokens.size(), kSampleCount);
}

TEST(TokenCryptoTest, TokenHasher_DeterminismAndVerification) {
    // Standard test vector: SHA-256 of empty string
    EXPECT_EQ(TokenHasher::compute_sha256_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // Standard test vector: SHA-256 of "SecureCloud"
    std::string secret = "sc_rt_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
    std::string expected_hash = TokenHasher::compute_sha256_hex(secret);
    ASSERT_EQ(expected_hash.size(), 64u);

    // Verify deterministic equality
    EXPECT_EQ(TokenHasher::compute_sha256_hex(secret), expected_hash);

    // Constant-time verification
    EXPECT_TRUE(TokenHasher::verify_hash(secret, expected_hash));
    EXPECT_FALSE(TokenHasher::verify_hash("wrong_secret", expected_hash));

    // Tampered hash rejection
    std::string tampered_hash = expected_hash;
    tampered_hash[0] = (tampered_hash[0] == 'a') ? 'b' : 'a';
    EXPECT_FALSE(TokenHasher::verify_hash(secret, tampered_hash));
}

} // namespace
} // namespace securecloud::auth::crypto::test
