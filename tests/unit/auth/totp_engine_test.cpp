#include "auth/crypto/base32.hpp"
#include "auth/crypto/mfa_secret_protector.hpp"
#include "auth/crypto/totp_engine.hpp"
#include "auth/domain/secret_mfa_string.hpp"

#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <vector>

namespace securecloud::auth::crypto::test {
namespace {

using domain::SecretMfaString;

// ============================================================================
// 1. RFC 4648 Base32 Codec Tests
// ============================================================================

TEST(Base32Test, Encode_Rfc4648TestVectors) {
    EXPECT_EQ(Base32::encode("", true), "");
    EXPECT_EQ(Base32::encode("f", true), "MY======");
    EXPECT_EQ(Base32::encode("fo", true), "MZXQ====");
    EXPECT_EQ(Base32::encode("foo", true), "MZXW6===");
    EXPECT_EQ(Base32::encode("foob", true), "MZXW6YQ=");
    EXPECT_EQ(Base32::encode("fooba", true), "MZXW6YTB");
    EXPECT_EQ(Base32::encode("foobar", true), "MZXW6YTBOI======");

    // Unpadded mode (standard for authenticator URIs)
    EXPECT_EQ(Base32::encode("f", false), "MY");
    EXPECT_EQ(Base32::encode("fo", false), "MZXQ");
    EXPECT_EQ(Base32::encode("foo", false), "MZXW6");
    EXPECT_EQ(Base32::encode("foob", false), "MZXW6YQ");
    EXPECT_EQ(Base32::encode("fooba", false), "MZXW6YTB");
    EXPECT_EQ(Base32::encode("foobar", false), "MZXW6YTBOI");
}

TEST(Base32Test, Decode_Rfc4648TestVectors) {
    EXPECT_EQ(Base32::decode_string(""), "");
    EXPECT_EQ(Base32::decode_string("MY======"), "f");
    EXPECT_EQ(Base32::decode_string("MZXQ===="), "fo");
    EXPECT_EQ(Base32::decode_string("MZXW6==="), "foo");
    EXPECT_EQ(Base32::decode_string("MZXW6YQ="), "foob");
    EXPECT_EQ(Base32::decode_string("MZXW6YTB"), "fooba");
    EXPECT_EQ(Base32::decode_string("MZXW6YTBOI======"), "foobar");

    // Unpadded decoding
    EXPECT_EQ(Base32::decode_string("MY"), "f");
    EXPECT_EQ(Base32::decode_string("MZXQ"), "fo");
    EXPECT_EQ(Base32::decode_string("MZXW6"), "foo");
    EXPECT_EQ(Base32::decode_string("MZXW6YQ"), "foob");
    EXPECT_EQ(Base32::decode_string("MZXW6YTB"), "fooba");
    EXPECT_EQ(Base32::decode_string("MZXW6YTBOI"), "foobar");
}

TEST(Base32Test, Decode_ToleratesLowercaseAndSeparators) {
    // Case-insensitivity
    EXPECT_EQ(Base32::decode_string("mzxw6ytboi"), "foobar");
    EXPECT_EQ(Base32::decode_string("MzxW6YtBoi"), "foobar");

    // Spaces and hyphens
    EXPECT_EQ(Base32::decode_string("MZXW 6YTB OI"), "foobar");
    EXPECT_EQ(Base32::decode_string("MZXW-6YTB-OI"), "foobar");
    EXPECT_EQ(Base32::decode_string("  MZXW6YTBOI  "), "foobar");
}

TEST(Base32Test, Decode_RejectsInvalidInput) {
    // '8' and '9' are not in Base32 alphabet
    EXPECT_FALSE(Base32::decode("MZXW8").has_value());
    EXPECT_FALSE(Base32::decode("MZXW9").has_value());
    EXPECT_FALSE(Base32::decode("10").has_value());
    EXPECT_FALSE(Base32::decode("!@#$%").has_value());

    // Characters after padding are invalid
    EXPECT_FALSE(Base32::decode("MY=A====").has_value());
}

// ============================================================================
// 2. RFC 6238 TOTP Official Test Vectors
// ============================================================================

TEST(TotpEngineTest, Rfc6238TestVectors_Sha1_8Digits) {
    // RFC 6238 Appendix B test secret: ASCII string "12345678901234567890" (20 bytes)
    const std::string rfc_secret = "12345678901234567890";
    std::span<const uint8_t> secret_span(reinterpret_cast<const uint8_t*>(rfc_secret.data()), rfc_secret.size());

    TotpConfig config;
    config.digits = 8;
    config.time_step_seconds = 30;
    config.algorithm = TotpHashAlgorithm::Sha1;
    TotpEngine engine(config);

    // RFC 6238 table:
    // Time=59          -> 94287082
    // Time=1111111109  -> 07081804
    // Time=1111111111  -> 14050471
    // Time=1234567890  -> 89005924
    // Time=2000000000  -> 69279037
    // Time=20000000000 -> 65353130
    EXPECT_EQ(engine.compute_code(secret_span, 59ULL), "94287082");
    EXPECT_EQ(engine.compute_code(secret_span, 1111111109ULL), "07081804");
    EXPECT_EQ(engine.compute_code(secret_span, 1111111111ULL), "14050471");
    EXPECT_EQ(engine.compute_code(secret_span, 1234567890ULL), "89005924");
    EXPECT_EQ(engine.compute_code(secret_span, 2000000000ULL), "69279037");
    EXPECT_EQ(engine.compute_code(secret_span, 20000000000ULL), "65353130");
}

TEST(TotpEngineTest, Rfc6238TestVectors_Sha1_6Digits) {
    // Standard 6-digit mode (modulo 10^6 extracts lowest 6 digits of 8-digit vector)
    const std::string rfc_secret = "12345678901234567890";
    std::span<const uint8_t> secret_span(reinterpret_cast<const uint8_t*>(rfc_secret.data()), rfc_secret.size());

    TotpConfig config;
    config.digits = 6;
    config.time_step_seconds = 30;
    config.algorithm = TotpHashAlgorithm::Sha1;
    TotpEngine engine(config);

    EXPECT_EQ(engine.compute_code(secret_span, 59ULL), "287082");
    EXPECT_EQ(engine.compute_code(secret_span, 1111111109ULL), "081804");
    EXPECT_EQ(engine.compute_code(secret_span, 1111111111ULL), "050471");
    EXPECT_EQ(engine.compute_code(secret_span, 1234567890ULL), "005924");
    EXPECT_EQ(engine.compute_code(secret_span, 2000000000ULL), "279037");
    EXPECT_EQ(engine.compute_code(secret_span, 20000000000ULL), "353130");
}

// ============================================================================
// 3. Secret Generation & Code Verification Window Drift (+/- 1 Step)
// ============================================================================

TEST(TotpEngineTest, GenerateSecretBytes_ProducesSecureRandomData) {
    auto secret1 = TotpEngine::generate_secret_bytes(20);
    auto secret2 = TotpEngine::generate_secret_bytes(20);

    EXPECT_EQ(secret1.size(), 20u);
    EXPECT_EQ(secret2.size(), 20u);
    EXPECT_NE(secret1, secret2);

    // Assert not all zeros
    bool has_nonzero = false;
    for (uint8_t b : secret1) {
        if (b != 0) has_nonzero = true;
    }
    EXPECT_TRUE(has_nonzero);
}

TEST(TotpEngineTest, Verification_AcceptsCurrentStepAndDriftWindow) {
    TotpEngine engine; // Default 6 digits, 30s step, drift +/- 1
    auto secret = TotpEngine::generate_secret_bytes(20);

    const uint64_t base_time = 1700000015ULL; // Step T = 56666667
    const uint64_t expected_step = base_time / 30;
    const std::string valid_code = engine.compute_code(secret, base_time);

    // 1. Current step (drift 0)
    auto res_current = engine.verify_code(secret, valid_code, base_time);
    EXPECT_TRUE(res_current.is_valid);
    EXPECT_EQ(res_current.matched_time_step, expected_step);

    // 2. Next step (drift +1, e.g. 30 seconds into future)
    auto res_future = engine.verify_code(secret, valid_code, base_time + 30);
    EXPECT_TRUE(res_future.is_valid);
    EXPECT_EQ(res_future.matched_time_step, expected_step);

    // 3. Previous step (drift -1, e.g. 30 seconds into past)
    auto res_past = engine.verify_code(secret, valid_code, base_time - 30);
    EXPECT_TRUE(res_past.is_valid);
    EXPECT_EQ(res_past.matched_time_step, expected_step);

    // 4. Two steps in future (drift +2, out of window) -> Rejection
    auto res_too_late = engine.verify_code(secret, valid_code, base_time + 65);
    EXPECT_FALSE(res_too_late.is_valid);

    // 5. Two steps in past (drift -2, out of window) -> Rejection
    auto res_too_early = engine.verify_code(secret, valid_code, base_time - 65);
    EXPECT_FALSE(res_too_early.is_valid);
}

TEST(TotpEngineTest, Verification_RejectsInvalidOrMalformedCodes) {
    TotpEngine engine;
    auto secret = TotpEngine::generate_secret_bytes(20);
    const uint64_t now = 1700000000ULL;

    EXPECT_FALSE(engine.verify_code(secret, "000000", now).is_valid);
    EXPECT_FALSE(engine.verify_code(secret, "12345", now).is_valid);   // 5 digits
    EXPECT_FALSE(engine.verify_code(secret, "1234567", now).is_valid); // 7 digits
    EXPECT_FALSE(engine.verify_code(secret, "abcdef", now).is_valid);  // non-numeric
    EXPECT_FALSE(engine.verify_code(secret, "", now).is_valid);

    // User spaces tolerated
    std::string valid_code = engine.compute_code(secret, now);
    std::string spaced_code = valid_code.substr(0, 3) + " " + valid_code.substr(3);
    EXPECT_TRUE(engine.verify_code(secret, spaced_code, now).is_valid);
}

// ============================================================================
// 4. OTPAuth URI Generation
// ============================================================================

TEST(TotpEngineTest, GenerateOtpauthUri_FormatsStandardUri) {
    TotpEngine engine;
    std::string uri = engine.generate_otpauth_uri("SecureCloud", "alice@example.com", "JBSWY3DPEHPK3PXP");

    EXPECT_EQ(uri,
              "otpauth://totp/SecureCloud:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=SecureCloud&algorithm=SHA1&digits=6&period=30");
}

// ============================================================================
// 5. AES-256-GCM MFA Secret Protector Tests
// ============================================================================

TEST(MfaSecretProtectorTest, RoundTrip_EncryptDecrypt_MatchesOriginal) {
    // 32-byte hexadecimal Key Encryption Key
    const std::string kek_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    MfaSecretProtector protector(kek_hex);

    std::vector<uint8_t> secret_plaintext = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                                             0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01,
                                             0x02, 0x03, 0x04, 0x05};

    auto encrypted = protector.encrypt(secret_plaintext, "user-uuid-1234");

    // Min size = 12 IV + 20 plaintext + 16 Tag = 48 bytes
    EXPECT_EQ(encrypted.size(), 48u);

    auto decrypted = protector.decrypt(encrypted, "user-uuid-1234");
    EXPECT_EQ(decrypted, secret_plaintext);
}

TEST(MfaSecretProtectorTest, Tampering_CiphertextBitFlip_ThrowsRuntimeError) {
    const std::string kek_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    MfaSecretProtector protector(kek_hex);

    std::vector<uint8_t> secret = {1, 2, 3, 4, 5, 6, 7, 8};
    auto encrypted = protector.encrypt(secret);

    // Tamper with ciphertext byte (index 15)
    encrypted[15] ^= 0x01;

    EXPECT_THROW((void)protector.decrypt(encrypted), std::runtime_error);
}

TEST(MfaSecretProtectorTest, Tampering_IvOrTagBitFlip_ThrowsRuntimeError) {
    const std::string kek_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    MfaSecretProtector protector(kek_hex);

    std::vector<uint8_t> secret = {1, 2, 3, 4, 5, 6, 7, 8};

    // 1. Tamper with IV byte (index 0)
    auto enc_iv_tamper = protector.encrypt(secret);
    enc_iv_tamper[0] ^= 0xFF;
    EXPECT_THROW((void)protector.decrypt(enc_iv_tamper), std::runtime_error);

    // 2. Tamper with GCM tag byte (last byte)
    auto enc_tag_tamper = protector.encrypt(secret);
    enc_tag_tamper.back() ^= 0xFF;
    EXPECT_THROW((void)protector.decrypt(enc_tag_tamper), std::runtime_error);
}

TEST(MfaSecretProtectorTest, AadMismatch_ThrowsRuntimeError) {
    const std::string kek_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    MfaSecretProtector protector(kek_hex);

    std::vector<uint8_t> secret = {1, 2, 3, 4};
    auto encrypted = protector.encrypt(secret, "alice-account-id");

    // Decrypting with wrong AAD (Bob's account ID) fails tag check
    EXPECT_THROW((void)protector.decrypt(encrypted, "bob-account-id"), std::runtime_error);
    EXPECT_THROW((void)protector.decrypt(encrypted, ""), std::runtime_error);
}

TEST(MfaSecretProtectorTest, TruncatedPayload_ThrowsInvalidArgument) {
    const std::string kek_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    MfaSecretProtector protector(kek_hex);

    std::vector<uint8_t> too_short(27, 0x00); // 27 bytes < min 28 bytes
    EXPECT_THROW((void)protector.decrypt(too_short), std::invalid_argument);
}

TEST(MfaSecretProtectorTest, InvalidKeyFormat_ThrowsInvalidArgument) {
    EXPECT_THROW(MfaSecretProtector("too-short-key"), std::invalid_argument);
    EXPECT_THROW(MfaSecretProtector("not-valid-hex-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1z"),
                 std::invalid_argument);
}

// ============================================================================
// 6. SecretMfaString RAII Memory Scrubbing & Stream Redaction Tests
// ============================================================================

TEST(SecretMfaStringTest, StreamOperator_EmitsRedactedPlaceholder) {
    SecretMfaString secret("JBSWY3DPEHPK3PXP");

    std::ostringstream oss;
    oss << secret;

    EXPECT_EQ(oss.str(), "[REDACTED_MFA_SECRET]");
    EXPECT_EQ(secret.raw_secret(), "JBSWY3DPEHPK3PXP");
    EXPECT_EQ(secret.raw_view(), "JBSWY3DPEHPK3PXP");
    EXPECT_FALSE(secret.empty());
    EXPECT_EQ(secret.size(), 16u);
}

TEST(SecretMfaStringTest, EqualityAndCopyMoveSemantics) {
    SecretMfaString s1("MY_MFA_SECRET_123");
    SecretMfaString s2("MY_MFA_SECRET_123");
    SecretMfaString s3("DIFFERENT_SECRET");

    EXPECT_EQ(s1, s2);
    EXPECT_NE(s1, s3);

    // Copy
    SecretMfaString s_copy = s1;
    EXPECT_EQ(s_copy.raw_secret(), "MY_MFA_SECRET_123");

    // Move
    SecretMfaString s_move = std::move(s_copy);
    EXPECT_EQ(s_move.raw_secret(), "MY_MFA_SECRET_123");
}

} // namespace
} // namespace securecloud::auth::crypto::test
