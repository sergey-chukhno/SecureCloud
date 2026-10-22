#include "auth/crypto/mfa_secret_protector.hpp"
#include "auth/crypto/recovery_code_generator.hpp"
#include "auth/crypto/totp_engine.hpp"
#include "auth/domain/mfa_result.hpp"
#include "auth/service/mfa_authenticator_interface.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using crypto::MfaSecretProtector;
using crypto::RecoveryCodeBatch;
using crypto::RecoveryCodeGenerator;
using crypto::TotpConfig;
using crypto::TotpEngine;
using domain::MfaFactorType;

// ============================================================================
// 1. TotpAuthenticator Unit Tests
// ============================================================================

class TotpAuthenticatorTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const std::string kek_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        secret_protector_ = std::make_shared<MfaSecretProtector>(kek_hex);
        totp_engine_ = std::make_shared<TotpEngine>();
        authenticator_ = std::make_unique<TotpAuthenticator>(totp_engine_, secret_protector_);

        raw_secret_ = TotpEngine::generate_secret_bytes(20);
        aad_ = "user-uuid-1234";
        encrypted_secret_ = secret_protector_->encrypt(raw_secret_, aad_);
    }

    std::shared_ptr<MfaSecretProtector> secret_protector_;
    std::shared_ptr<TotpEngine> totp_engine_;
    std::unique_ptr<TotpAuthenticator> authenticator_;
    std::vector<uint8_t> raw_secret_;
    std::string aad_;
    std::vector<uint8_t> encrypted_secret_;
};

TEST_F(TotpAuthenticatorTest, FactorType_ReturnsTotp) {
    EXPECT_EQ(authenticator_->factor_type(), MfaFactorType::Totp);
}

TEST_F(TotpAuthenticatorTest, Constructor_NullDependenciesThrow) {
    EXPECT_THROW(TotpAuthenticator(nullptr, secret_protector_), std::invalid_argument);
    EXPECT_THROW(TotpAuthenticator(totp_engine_, nullptr), std::invalid_argument);
}

TEST_F(TotpAuthenticatorTest, VerifyFactor_Success_ValidCode) {
    const uint64_t now = 1700000015ULL;
    const std::string valid_code = totp_engine_->compute_code(raw_secret_, now);

    auto result = authenticator_->verify_factor(encrypted_secret_, valid_code, now, aad_);

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.matched_time_step, now / 30);
    EXPECT_TRUE(result.error_message.empty());
}

TEST_F(TotpAuthenticatorTest, VerifyFactor_Failure_InvalidCode) {
    const uint64_t now = 1700000015ULL;

    auto result = authenticator_->verify_factor(encrypted_secret_, "000000", now, aad_);

    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error_message.empty());
}

TEST_F(TotpAuthenticatorTest, VerifyFactor_Failure_TamperedSecret) {
    const uint64_t now = 1700000015ULL;
    const std::string valid_code = totp_engine_->compute_code(raw_secret_, now);

    auto tampered = encrypted_secret_;
    tampered[15] ^= 0x01; // Tamper with ciphertext

    // Must not crash or re-throw; must report failure safely
    auto result = authenticator_->verify_factor(tampered, valid_code, now, aad_);

    EXPECT_FALSE(result.success);
    EXPECT_NE(result.error_message.find("decryption failed"), std::string::npos);
}

TEST_F(TotpAuthenticatorTest, VerifyFactor_Failure_AadMismatch) {
    const uint64_t now = 1700000015ULL;
    const std::string valid_code = totp_engine_->compute_code(raw_secret_, now);

    // Presenting with different user ID AAD fails authentication
    auto result = authenticator_->verify_factor(encrypted_secret_, valid_code, now, "attacker-user-id");

    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error_message.empty());
}

TEST_F(TotpAuthenticatorTest, VerifyFactor_Failure_EmptyInputs) {
    const uint64_t now = 1700000015ULL;
    const std::vector<uint8_t> empty_secret;

    EXPECT_FALSE(authenticator_->verify_factor(empty_secret, "123456", now, aad_).success);
    EXPECT_FALSE(authenticator_->verify_factor(encrypted_secret_, "", now, aad_).success);
}

// ============================================================================
// 2. Extensibility Verification (Future WebAuthn / FIDO2 Authenticator)
// ============================================================================

class MockWebAuthnAuthenticator : public IMfaAuthenticator {
  public:
    [[nodiscard]] MfaFactorType factor_type() const noexcept override { return MfaFactorType::WebAuthn; }

    [[nodiscard]] MfaFactorVerificationResult verify_factor(std::span<const uint8_t> /*encrypted_secret*/,
                                                            std::string_view credential, uint64_t /*timestamp_seconds*/,
                                                            std::string_view /*aad*/) const override {
        if (credential == "valid_webauthn_assertion_json") {
            return MfaFactorVerificationResult::ok(0);
        }
        return MfaFactorVerificationResult::fail("Invalid WebAuthn assertion signature");
    }
};

TEST(MfaAuthenticatorExtensibilityTest, InterfacePolymorphism_WebAuthnPlugsInSeamlessly) {
    std::unique_ptr<IMfaAuthenticator> authenticator = std::make_unique<MockWebAuthnAuthenticator>();

    EXPECT_EQ(authenticator->factor_type(), MfaFactorType::WebAuthn);

    auto ok_res = authenticator->verify_factor({}, "valid_webauthn_assertion_json", 0);
    EXPECT_TRUE(ok_res.success);

    auto bad_res = authenticator->verify_factor({}, "invalid_assertion", 0);
    EXPECT_FALSE(bad_res.success);
}

// ============================================================================
// 3. Recovery Code Generator Tests
// ============================================================================

TEST(RecoveryCodeGeneratorTest, GenerateBatch_Produces8DistinctFormattedCodes) {
    auto batch = RecoveryCodeGenerator::generate_batch(8);

    EXPECT_EQ(batch.plaintext_codes.size(), 8u);
    EXPECT_EQ(batch.hashed_codes.size(), 8u);

    for (size_t i = 0; i < batch.plaintext_codes.size(); ++i) {
        const auto& code = batch.plaintext_codes[i];
        EXPECT_EQ(code.size(), 9u); // 4 + '-' + 4
        EXPECT_EQ(code[4], '-');

        // Check SHA-256 hash matches
        std::string expected_hash = RecoveryCodeGenerator::hash_code(code);
        EXPECT_EQ(batch.hashed_codes[i], expected_hash);
        EXPECT_EQ(expected_hash.size(), 64u); // 256 bits = 64 hex characters
    }

    // Verify all 8 codes are unique
    for (size_t i = 0; i < batch.plaintext_codes.size(); ++i) {
        for (size_t j = i + 1; j < batch.plaintext_codes.size(); ++j) {
            EXPECT_NE(batch.plaintext_codes[i], batch.plaintext_codes[j]);
        }
    }
}

TEST(RecoveryCodeGeneratorTest, NormalizeCode_ToleratesHyphensSpacesAndLowercase) {
    EXPECT_EQ(RecoveryCodeGenerator::normalize_code("abcd-efgh"), "ABCDEFGH");
    EXPECT_EQ(RecoveryCodeGenerator::normalize_code("  abcd efgh  "), "ABCDEFGH");
    EXPECT_EQ(RecoveryCodeGenerator::normalize_code("ABCD-EFGH"), "ABCDEFGH");
}

TEST(RecoveryCodeGeneratorTest, VerifyAndConsume_MatchesAndBurnsCode) {
    auto batch = RecoveryCodeGenerator::generate_batch(8);
    auto active_pool = batch.hashed_codes;

    // 1. User presents 3rd code with lowercase and spaces
    std::string user_input = batch.plaintext_codes[2];
    std::string sloppy_input = "  " + user_input + "  ";

    auto match_idx = RecoveryCodeGenerator::verify_and_consume(sloppy_input, active_pool);
    ASSERT_TRUE(match_idx.has_value());
    EXPECT_EQ(*match_idx, 2u);

    // 2. Burn (erase) the matched code from the active pool
    active_pool.erase(active_pool.begin() + static_cast<std::ptrdiff_t>(*match_idx));
    EXPECT_EQ(active_pool.size(), 7u);

    // 3. Attempting to reuse the exact same code now fails safely
    auto reuse_attempt = RecoveryCodeGenerator::verify_and_consume(user_input, active_pool);
    EXPECT_FALSE(reuse_attempt.has_value());
}

TEST(RecoveryCodeGeneratorTest, VerifyAndConsume_InvalidCodeReturnsNullopt) {
    auto batch = RecoveryCodeGenerator::generate_batch(8);

    EXPECT_FALSE(RecoveryCodeGenerator::verify_and_consume("INVALID-CODE", batch.hashed_codes).has_value());
    EXPECT_FALSE(RecoveryCodeGenerator::verify_and_consume("", batch.hashed_codes).has_value());

    std::vector<std::string> empty_pool;
    EXPECT_FALSE(RecoveryCodeGenerator::verify_and_consume(batch.plaintext_codes[0], empty_pool).has_value());
}

} // namespace
} // namespace securecloud::auth::service::test
