#include "application/client_error.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::client::tests {

using namespace securecloud::client::application;
using namespace securecloud::client::domain;

class SafetyNumberEngineTest : public ::testing::Test {
  protected:
    void SetUp() override {
        secure_storage_ = std::make_unique<infrastructure::adapters::MemorySecureStorage>();
        crypto_provider_ = std::make_unique<infrastructure::adapters::OpenSslCryptoProvider>();
        engine_ = std::make_unique<managers::SafetyNumberEngine>(*crypto_provider_, *secure_storage_);

        alice_user_ = UserId("usr-alice");
        bob_user_ = UserId("usr-bob");

        auto alice_id = crypto_provider_->generate_identity_keypair().value();
        alice_ik_ = std::move(alice_id.public_key);

        auto bob_id = crypto_provider_->generate_identity_keypair().value();
        bob_ik_ = std::move(bob_id.public_key);
    }

    std::unique_ptr<infrastructure::adapters::MemorySecureStorage> secure_storage_;
    std::unique_ptr<infrastructure::adapters::OpenSslCryptoProvider> crypto_provider_;
    std::unique_ptr<managers::SafetyNumberEngine> engine_;

    UserId alice_user_;
    UserId bob_user_;
    std::vector<uint8_t> alice_ik_;
    std::vector<uint8_t> bob_ik_;
};

TEST_F(SafetyNumberEngineTest, ComputeSafetyNumberSymmetryAndFormatting) {
    // Alice derives safety number with Bob
    auto res_alice = engine_->compute_safety_number(alice_user_, alice_ik_, bob_user_, bob_ik_);
    ASSERT_TRUE(res_alice.is_ok());
    const auto& sn_alice = res_alice.value();

    // Bob derives safety number with Alice
    auto res_bob = engine_->compute_safety_number(bob_user_, bob_ik_, alice_user_, alice_ik_);
    ASSERT_TRUE(res_bob.is_ok());
    const auto& sn_bob = res_bob.value();

    // Mutual symmetry: Alice and Bob must see the EXACT same 60-digit string
    EXPECT_EQ(sn_alice, sn_bob);

    // Verify 12 blocks of 5 decimal digits (length: 12*5 + 11 spaces = 71 characters)
    EXPECT_EQ(sn_alice.size(), 71U);

    // Verify format: digits and spaces only
    int space_count = 0;
    for (std::size_t i = 0; i < sn_alice.size(); ++i) {
        if ((i + 1) % 6 == 0) {
            EXPECT_EQ(sn_alice[i], ' ');
            space_count++;
        } else {
            EXPECT_TRUE(std::isdigit(static_cast<unsigned char>(sn_alice[i])));
        }
    }
    EXPECT_EQ(space_count, 11);
}

TEST_F(SafetyNumberEngineTest, ComputeSafetyNumberRejectsEmptyParams) {
    auto res1 = engine_->compute_safety_number(UserId{}, alice_ik_, bob_user_, bob_ik_);
    EXPECT_TRUE(res1.is_error());
    EXPECT_EQ(res1.error().code(), ClientErrorCode::ValidationFailed);

    auto res2 = engine_->compute_safety_number(alice_user_, {}, bob_user_, bob_ik_);
    EXPECT_TRUE(res2.is_error());
    EXPECT_EQ(res2.error().code(), ClientErrorCode::ValidationFailed);
}

TEST_F(SafetyNumberEngineTest, FormatSafetyNumberRawAndClean) {
    std::string raw = "111112222233333444445555566666777778888899999000001234567890";
    ASSERT_EQ(raw.size(), 60U);

    std::string formatted = managers::SafetyNumberEngine::format_safety_number(raw);
    EXPECT_EQ(formatted, "11111 22222 33333 44444 55555 66666 77777 88888 99999 00000 12345 67890");

    // Idempotent formatting with existing spaces
    std::string formatted_again = managers::SafetyNumberEngine::format_safety_number(formatted);
    EXPECT_EQ(formatted_again, formatted);
}

TEST_F(SafetyNumberEngineTest, EvaluateStatusInitiallyUnverified) {
    auto status_res = engine_->evaluate_key_verification_status(bob_user_, bob_ik_);
    ASSERT_TRUE(status_res.is_ok());
    EXPECT_EQ(status_res.value(), KeyVerificationStatus::Unverified);
}

TEST_F(SafetyNumberEngineTest, SetVerificationStateAndEvaluateVerified) {
    // Alice verifies Bob's key out-of-band
    auto set_res = engine_->set_verification_state(bob_user_, bob_ik_, true);
    ASSERT_TRUE(set_res.is_ok());

    // Status is now Verified
    auto status_res = engine_->evaluate_key_verification_status(bob_user_, bob_ik_);
    ASSERT_TRUE(status_res.is_ok());
    EXPECT_EQ(status_res.value(), KeyVerificationStatus::Verified);

    // Verify stored fingerprint
    auto fp_res = engine_->get_verified_fingerprint(bob_user_);
    ASSERT_TRUE(fp_res.is_ok());
    ASSERT_TRUE(fp_res.value().has_value());
    EXPECT_FALSE(fp_res.value()->empty());
}

TEST_F(SafetyNumberEngineTest, AutomatedKeyChangeDetectionTransitionsToKeyChanged) {
    // 1. Initial state: Bob's identity key is verified by Alice
    auto set_res = engine_->set_verification_state(bob_user_, bob_ik_, true);
    ASSERT_TRUE(set_res.is_ok());

    auto status1 = engine_->evaluate_key_verification_status(bob_user_, bob_ik_);
    ASSERT_TRUE(status1.is_ok());
    EXPECT_EQ(status1.value(), KeyVerificationStatus::Verified);

    // 2. Bob reinstalls or an attacker swaps Bob's public key
    auto rogue_id = crypto_provider_->generate_identity_keypair().value();
    std::vector<uint8_t> rogue_ik = std::move(rogue_id.public_key);

    // 3. Engine automatically detects key mismatch and flags KeyChanged!
    auto status2 = engine_->evaluate_key_verification_status(bob_user_, rogue_ik);
    ASSERT_TRUE(status2.is_ok());
    EXPECT_EQ(status2.value(), KeyVerificationStatus::KeyChanged);
}

TEST_F(SafetyNumberEngineTest, ResetVerificationStateReturnsUnverified) {
    // Verify Bob
    ASSERT_TRUE(engine_->set_verification_state(bob_user_, bob_ik_, true).is_ok());
    EXPECT_EQ(engine_->evaluate_key_verification_status(bob_user_, bob_ik_).value(), KeyVerificationStatus::Verified);

    // Reset verification (unmark)
    ASSERT_TRUE(engine_->set_verification_state(bob_user_, bob_ik_, false).is_ok());
    EXPECT_EQ(engine_->evaluate_key_verification_status(bob_user_, bob_ik_).value(), KeyVerificationStatus::Unverified);

    auto fp_res = engine_->get_verified_fingerprint(bob_user_);
    ASSERT_TRUE(fp_res.is_ok());
    EXPECT_FALSE(fp_res.value().has_value());
}

TEST_F(SafetyNumberEngineTest, VerificationUriGenerationAndRoundTrip) {
    auto sn_res = engine_->compute_safety_number(alice_user_, alice_ik_, bob_user_, bob_ik_);
    ASSERT_TRUE(sn_res.is_ok());

    std::string uri = managers::SafetyNumberEngine::generate_verification_uri(alice_user_, bob_user_, sn_res.value());
    EXPECT_FALSE(uri.empty());
    EXPECT_NE(uri.find("securecloud://verify?"), std::string::npos);
    EXPECT_NE(uri.find("v=1"), std::string::npos);
    EXPECT_NE(uri.find("u1=usr-alice"), std::string::npos);
    EXPECT_NE(uri.find("u2=usr-bob"), std::string::npos);

    // Parse URI back
    auto parse_res = managers::SafetyNumberEngine::parse_verification_uri(uri);
    ASSERT_TRUE(parse_res.is_ok());
    const auto& parsed = parse_res.value();
    EXPECT_EQ(parsed.user1, alice_user_);
    EXPECT_EQ(parsed.user2, bob_user_);
    EXPECT_EQ(parsed.safety_number, sn_res.value());
}

TEST_F(SafetyNumberEngineTest, ParseVerificationUriRejectsMalformedPayloads) {
    // Missing scheme
    auto res1 = managers::SafetyNumberEngine::parse_verification_uri("https://example.com");
    EXPECT_TRUE(res1.is_error());

    // Bad version
    auto res2 = managers::SafetyNumberEngine::parse_verification_uri("securecloud://verify?v=2&u1=a&u2=b&sn=123");
    EXPECT_TRUE(res2.is_error());

    // Missing parameter
    auto res3 = managers::SafetyNumberEngine::parse_verification_uri("securecloud://verify?v=1&u1=a&sn=123");
    EXPECT_TRUE(res3.is_error());
}

} // namespace securecloud::client::tests
