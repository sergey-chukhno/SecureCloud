#include "crypto/argon2id_hasher.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <securecloud/configuration/secret_string.hpp>
#include <string>
#include <vector>

namespace securecloud::auth::crypto {
namespace {

using common::configuration::SecretString;

// Fast config for unit tests to keep test suite execution fast (sub-second)
Argon2idConfig create_fast_test_config() {
    Argon2idConfig config;
    config.memory_cost_kib = 64; // 64 KiB
    config.iterations = 1;
    config.parallelism = 1;
    config.salt_length = 16;
    config.hash_length = 32;
    return config;
}

TEST(Argon2idHasherTest, HashPassword_ProducesValidPhcFormat) {
    OpenSslArgon2idHasher hasher(create_fast_test_config());
    SecretString password("P@ssw0rd!Secure2026");

    std::string verifier = hasher.hash_password(password);

    EXPECT_FALSE(verifier.empty());
    EXPECT_TRUE(verifier.starts_with("$argon2id$v=19$m=64,t=1,p=1$"));

    // Check count of '$' delimiters
    size_t dollar_count = 0;
    for (char c : verifier) {
        if (c == '$') {
            ++dollar_count;
        }
    }
    // Expected: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash> -> 5 delimiters
    EXPECT_EQ(dollar_count, 5);
}

TEST(Argon2idHasherTest, VerifyPassword_MatchingPassword_ReturnsTrue) {
    OpenSslArgon2idHasher hasher(create_fast_test_config());
    SecretString password("CorrectHorseBatteryStaple");

    std::string verifier = hasher.hash_password(password);

    EXPECT_TRUE(hasher.verify_password(password, verifier));
}

TEST(Argon2idHasherTest, VerifyPassword_WrongPassword_ReturnsFalse) {
    OpenSslArgon2idHasher hasher(create_fast_test_config());
    SecretString correct_pwd("CorrectPassword123!");
    SecretString wrong_pwd("WrongPassword456?");

    std::string verifier = hasher.hash_password(correct_pwd);

    EXPECT_FALSE(hasher.verify_password(wrong_pwd, verifier));
}

TEST(Argon2idHasherTest, VerifyPassword_EmptyPassword_WorksConsistently) {
    OpenSslArgon2idHasher hasher(create_fast_test_config());
    SecretString empty_pwd("");
    SecretString non_empty_pwd("Something");

    std::string verifier = hasher.hash_password(empty_pwd);

    EXPECT_TRUE(hasher.verify_password(empty_pwd, verifier));
    EXPECT_FALSE(hasher.verify_password(non_empty_pwd, verifier));
}

TEST(Argon2idHasherTest, VerifyPassword_MalformedVerifierStrings_ReturnsFalse) {
    OpenSslArgon2idHasher hasher(create_fast_test_config());
    SecretString password("TestPassword");

    // Various malformed strings must all fail-closed (return false)
    EXPECT_FALSE(hasher.verify_password(password, ""));
    EXPECT_FALSE(hasher.verify_password(password, "plain_text_not_phc"));
    EXPECT_FALSE(hasher.verify_password(password, "$bcrypt$v=19$m=64,t=1,p=1$salt$hash"));
    EXPECT_FALSE(hasher.verify_password(password, "$argon2id$v=99$m=64,t=1,p=1$salt$hash"));
    EXPECT_FALSE(hasher.verify_password(password, "$argon2id$v=19$m=0,t=1,p=1$salt$hash"));
    EXPECT_FALSE(hasher.verify_password(password, "$argon2id$v=19$invalid_params$salt$hash"));
    EXPECT_FALSE(hasher.verify_password(password, "$argon2id$v=19$m=64,t=1,p=1$!!!invalid_b64!!!$hash"));
    EXPECT_FALSE(hasher.verify_password(password, "$argon2id$v=19$m=64,t=1,p=1$salt$"));
    EXPECT_FALSE(hasher.verify_password(password, "$argon2id$v=19$m=64,t=1,p=1$$hash"));
    EXPECT_FALSE(hasher.verify_password(password, "$argon2id$v=19$m=64,t=1,p=1$salt"));
}

TEST(Argon2idHasherTest, VerifyPassword_TamperedSaltOrHash_ReturnsFalse) {
    OpenSslArgon2idHasher hasher(create_fast_test_config());
    SecretString password("SecureUserCredentials");

    std::string verifier = hasher.hash_password(password);
    ASSERT_TRUE(hasher.verify_password(password, verifier));

    // Tamper with the hash
    std::string tampered_hash = verifier;
    auto last_dollar = tampered_hash.rfind('$');
    ASSERT_NE(last_dollar, std::string::npos);
    tampered_hash[last_dollar + 1] = (tampered_hash[last_dollar + 1] == 'A') ? 'B' : 'A';
    EXPECT_FALSE(hasher.verify_password(password, tampered_hash));

    // Tamper with salt
    std::string tampered_salt = verifier;
    auto second_last_dollar = tampered_salt.rfind('$', last_dollar - 1);
    ASSERT_NE(second_last_dollar, std::string::npos);

    tampered_salt[second_last_dollar + 1] = (tampered_salt[second_last_dollar + 1] == 'A') ? 'B' : 'A';
    EXPECT_FALSE(hasher.verify_password(password, tampered_salt));
}

TEST(Argon2idHasherTest, ExecuteDummyVerification_CompletesSuccessfully) {
    OpenSslArgon2idHasher hasher(create_fast_test_config());
    SecretString password("NonExistentUserPassword");

    // Must execute cleanly without throwing
    EXPECT_NO_THROW(hasher.execute_dummy_verification(password));
}

TEST(Argon2idHasherTest, UniqueSalts_GenerateDifferentVerifiersForSamePassword) {
    OpenSslArgon2idHasher hasher(create_fast_test_config());
    SecretString password("IdenticalPassword");

    std::string v1 = hasher.hash_password(password);
    std::string v2 = hasher.hash_password(password);

    EXPECT_NE(v1, v2);
    EXPECT_TRUE(hasher.verify_password(password, v1));
    EXPECT_TRUE(hasher.verify_password(password, v2));
}

TEST(Argon2idHasherTest, ConfigAccessor_ReturnsConfiguredValues) {
    Argon2idConfig config;
    config.memory_cost_kib = 128;
    config.iterations = 2;
    config.parallelism = 1;
    config.salt_length = 24;
    config.hash_length = 48;

    OpenSslArgon2idHasher hasher(config);
    EXPECT_EQ(hasher.config().memory_cost_kib, 128);
    EXPECT_EQ(hasher.config().iterations, 2);
    EXPECT_EQ(hasher.config().parallelism, 1);
    EXPECT_EQ(hasher.config().salt_length, 24);
    EXPECT_EQ(hasher.config().hash_length, 48);

    SecretString pwd("CustomConfigSecret");
    std::string v = hasher.hash_password(pwd);
    EXPECT_TRUE(v.starts_with("$argon2id$v=19$m=128,t=2,p=1$"));
    EXPECT_TRUE(hasher.verify_password(pwd, v));
}

} // namespace
} // namespace securecloud::auth::crypto
