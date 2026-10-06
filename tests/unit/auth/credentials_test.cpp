#include "domain/credentials.hpp"

#include <gtest/gtest.h>
#include <sstream>
#include <string>

namespace securecloud::auth::domain {
namespace {

// Test 1: Valid inputs construct successfully
TEST(CredentialsTest, CredentialIdentifier_ValidInputs_ConstructsSuccessfully) {
    auto opt1 = CredentialIdentifier::create("alice");
    ASSERT_TRUE(opt1.has_value());
    EXPECT_EQ(opt1->value(), "alice");
    EXPECT_EQ(opt1->view(), "alice");

    auto opt2 = CredentialIdentifier::create("user.name_123@sub.domain.com");
    ASSERT_TRUE(opt2.has_value());
    EXPECT_EQ(opt2->value(), "user.name_123@sub.domain.com");

    EXPECT_NO_THROW({
        CredentialIdentifier id("admin_service");
        EXPECT_EQ(id.value(), "admin_service");
    });
}

// Test 2: Whitespace trimming normalization
TEST(CredentialsTest, CredentialIdentifier_TrimsWhitespace) {
    auto opt = CredentialIdentifier::create("  \t\r\n admin@securecloud.io \n\r\t ");
    ASSERT_TRUE(opt.has_value());
    EXPECT_EQ(opt->value(), "admin@securecloud.io");

    CredentialIdentifier id("   operator_42   ");
    EXPECT_EQ(id.value(), "operator_42");
}

// Test 3: Too short identifiers rejected
TEST(CredentialsTest, CredentialIdentifier_TooShort_Rejected) {
    EXPECT_FALSE(CredentialIdentifier::create("").has_value());
    EXPECT_FALSE(CredentialIdentifier::create("   ").has_value());
    EXPECT_FALSE(CredentialIdentifier::create("a").has_value());
    EXPECT_FALSE(CredentialIdentifier::create("ab").has_value());
    EXPECT_FALSE(CredentialIdentifier::create("  ab  ").has_value());

    EXPECT_THROW(CredentialIdentifier{""}, InvalidCredentialException);
    EXPECT_THROW(CredentialIdentifier{"ab"}, InvalidCredentialException);
}

// Test 4: Too long identifiers rejected
TEST(CredentialsTest, CredentialIdentifier_TooLong_Rejected) {
    std::string exactly_255(255, 'x');
    auto opt_valid = CredentialIdentifier::create(exactly_255);
    EXPECT_TRUE(opt_valid.has_value());

    std::string too_long(256, 'y');
    EXPECT_FALSE(CredentialIdentifier::create(too_long).has_value());
    EXPECT_THROW(CredentialIdentifier{too_long}, InvalidCredentialException);
}

// Test 5: Control characters rejected
TEST(CredentialsTest, CredentialIdentifier_ControlCharacters_Rejected) {
    EXPECT_FALSE(CredentialIdentifier::create("user\x01name").has_value());
    EXPECT_FALSE(CredentialIdentifier::create("user\nname").has_value());
    EXPECT_FALSE(CredentialIdentifier::create("user\tname").has_value());
    EXPECT_FALSE(CredentialIdentifier::create("user\x7Fname").has_value());

    EXPECT_THROW(CredentialIdentifier{"admin\nroot"}, InvalidCredentialException);
    EXPECT_THROW(CredentialIdentifier{"admin\troot"}, InvalidCredentialException);
}

// Test 6: Stream output emits exact value
TEST(CredentialsTest, CredentialIdentifier_StreamOutput_EmitsExactValue) {
    CredentialIdentifier id("test.user@cloud.local");
    std::ostringstream ss;
    ss << id;
    EXPECT_EQ(ss.str(), "test.user@cloud.local");

    CredentialIdentifier id2("test.user@cloud.local");
    CredentialIdentifier id3("other.user@cloud.local");
    EXPECT_EQ(id, id2);
    EXPECT_NE(id, id3);
}

// Test 7: Valid passwords accepted within bounds
TEST(CredentialsTest, PasswordCredential_ValidPassword_Accepted) {
    auto opt = PasswordCredential::create("CorrectHorseBatteryStaple123!");
    ASSERT_TRUE(opt.has_value());
    EXPECT_FALSE(opt->empty());
    EXPECT_EQ(opt->size(), 29);
    EXPECT_EQ(opt->secret().expose_unredacted_secret(), "CorrectHorseBatteryStaple123!");

    // Empty password is technically valid string within length bound
    auto empty_opt = PasswordCredential::create("");
    ASSERT_TRUE(empty_opt.has_value());
    EXPECT_TRUE(empty_opt->empty());
    EXPECT_EQ(empty_opt->size(), 0);
}

// Test 8: Excessive length rejected to prevent Argon2id DoS attacks
TEST(CredentialsTest, PasswordCredential_ExcessiveLength_Rejected) {
    std::string max_password(1024, 'p');
    auto opt_max = PasswordCredential::create(max_password);
    EXPECT_TRUE(opt_max.has_value());
    EXPECT_EQ(opt_max->size(), 1024);

    std::string excessive_password(1025, 'p');
    EXPECT_FALSE(PasswordCredential::create(excessive_password).has_value());
    EXPECT_THROW(PasswordCredential{excessive_password}, InvalidCredentialException);

    common::configuration::SecretString secret_too_long(excessive_password);
    EXPECT_THROW(PasswordCredential{secret_too_long}, InvalidCredentialException);
}

// Test 9: Stream output strictly emits redaction placeholder
TEST(CredentialsTest, PasswordCredential_StreamOutput_EmitsRedacted) {
    PasswordCredential pwd("SuperSecretPassword987!");
    std::ostringstream ss;
    ss << pwd;

    // Must never output the raw password to stream
    EXPECT_EQ(ss.str(), "[REDACTED_PASSWORD]");
    EXPECT_EQ(ss.str().find("SuperSecretPassword"), std::string::npos);
}

// Test 10: Copy and move semantics
TEST(CredentialsTest, PasswordCredential_MoveAndCopySemantics) {
    PasswordCredential orig("P@ssword123");
    EXPECT_EQ(orig.size(), 11);

    PasswordCredential copy(orig);
    EXPECT_EQ(copy.size(), 11);
    EXPECT_EQ(copy.secret().expose_unredacted_secret(), "P@ssword123");

    PasswordCredential moved(std::move(copy));
    EXPECT_EQ(moved.size(), 11);
    EXPECT_EQ(moved.secret().expose_unredacted_secret(), "P@ssword123");

    PasswordCredential assigned("Initial");
    assigned = std::move(moved);
    EXPECT_EQ(assigned.size(), 11);
    EXPECT_EQ(assigned.secret().expose_unredacted_secret(), "P@ssword123");
}

} // namespace
} // namespace securecloud::auth::domain
