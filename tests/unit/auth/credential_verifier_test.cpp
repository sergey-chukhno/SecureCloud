#include "crypto/password_hasher.hpp"
#include "domain/auth_result.hpp"
#include "domain/credentials.hpp"
#include "domain/entities.hpp"
#include "domain/enums.hpp"
#include "domain/timestamp.hpp"
#include "domain/uuid.hpp"
#include "repository/exceptions.hpp"
#include "repository/user_repository.hpp"
#include "service/credential_verifier.hpp"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <string>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::Return;
using ::testing::Throw;

class MockUserRepository : public repository::IUserRepository {
  public:
    MOCK_METHOD(void, create_user, (const domain::UserEntity& user), (override));
    MOCK_METHOD(void, create_user, (const domain::UserEntity& user, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::optional<domain::UserEntity>, find_by_id, (const domain::Uuid& user_id), (override));
    MOCK_METHOD(std::optional<domain::UserEntity>, find_by_id,
                (const domain::Uuid& user_id, pqxx::transaction_base& tx), (override));

    std::optional<domain::UserEntity> find_by_credential_identifier(std::string_view credential_identifier) override {
        return find_by_credential_identifier_str(std::string(credential_identifier));
    }
    std::optional<domain::UserEntity> find_by_credential_identifier(std::string_view credential_identifier,
                                                                    pqxx::transaction_base& tx) override {
        return find_by_credential_identifier_tx_str(std::string(credential_identifier), tx);
    }

    MOCK_METHOD(std::optional<domain::UserEntity>, find_by_credential_identifier_str,
                (const std::string& credential_identifier));
    MOCK_METHOD(std::optional<domain::UserEntity>, find_by_credential_identifier_tx_str,
                (const std::string& credential_identifier, pqxx::transaction_base& tx));

    MOCK_METHOD(void, update_user, (const domain::UserEntity& user), (override));
    MOCK_METHOD(void, update_user, (const domain::UserEntity& user, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(void, set_account_status,
                (const domain::Uuid& user_id, domain::AccountStatus status, uint64_t expected_version), (override));
    MOCK_METHOD(void, set_account_status,
                (const domain::Uuid& user_id, domain::AccountStatus status, uint64_t expected_version,
                 pqxx::transaction_base& tx),
                (override));
};

class MockPasswordHasher : public crypto::IPasswordHasher {
  public:
    MOCK_METHOD(std::string, hash_password, (const common::configuration::SecretString& password), (override));

    bool verify_password(const common::configuration::SecretString& password,
                         std::string_view stored_verifier) override {
        return verify_password_str(password, std::string(stored_verifier));
    }

    MOCK_METHOD(bool, verify_password_str,
                (const common::configuration::SecretString& password, const std::string& stored_verifier));
    MOCK_METHOD(void, execute_dummy_verification, (const common::configuration::SecretString& password), (override));
};

domain::UserEntity create_sample_user(domain::AccountStatus status = domain::AccountStatus::Active) {
    domain::UserEntity user;
    user.user_id = domain::Uuid::generate_v7();
    user.credential_identifier = "alice@example.com";
    user.password_verifier = "$argon2id$v=19$m=65536,t=3,p=1$fake_salt$fake_hash";
    user.password_algorithm = "argon2id";
    user.password_updated_at = std::chrono::system_clock::now();
    user.account_status = status;
    user.created_at = std::chrono::system_clock::now();
    user.updated_at = std::chrono::system_clock::now();
    user.version = 1;
    return user;
}

// Test 1: Valid credentials return Success with populated UserEntity
TEST(CredentialVerifierTest, Verify_ValidCredentials_ReturnsSuccess) {
    auto mock_user_repo = std::make_shared<MockUserRepository>();
    auto mock_hasher = std::make_shared<MockPasswordHasher>();
    CredentialVerifier verifier(mock_user_repo, mock_hasher);

    domain::CredentialIdentifier id("alice@example.com");
    domain::PasswordCredential pwd("ValidP@ssword123");
    auto user = create_sample_user(domain::AccountStatus::Active);

    EXPECT_CALL(*mock_user_repo, find_by_credential_identifier_str("alice@example.com")).WillOnce(Return(user));
    EXPECT_CALL(*mock_hasher, verify_password_str(_, user.password_verifier)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hasher, execute_dummy_verification(_)).Times(0);

    auto result = verifier.verify(id, pwd);

    EXPECT_EQ(result.status, domain::AuthenticationStatus::Success);
    EXPECT_TRUE(result.is_success());
    ASSERT_TRUE(result.user.has_value());
    EXPECT_EQ(result.user->user_id, user.user_id);
    EXPECT_EQ(result.user->credential_identifier, "alice@example.com");
}

// Test 2: Incorrect password returns InvalidCredentials
TEST(CredentialVerifierTest, Verify_WrongPassword_ReturnsInvalidCredentials) {
    auto mock_user_repo = std::make_shared<MockUserRepository>();
    auto mock_hasher = std::make_shared<MockPasswordHasher>();
    CredentialVerifier verifier(mock_user_repo, mock_hasher);

    domain::CredentialIdentifier id("alice@example.com");
    domain::PasswordCredential pwd("WrongPassword!");
    auto user = create_sample_user(domain::AccountStatus::Active);

    EXPECT_CALL(*mock_user_repo, find_by_credential_identifier_str("alice@example.com")).WillOnce(Return(user));
    EXPECT_CALL(*mock_hasher, verify_password_str(_, user.password_verifier)).WillOnce(Return(false));

    auto result = verifier.verify(id, pwd);

    EXPECT_EQ(result.status, domain::AuthenticationStatus::InvalidCredentials);
    EXPECT_FALSE(result.is_success());
    EXPECT_FALSE(result.user.has_value());
}

// Test 3: Non-existent user executes dummy verification to equalize timing
TEST(CredentialVerifierTest, Verify_NonExistentUser_ExecutesDummyVerificationAndFails) {
    auto mock_user_repo = std::make_shared<MockUserRepository>();
    auto mock_hasher = std::make_shared<MockPasswordHasher>();
    CredentialVerifier verifier(mock_user_repo, mock_hasher);

    domain::CredentialIdentifier id("unknown@example.com");
    domain::PasswordCredential pwd("SomePassword123");

    EXPECT_CALL(*mock_user_repo, find_by_credential_identifier_str("unknown@example.com"))
        .WillOnce(Return(std::nullopt));
    // Must call execute_dummy_verification exactly once to prevent user enumeration
    EXPECT_CALL(*mock_hasher, execute_dummy_verification(_)).Times(1);
    EXPECT_CALL(*mock_hasher, verify_password_str(_, _)).Times(0);

    auto result = verifier.verify(id, pwd);

    EXPECT_EQ(result.status, domain::AuthenticationStatus::InvalidCredentials);
    EXPECT_FALSE(result.is_success());
    EXPECT_FALSE(result.user.has_value());
}

// Test 4: Missing user and wrong password return identical public status
TEST(CredentialVerifierTest, Verify_MissingUserAndWrongPassword_ReturnIdenticalStatus) {
    auto mock_user_repo = std::make_shared<MockUserRepository>();
    auto mock_hasher = std::make_shared<MockPasswordHasher>();
    CredentialVerifier verifier(mock_user_repo, mock_hasher);

    domain::CredentialIdentifier id1("missing@example.com");
    domain::CredentialIdentifier id2("alice@example.com");
    domain::PasswordCredential pwd("Password!");
    auto user = create_sample_user(domain::AccountStatus::Active);

    EXPECT_CALL(*mock_user_repo, find_by_credential_identifier_str("missing@example.com"))
        .WillOnce(Return(std::nullopt));
    EXPECT_CALL(*mock_hasher, execute_dummy_verification(_)).Times(1);

    EXPECT_CALL(*mock_user_repo, find_by_credential_identifier_str("alice@example.com")).WillOnce(Return(user));
    EXPECT_CALL(*mock_hasher, verify_password_str(_, _)).WillOnce(Return(false));

    auto result1 = verifier.verify(id1, pwd);
    auto result2 = verifier.verify(id2, pwd);

    // Both must be strictly equal to InvalidCredentials
    EXPECT_EQ(result1.status, result2.status);
    EXPECT_EQ(result1.status, domain::AuthenticationStatus::InvalidCredentials);
}

// Test 5: Disabled account returns AccountDisabled
TEST(CredentialVerifierTest, Verify_DisabledAccount_ReturnsAccountDisabled) {
    auto mock_user_repo = std::make_shared<MockUserRepository>();
    auto mock_hasher = std::make_shared<MockPasswordHasher>();
    CredentialVerifier verifier(mock_user_repo, mock_hasher);

    domain::CredentialIdentifier id("alice@example.com");
    domain::PasswordCredential pwd("Password123");
    auto user = create_sample_user(domain::AccountStatus::Disabled);

    EXPECT_CALL(*mock_user_repo, find_by_credential_identifier_str("alice@example.com")).WillOnce(Return(user));
    EXPECT_CALL(*mock_hasher, verify_password_str(_, _)).Times(0);

    auto result = verifier.verify(id, pwd);

    EXPECT_EQ(result.status, domain::AuthenticationStatus::AccountDisabled);
    EXPECT_FALSE(result.is_success());
    EXPECT_FALSE(result.user.has_value());
}

// Test 6: Database exception fails closed with InternalError
TEST(CredentialVerifierTest, Verify_DatabaseException_FailsClosedWithInternalError) {
    auto mock_user_repo = std::make_shared<MockUserRepository>();
    auto mock_hasher = std::make_shared<MockPasswordHasher>();
    CredentialVerifier verifier(mock_user_repo, mock_hasher);

    domain::CredentialIdentifier id("alice@example.com");
    domain::PasswordCredential pwd("Password123");

    EXPECT_CALL(*mock_user_repo, find_by_credential_identifier_str("alice@example.com"))
        .WillOnce(Throw(repository::DatabaseExecutionException("Connection refused")));

    auto result = verifier.verify(id, pwd);

    EXPECT_EQ(result.status, domain::AuthenticationStatus::InternalError);
    EXPECT_FALSE(result.is_success());
    EXPECT_FALSE(result.user.has_value());
}

// Test 7: Password hasher exception fails closed with InternalError
TEST(CredentialVerifierTest, Verify_PasswordHasherException_FailsClosedWithInternalError) {
    auto mock_user_repo = std::make_shared<MockUserRepository>();
    auto mock_hasher = std::make_shared<MockPasswordHasher>();
    CredentialVerifier verifier(mock_user_repo, mock_hasher);

    domain::CredentialIdentifier id("alice@example.com");
    domain::PasswordCredential pwd("Password123");
    auto user = create_sample_user(domain::AccountStatus::Active);

    EXPECT_CALL(*mock_user_repo, find_by_credential_identifier_str("alice@example.com")).WillOnce(Return(user));
    EXPECT_CALL(*mock_hasher, verify_password_str(_, _))
        .WillOnce(Throw(std::runtime_error("OpenSSL KDF internal failure")));

    auto result = verifier.verify(id, pwd);

    EXPECT_EQ(result.status, domain::AuthenticationStatus::InternalError);
    EXPECT_FALSE(result.is_success());
}

// Test 8: Corrupted password verifier in DB fails closed with InvalidCredentials
TEST(CredentialVerifierTest, Verify_CorruptedPasswordVerifierInDb_FailsClosedWithInvalidCredentials) {
    auto mock_user_repo = std::make_shared<MockUserRepository>();
    auto mock_hasher = std::make_shared<MockPasswordHasher>();
    CredentialVerifier verifier(mock_user_repo, mock_hasher);

    domain::CredentialIdentifier id("alice@example.com");
    domain::PasswordCredential pwd("Password123");
    auto user = create_sample_user(domain::AccountStatus::Active);
    user.password_verifier = "corrupted_garbage_hash";

    EXPECT_CALL(*mock_user_repo, find_by_credential_identifier_str("alice@example.com")).WillOnce(Return(user));
    EXPECT_CALL(*mock_hasher, verify_password_str(_, "corrupted_garbage_hash"))
        .WillOnce(Return(false)); // Hasher fails closed

    auto result = verifier.verify(id, pwd);

    EXPECT_EQ(result.status, domain::AuthenticationStatus::InvalidCredentials);
    EXPECT_FALSE(result.is_success());
}

// Test 9: Constructor throws invalid_argument on null user repository
TEST(CredentialVerifierTest, Constructor_NullUserRepository_ThrowsInvalidArgument) {
    auto mock_hasher = std::make_shared<MockPasswordHasher>();
    EXPECT_THROW(CredentialVerifier(nullptr, mock_hasher), std::invalid_argument);
}

// Test 10: Constructor throws invalid_argument on null password hasher
TEST(CredentialVerifierTest, Constructor_NullPasswordHasher_ThrowsInvalidArgument) {
    auto mock_user_repo = std::make_shared<MockUserRepository>();
    EXPECT_THROW(CredentialVerifier(mock_user_repo, nullptr), std::invalid_argument);
}

} // namespace
} // namespace securecloud::auth::service::test
