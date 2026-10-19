#include "auth/crypto/prekey_validator.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <vector>

namespace securecloud::auth::crypto::test {
namespace {

// Helper to generate a valid X25519 public key using OpenSSL
std::vector<uint8_t> generate_valid_x25519_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    size_t len = 32;
    std::vector<uint8_t> key(len);
    EVP_PKEY_get_raw_public_key(pkey, key.data(), &len);
    EVP_PKEY_free(pkey);
    return key;
}

// ============================================================================
// Single Prekey Validation Tests
// ============================================================================

TEST(PrekeyValidatorTest, ValidateSinglePrekey_ValidKey_ReturnsTrue) {
    auto key = generate_valid_x25519_key();
    std::string err;
    EXPECT_TRUE(PrekeyValidator::validate_single_prekey(key, &err));
    EXPECT_TRUE(err.empty());
}

TEST(PrekeyValidatorTest, ValidateSinglePrekey_InvalidSize_ReturnsFalse) {
    std::vector<uint8_t> short_key(31, 0x42);
    std::string err;
    EXPECT_FALSE(PrekeyValidator::validate_single_prekey(short_key, &err));
    EXPECT_THAT(err, ::testing::HasSubstr("exactly 32 bytes"));

    std::vector<uint8_t> long_key(33, 0x42);
    EXPECT_FALSE(PrekeyValidator::validate_single_prekey(long_key, &err));
    EXPECT_THAT(err, ::testing::HasSubstr("exactly 32 bytes"));
}

TEST(PrekeyValidatorTest, ValidateSinglePrekey_AllZeros_ReturnsFalse) {
    std::vector<uint8_t> zero_key(32, 0x00);
    std::string err;
    EXPECT_FALSE(PrekeyValidator::validate_single_prekey(zero_key, &err));
    EXPECT_THAT(err, ::testing::HasSubstr("all zeros"));
}

TEST(PrekeyValidatorTest, ValidateSinglePrekey_AllFF_ReturnsFalse) {
    std::vector<uint8_t> ff_key(32, 0xFF);
    std::string err;
    EXPECT_FALSE(PrekeyValidator::validate_single_prekey(ff_key, &err));
    EXPECT_THAT(err, ::testing::HasSubstr("all 0xFF"));
}

TEST(PrekeyValidatorTest, ValidateSinglePrekey_ContainsPrivateKeyMarker_ReturnsFalse) {
    std::string marker = "PRIVATE KEY";
    std::vector<uint8_t> key(32, 0x55);
    std::copy(marker.begin(), marker.end(), key.begin());

    std::string err;
    EXPECT_FALSE(PrekeyValidator::validate_single_prekey(key, &err));
    EXPECT_THAT(err, ::testing::HasSubstr("Zero Private Key Invariant"));
}

// ============================================================================
// Prekey Batch Validation Tests
// ============================================================================

TEST(PrekeyValidatorTest, ValidatePrekeyBatch_ValidBatch_ReturnsTrue) {
    std::vector<std::vector<uint8_t>> batch;
    for (int i = 0; i < 5; ++i) {
        batch.push_back(generate_valid_x25519_key());
    }

    std::string err;
    EXPECT_TRUE(PrekeyValidator::validate_prekey_batch(batch, &err));
    EXPECT_TRUE(err.empty());
}

TEST(PrekeyValidatorTest, ValidatePrekeyBatch_EmptyBatch_ReturnsFalse) {
    std::vector<std::vector<uint8_t>> empty_batch;
    std::string err;
    EXPECT_FALSE(PrekeyValidator::validate_prekey_batch(empty_batch, &err));
    EXPECT_THAT(err, ::testing::HasSubstr("at least 1 key"));
}

TEST(PrekeyValidatorTest, ValidatePrekeyBatch_OversizedBatch_ReturnsFalse) {
    std::vector<std::vector<uint8_t>> large_batch;
    for (int i = 0; i < 101; ++i) {
        large_batch.push_back(generate_valid_x25519_key());
    }

    std::string err;
    EXPECT_FALSE(PrekeyValidator::validate_prekey_batch(large_batch, &err));
    EXPECT_THAT(err, ::testing::HasSubstr("exceeds maximum allowed limit of 100"));
}

TEST(PrekeyValidatorTest, ValidatePrekeyBatch_DuplicateKeyInBatch_ReturnsFalse) {
    auto key1 = generate_valid_x25519_key();
    auto key2 = generate_valid_x25519_key();

    std::vector<std::vector<uint8_t>> batch = {key1, key2, key1}; // duplicate key1

    std::string err;
    EXPECT_FALSE(PrekeyValidator::validate_prekey_batch(batch, &err));
    EXPECT_THAT(err, ::testing::HasSubstr("Duplicate one-time prekey found within batch"));
}

TEST(PrekeyValidatorTest, ValidatePrekeyBatch_InvalidKeyInBatch_ReturnsFalse) {
    auto key1 = generate_valid_x25519_key();
    std::vector<uint8_t> corrupted_key(32, 0x00); // all zeros

    std::vector<std::vector<uint8_t>> batch = {key1, corrupted_key};

    std::string err;
    EXPECT_FALSE(PrekeyValidator::validate_prekey_batch(batch, &err));
    EXPECT_THAT(err, ::testing::HasSubstr("all zeros"));
}

} // namespace
} // namespace securecloud::auth::crypto::test
