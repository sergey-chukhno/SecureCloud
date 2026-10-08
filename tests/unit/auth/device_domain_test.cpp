#include "auth/crypto/device_key_validator.hpp"
#include "auth/domain/enums.hpp"

#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

namespace securecloud::auth::crypto::test {
namespace {

using domain::DeviceStatus;

// ============================================================================
// 1. DeviceStatus Enum Serialization & Deserialization Tests
// ============================================================================

TEST(DeviceDomainTest, DeviceStatusEnumToString) {
    EXPECT_EQ(domain::to_string(DeviceStatus::PendingAuthorization), "PendingAuthorization");
    EXPECT_EQ(domain::to_string(DeviceStatus::Active), "Active");
    EXPECT_EQ(domain::to_string(DeviceStatus::Revoked), "Revoked");
}

TEST(DeviceDomainTest, DeviceStatusEnumParseValidStrings) {
    EXPECT_EQ(domain::parse_enum<DeviceStatus>("PendingAuthorization"), DeviceStatus::PendingAuthorization);
    EXPECT_EQ(domain::parse_enum<DeviceStatus>("PENDING_AUTHORIZATION"), DeviceStatus::PendingAuthorization);
    EXPECT_EQ(domain::parse_enum<DeviceStatus>("pending_authorization"), DeviceStatus::PendingAuthorization);

    EXPECT_EQ(domain::parse_enum<DeviceStatus>("Active"), DeviceStatus::Active);
    EXPECT_EQ(domain::parse_enum<DeviceStatus>("ACTIVE"), DeviceStatus::Active);
    EXPECT_EQ(domain::parse_enum<DeviceStatus>("active"), DeviceStatus::Active);

    EXPECT_EQ(domain::parse_enum<DeviceStatus>("Revoked"), DeviceStatus::Revoked);
    EXPECT_EQ(domain::parse_enum<DeviceStatus>("REVOKED"), DeviceStatus::Revoked);
    EXPECT_EQ(domain::parse_enum<DeviceStatus>("revoked"), DeviceStatus::Revoked);
}

TEST(DeviceDomainTest, DeviceStatusEnumParseInvalidStrings) {
    EXPECT_FALSE(domain::parse_enum<DeviceStatus>("").has_value());
    EXPECT_FALSE(domain::parse_enum<DeviceStatus>("Invalid").has_value());
    EXPECT_FALSE(domain::parse_enum<DeviceStatus>("Pending").has_value());
    EXPECT_FALSE(domain::parse_enum<DeviceStatus>("Disabled").has_value());
}

// ============================================================================
// Cryptographic Test Helpers
// ============================================================================

struct TestEd25519Keypair {
    std::vector<uint8_t> public_key;
    EVP_PKEY* pkey{nullptr};

    ~TestEd25519Keypair() {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
    }

    TestEd25519Keypair() = default;
    TestEd25519Keypair(const TestEd25519Keypair&) = delete;
    TestEd25519Keypair& operator=(const TestEd25519Keypair&) = delete;
    TestEd25519Keypair(TestEd25519Keypair&& other) noexcept
        : public_key(std::move(other.public_key)), pkey(other.pkey) {
        other.pkey = nullptr;
    }
    TestEd25519Keypair& operator=(TestEd25519Keypair&& other) noexcept {
        if (this != &other) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
            public_key = std::move(other.public_key);
            pkey = other.pkey;
            other.pkey = nullptr;
        }
        return *this;
    }
};

TestEd25519Keypair generate_ed25519_keypair() {
    TestEd25519Keypair kp;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX for ED25519");
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &kp.pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate ED25519 keypair");
    }
    EVP_PKEY_CTX_free(ctx);

    size_t len = 32;
    kp.public_key.resize(len);
    if (EVP_PKEY_get_raw_public_key(kp.pkey, kp.public_key.data(), &len) <= 0) {
        throw std::runtime_error("Failed to extract raw Ed25519 public key");
    }
    return kp;
}

std::vector<uint8_t> sign_payload(EVP_PKEY* pkey, std::span<const uint8_t> payload) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to init EVP_DigestSignInit");
    }
    size_t sig_len = 64;
    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSign(ctx, sig.data(), &sig_len, payload.data(), payload.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to sign payload");
    }
    EVP_MD_CTX_free(ctx);
    sig.resize(sig_len);
    return sig;
}

std::vector<uint8_t> generate_x25519_public_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX for X25519");
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate X25519 keypair");
    }
    EVP_PKEY_CTX_free(ctx);

    size_t len = 32;
    std::vector<uint8_t> pub(len);
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to extract raw X25519 public key");
    }
    EVP_PKEY_free(pkey);
    return pub;
}

// ============================================================================
// 2. Identity Key Validation Tests
// ============================================================================

TEST(DeviceDomainTest, ValidateIdentityKey_ValidEd25519KeySucceeds) {
    auto kp = generate_ed25519_keypair();
    std::string err;
    EXPECT_TRUE(DeviceKeyValidator::validate_identity_key(kp.public_key, &err));
    EXPECT_TRUE(err.empty());
}

TEST(DeviceDomainTest, ValidateIdentityKey_RejectsInvalidSizes) {
    std::string err;

    // Empty buffer
    EXPECT_FALSE(DeviceKeyValidator::validate_identity_key({}, &err));
    EXPECT_FALSE(err.empty());

    // 16 bytes
    std::vector<uint8_t> k16(16, 0x42);
    EXPECT_FALSE(DeviceKeyValidator::validate_identity_key(k16, &err));

    // 31 bytes
    std::vector<uint8_t> k31(31, 0x42);
    EXPECT_FALSE(DeviceKeyValidator::validate_identity_key(k31, &err));

    // 33 bytes
    std::vector<uint8_t> k33(33, 0x42);
    EXPECT_FALSE(DeviceKeyValidator::validate_identity_key(k33, &err));

    // 64 bytes (private key / expanded seed length)
    std::vector<uint8_t> k64(64, 0x42);
    EXPECT_FALSE(DeviceKeyValidator::validate_identity_key(k64, &err));
}

TEST(DeviceDomainTest, ValidateIdentityKey_ZeroPrivateKeyInvariant) {
    std::string err;

    // PEM header injected into a 32-byte buffer
    std::string pem_prefix = "-----BEGIN PRIVATE KEY-----";
    std::vector<uint8_t> bad_buf(pem_prefix.begin(), pem_prefix.end());
    bad_buf.resize(32, 0x00);

    EXPECT_FALSE(DeviceKeyValidator::validate_identity_key(bad_buf, &err));
    EXPECT_NE(err.find("Zero Private Key Invariant"), std::string::npos);
}

// ============================================================================
// 3. Signed Prekey Validation Tests
// ============================================================================

TEST(DeviceDomainTest, ValidateSignedPrekey_ValidX25519KeySucceeds) {
    auto pub = generate_x25519_public_key();
    std::string err;
    EXPECT_TRUE(DeviceKeyValidator::validate_signed_prekey(pub, &err));
    EXPECT_TRUE(err.empty());
}

TEST(DeviceDomainTest, ValidateSignedPrekey_RejectsInvalidSizesAndPrivateMarkers) {
    std::string err;

    // 0 bytes
    EXPECT_FALSE(DeviceKeyValidator::validate_signed_prekey({}, &err));

    // 64 bytes
    std::vector<uint8_t> k64(64, 0x55);
    EXPECT_FALSE(DeviceKeyValidator::validate_signed_prekey(k64, &err));

    // Private key marker
    std::string marker = "PRIVATE KEY";
    std::vector<uint8_t> bad_buf(marker.begin(), marker.end());
    bad_buf.resize(32, 0x00);
    EXPECT_FALSE(DeviceKeyValidator::validate_signed_prekey(bad_buf, &err));
}

// ============================================================================
// 4. Signed Prekey Cryptographic Signature Verification Tests
// ============================================================================

TEST(DeviceDomainTest, ValidateSignedPrekeySignature_ValidSignaturePasses) {
    auto kp = generate_ed25519_keypair();
    auto prekey = generate_x25519_public_key();
    auto signature = sign_payload(kp.pkey, prekey);

    std::string err;
    EXPECT_TRUE(DeviceKeyValidator::validate_signed_prekey_signature(kp.public_key, prekey, signature, &err));
    EXPECT_TRUE(err.empty());
}

TEST(DeviceDomainTest, ValidateSignedPrekeySignature_TamperedSignatureFails) {
    auto kp = generate_ed25519_keypair();
    auto prekey = generate_x25519_public_key();
    auto signature = sign_payload(kp.pkey, prekey);

    // Tamper with one bit of signature
    signature[10] ^= 0x01;

    std::string err;
    EXPECT_FALSE(DeviceKeyValidator::validate_signed_prekey_signature(kp.public_key, prekey, signature, &err));
    EXPECT_NE(err.find("Cryptographic signature verification failed"), std::string::npos);
}

TEST(DeviceDomainTest, ValidateSignedPrekeySignature_TamperedPrekeyFails) {
    auto kp = generate_ed25519_keypair();
    auto prekey = generate_x25519_public_key();
    auto signature = sign_payload(kp.pkey, prekey);

    // Tamper with one byte of prekey
    prekey[0] ^= 0x80;

    std::string err;
    EXPECT_FALSE(DeviceKeyValidator::validate_signed_prekey_signature(kp.public_key, prekey, signature, &err));
}

TEST(DeviceDomainTest, ValidateSignedPrekeySignature_WrongIdentityKeyFails) {
    auto kp1 = generate_ed25519_keypair();
    auto kp2 = generate_ed25519_keypair();
    auto prekey = generate_x25519_public_key();
    auto signature = sign_payload(kp1.pkey, prekey);

    std::string err;
    // Verifying with kp2's public key must fail
    EXPECT_FALSE(DeviceKeyValidator::validate_signed_prekey_signature(kp2.public_key, prekey, signature, &err));
}

TEST(DeviceDomainTest, ValidateSignedPrekeySignature_InvalidSignatureSize) {
    auto kp = generate_ed25519_keypair();
    auto prekey = generate_x25519_public_key();

    std::vector<uint8_t> short_sig(63, 0xAA);
    std::string err;
    EXPECT_FALSE(DeviceKeyValidator::validate_signed_prekey_signature(kp.public_key, prekey, short_sig, &err));
    EXPECT_NE(err.find("must be exactly 64 bytes"), std::string::npos);
}

// ============================================================================
// 5. One-Time Prekeys Validation Tests
// ============================================================================

TEST(DeviceDomainTest, ValidateOneTimePrekeys_EmptyBatchAllowed) {
    std::string err;
    EXPECT_TRUE(DeviceKeyValidator::validate_one_time_prekeys({}, &err));
}

TEST(DeviceDomainTest, ValidateOneTimePrekeys_ValidBatchPasses) {
    std::vector<std::vector<uint8_t>> prekeys;
    for (int i = 0; i < 20; ++i) {
        prekeys.push_back(generate_x25519_public_key());
    }

    std::string err;
    EXPECT_TRUE(DeviceKeyValidator::validate_one_time_prekeys(prekeys, &err));
}

TEST(DeviceDomainTest, ValidateOneTimePrekeys_RejectsBatchOver100) {
    std::vector<std::vector<uint8_t>> prekeys;
    auto key = generate_x25519_public_key();
    for (int i = 0; i < 101; ++i) {
        prekeys.push_back(key);
    }

    std::string err;
    EXPECT_FALSE(DeviceKeyValidator::validate_one_time_prekeys(prekeys, &err));
    EXPECT_NE(err.find("exceeds limit of 100"), std::string::npos);
}

TEST(DeviceDomainTest, ValidateOneTimePrekeys_RejectsInvalidKeyInBatch) {
    std::vector<std::vector<uint8_t>> prekeys;
    prekeys.push_back(generate_x25519_public_key());
    prekeys.push_back(std::vector<uint8_t>(16, 0x00)); // Malformed size

    std::string err;
    EXPECT_FALSE(DeviceKeyValidator::validate_one_time_prekeys(prekeys, &err));
    EXPECT_NE(err.find("at index 1"), std::string::npos);
}

// ============================================================================
// 6. Complete Registration Bundle Validation Tests
// ============================================================================

TEST(DeviceDomainTest, ValidateRegistrationBundle_ValidBundlePasses) {
    auto kp = generate_ed25519_keypair();
    auto prekey = generate_x25519_public_key();
    auto signature = sign_payload(kp.pkey, prekey);

    std::vector<std::vector<uint8_t>> otks;
    for (int i = 0; i < 5; ++i) {
        otks.push_back(generate_x25519_public_key());
    }

    std::string err;
    EXPECT_TRUE(DeviceKeyValidator::validate_registration_bundle(kp.public_key, prekey, signature, otks, &err));
    EXPECT_TRUE(err.empty());
}

TEST(DeviceDomainTest, ValidateRegistrationBundle_FailsOnBadSignature) {
    auto kp = generate_ed25519_keypair();
    auto prekey = generate_x25519_public_key();
    auto signature = sign_payload(kp.pkey, prekey);
    signature[0] ^= 0xFF; // Invalidate signature

    std::vector<std::vector<uint8_t>> otks = {generate_x25519_public_key()};

    std::string err;
    EXPECT_FALSE(DeviceKeyValidator::validate_registration_bundle(kp.public_key, prekey, signature, otks, &err));
}

// ============================================================================
// 7. Zero Private Key Invariant Exhaustive Tests
// ============================================================================

TEST(DeviceDomainTest, ContainsPrivateKeyMaterial_DetectsAllHeaders) {
    const std::vector<std::string> patterns = {
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN ED25519 PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "private key content",
        "PRIVATE_KEY_DATA",
    };

    for (const auto& pattern : patterns) {
        std::vector<uint8_t> buf(pattern.begin(), pattern.end());
        EXPECT_TRUE(DeviceKeyValidator::contains_private_key_material(buf)) << "Failed to detect pattern: " << pattern;
    }

    // Normal public key bytes do not trigger false positive
    auto valid_key = generate_x25519_public_key();
    EXPECT_FALSE(DeviceKeyValidator::contains_private_key_material(valid_key));
}

} // namespace
} // namespace securecloud::auth::crypto::test
