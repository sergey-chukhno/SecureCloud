#include "application/interfaces/i_crypto_provider.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/prekey_bundle.hpp"
#include "domain/prekey_policy.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>

namespace {

using namespace securecloud::client;
using namespace securecloud::client::domain;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::infrastructure::adapters;

// Helper to compute raw SHA-256 digest manually via EVP for format parity verification
std::string compute_raw_sha256_colon_hex(const std::vector<uint8_t>& data) {
    uint8_t hash[EVP_MAX_MD_SIZE];
    std::size_t hash_len = 0;
    EVP_Q_digest(nullptr, "SHA256", nullptr, data.data(), data.size(), hash, &hash_len);

    std::ostringstream oss;
    oss << "SHA256:";
    for (unsigned int i = 0; i < hash_len; ++i) {
        if (i > 0) {
            oss << ':';
        }
        oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(hash[i]);
    }
    return oss.str();
}

TEST(ClientCryptoIdentityTest, KeySizesAndFormatInvariants) {
    OpenSslCryptoProvider crypto;

    // 1. Identity Keypair (Ed25519)
    auto id_res = crypto.generate_identity_keypair();
    ASSERT_TRUE(id_res.is_ok());
    const auto& id_pair = id_res.value();

    EXPECT_EQ(id_pair.public_key.size(), PrekeyPolicy::kEd25519PublicKeySize);
    EXPECT_EQ(id_pair.public_key.size(), 32u);
    EXPECT_EQ(id_pair.private_key.size(), PrekeyPolicy::kEd25519PrivateKeySize);
    EXPECT_EQ(id_pair.private_key.size(), 32u);

    // 2. Signed Prekey (X25519 + Ed25519 Signature)
    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key);
    ASSERT_TRUE(spk_res.is_ok());
    const auto& spk = spk_res.value();

    EXPECT_EQ(spk.public_key.size(), PrekeyPolicy::kX25519PublicKeySize);
    EXPECT_EQ(spk.public_key.size(), 32u);
    EXPECT_EQ(spk.private_key.size(), PrekeyPolicy::kX25519PrivateKeySize);
    EXPECT_EQ(spk.private_key.size(), 32u);
    EXPECT_EQ(spk.signature.size(), PrekeyPolicy::kEd25519SignatureSize);
    EXPECT_EQ(spk.signature.size(), 64u);

    // 3. One-Time Prekeys (X25519)
    auto otpk_res = crypto.generate_one_time_prekeys(5, 1);
    ASSERT_TRUE(otpk_res.is_ok());
    const auto& otpks = otpk_res.value();
    EXPECT_EQ(otpks.size(), 5u);

    for (const auto& otpk : otpks) {
        EXPECT_EQ(otpk.record.public_key().size(), PrekeyPolicy::kX25519PublicKeySize);
        EXPECT_EQ(otpk.record.public_key().size(), 32u);
        EXPECT_EQ(otpk.private_key.size(), PrekeyPolicy::kX25519PrivateKeySize);
        EXPECT_EQ(otpk.private_key.size(), 32u);
    }
}

TEST(ClientCryptoIdentityTest, SignatureVerificationAndTamperingRejection) {
    OpenSslCryptoProvider crypto;

    auto id_res = crypto.generate_identity_keypair();
    ASSERT_TRUE(id_res.is_ok());
    const auto& id_pair = id_res.value();

    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key);
    ASSERT_TRUE(spk_res.is_ok());
    const auto& spk = spk_res.value();

    // Valid signature passes
    auto valid_res = crypto.verify_signed_prekey(id_pair.public_key, spk.public_key, spk.signature);
    ASSERT_TRUE(valid_res.is_ok());
    EXPECT_TRUE(valid_res.value());

    // Tampered payload: Flip each bit of prekey payload
    for (std::size_t i = 0; i < spk.public_key.size(); ++i) {
        auto tampered_spk = spk.public_key;
        tampered_spk[i] ^= 0x01;
        auto verify_res = crypto.verify_signed_prekey(id_pair.public_key, tampered_spk, spk.signature);
        ASSERT_TRUE(verify_res.is_ok());
        EXPECT_FALSE(verify_res.value());
    }

    // Tampered signature: Flip bits of signature
    for (std::size_t i = 0; i < spk.signature.size(); i += 8) {
        auto tampered_sig = spk.signature;
        tampered_sig[i] ^= 0x80;
        auto verify_res = crypto.verify_signed_prekey(id_pair.public_key, spk.public_key, tampered_sig);
        ASSERT_TRUE(verify_res.is_ok());
        EXPECT_FALSE(verify_res.value());
    }

    // Wrong identity key rejects
    auto another_id = crypto.generate_identity_keypair().value();
    auto verify_wrong_res = crypto.verify_signed_prekey(another_id.public_key, spk.public_key, spk.signature);
    ASSERT_TRUE(verify_wrong_res.is_ok());
    EXPECT_FALSE(verify_wrong_res.value());
}

TEST(ClientCryptoIdentityTest, FingerprintFormatMatchesBackendParity) {
    OpenSslCryptoProvider crypto;

    auto id_res = crypto.generate_identity_keypair();
    ASSERT_TRUE(id_res.is_ok());
    const auto& id_pair = id_res.value();

    auto fp_res = crypto.compute_identity_fingerprint(id_pair.public_key);
    ASSERT_TRUE(fp_res.is_ok());
    const auto& fp = fp_res.value();

    // Verify format compliance
    EXPECT_TRUE(CryptoIdentity::is_valid_fingerprint(fp));
    EXPECT_EQ(fp.size(), 102u); // "SHA256:" (7) + 32*2 hex (64) + 31 colons (31) = 102 chars

    // Check against independent manual EVP SHA-256 calculation
    const std::string expected_fp = compute_raw_sha256_colon_hex(id_pair.public_key);
    EXPECT_EQ(fp, expected_fp);
}

TEST(ClientCryptoIdentityTest, PrivateKeyIsolationAndCleanseGuarantees) {
    MemorySecureStorage storage;
    const DeviceId did("dev-cleanse-001");

    // 1. Create a DevicePrivateBundle
    std::vector<uint8_t> id_pub(32, 0x11);
    securecloud::common::configuration::SecretString id_priv(std::string(32, '\x22'));
    std::vector<uint8_t> spk_pub(32, 0x33);
    securecloud::common::configuration::SecretString spk_priv(std::string(32, '\x44'));
    std::vector<uint8_t> sig(64, 0x55);

    DevicePrivateBundle bundle(did, id_pub, id_priv, spk_pub, spk_priv, sig);
    bundle.add_one_time_prekey("1", securecloud::common::configuration::SecretString(std::string(32, '\x66')));

    EXPECT_EQ(bundle.one_time_prekey_count(), 1u);
    EXPECT_FALSE(bundle.identity_private_key().empty());
    EXPECT_FALSE(bundle.signed_prekey_private_key().empty());

    // 2. Persist to storage via KeyStorageHelper
    auto store_res = KeyStorageHelper::save_bundle(storage, bundle);
    ASSERT_TRUE(store_res.is_ok());

    // 3. Clear bundle memory and verify zeroization
    bundle.clear();
    EXPECT_EQ(bundle.one_time_prekey_count(), 0u);
    EXPECT_TRUE(bundle.identity_private_key().empty());
    EXPECT_TRUE(bundle.signed_prekey_private_key().empty());

    // 4. Verify public PrekeyBundle domain object cannot contain private material
    PrekeyBundle pub_bundle(id_pub, spk_pub, sig);
    pub_bundle.add_one_time_prekey(OneTimePrekeyRecord("1", std::vector<uint8_t>(32, 0x77)));

    // Ensure public bundle only exposes public keys and record metadata
    EXPECT_EQ(pub_bundle.identity_key().size(), 32u);
    EXPECT_EQ(pub_bundle.signed_prekey().size(), 32u);
    EXPECT_EQ(pub_bundle.signed_prekey_signature().size(), 64u);
    EXPECT_EQ(pub_bundle.one_time_prekeys().size(), 1u);
    EXPECT_EQ(pub_bundle.one_time_prekeys()[0].public_key().size(), 32u);
}

} // namespace
