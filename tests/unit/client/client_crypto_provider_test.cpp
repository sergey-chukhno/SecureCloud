#include "application/interfaces/i_crypto_provider.hpp"
#include "domain/prekey_policy.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"

#include <gtest/gtest.h>
#include <set>

namespace {

using namespace securecloud::client;
using namespace securecloud::client::domain;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::infrastructure::adapters;

TEST(OpenSslCryptoProviderTest, IdentityKeyPairGeneration) {
    OpenSslCryptoProvider crypto;

    auto res1 = crypto.generate_identity_keypair();
    ASSERT_TRUE(res1.is_ok());
    const auto& pair1 = res1.value();

    EXPECT_EQ(pair1.public_key.size(), PrekeyPolicy::kEd25519PublicKeySize);
    EXPECT_EQ(pair1.private_key.size(), PrekeyPolicy::kEd25519PrivateKeySize);
    EXPECT_FALSE(pair1.private_key.empty());

    // Generate second keypair and assert uniqueness
    auto res2 = crypto.generate_identity_keypair();
    ASSERT_TRUE(res2.is_ok());
    const auto& pair2 = res2.value();

    EXPECT_NE(pair1.public_key, pair2.public_key);
    EXPECT_NE(pair1.private_key.expose_unredacted_secret(), pair2.private_key.expose_unredacted_secret());
}

TEST(OpenSslCryptoProviderTest, SignedPrekeyGenerationAndVerification) {
    OpenSslCryptoProvider crypto;

    // 1. Generate identity
    auto id_res = crypto.generate_identity_keypair();
    ASSERT_TRUE(id_res.is_ok());
    const auto& id_pair = id_res.value();

    // 2. Generate signed prekey
    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key);
    ASSERT_TRUE(spk_res.is_ok());
    const auto& spk = spk_res.value();

    EXPECT_EQ(spk.public_key.size(), PrekeyPolicy::kX25519PublicKeySize);
    EXPECT_EQ(spk.private_key.size(), PrekeyPolicy::kX25519PrivateKeySize);
    EXPECT_EQ(spk.signature.size(), PrekeyPolicy::kEd25519SignatureSize);

    // 3. Verify valid signature
    auto verify_res = crypto.verify_signed_prekey(id_pair.public_key, spk.public_key, spk.signature);
    ASSERT_TRUE(verify_res.is_ok());
    EXPECT_TRUE(verify_res.value());

    // 4. Verification fails on corrupted prekey
    auto corrupted_spk_key = spk.public_key;
    corrupted_spk_key[0] ^= 0xFF;
    auto verify_corrupted_key = crypto.verify_signed_prekey(id_pair.public_key, corrupted_spk_key, spk.signature);
    ASSERT_TRUE(verify_corrupted_key.is_ok());
    EXPECT_FALSE(verify_corrupted_key.value());

    // 5. Verification fails on corrupted signature
    auto corrupted_sig = spk.signature;
    corrupted_sig[0] ^= 0x01;
    auto verify_corrupted_sig = crypto.verify_signed_prekey(id_pair.public_key, spk.public_key, corrupted_sig);
    ASSERT_TRUE(verify_corrupted_sig.is_ok());
    EXPECT_FALSE(verify_corrupted_sig.value());

    // 6. Verification fails on wrong identity key
    auto another_id_res = crypto.generate_identity_keypair();
    ASSERT_TRUE(another_id_res.is_ok());
    auto verify_wrong_id =
        crypto.verify_signed_prekey(another_id_res.value().public_key, spk.public_key, spk.signature);
    ASSERT_TRUE(verify_wrong_id.is_ok());
    EXPECT_FALSE(verify_wrong_id.value());

    // 7. Verification fails on invalid buffer sizes
    EXPECT_FALSE(crypto.verify_signed_prekey(std::vector<uint8_t>(31, 0), spk.public_key, spk.signature).value());
    EXPECT_FALSE(crypto.verify_signed_prekey(id_pair.public_key, std::vector<uint8_t>(33, 0), spk.signature).value());
    EXPECT_FALSE(crypto.verify_signed_prekey(id_pair.public_key, spk.public_key, std::vector<uint8_t>(63, 0)).value());

    // 8. Invalid private key rejected on generation
    securecloud::common::configuration::SecretString bad_priv("short");
    auto bad_spk_res = crypto.generate_signed_prekey(bad_priv);
    EXPECT_TRUE(bad_spk_res.is_error());
}

TEST(OpenSslCryptoProviderTest, OneTimePrekeysBatchGeneration) {
    OpenSslCryptoProvider crypto;

    constexpr std::size_t kBatchCount = 100;
    auto otpk_res = crypto.generate_one_time_prekeys(kBatchCount, 1);
    ASSERT_TRUE(otpk_res.is_ok());
    const auto& otpks = otpk_res.value();

    EXPECT_EQ(otpks.size(), kBatchCount);

    std::set<std::vector<uint8_t>> unique_pubs;
    std::set<std::string> unique_privs;

    for (std::size_t i = 0; i < kBatchCount; ++i) {
        const auto& pair = otpks[i];
        EXPECT_EQ(pair.record.id(), std::to_string(i + 1));
        EXPECT_EQ(pair.record.public_key().size(), PrekeyPolicy::kX25519PublicKeySize);
        EXPECT_EQ(pair.private_key.size(), PrekeyPolicy::kX25519PrivateKeySize);

        unique_pubs.insert(pair.record.public_key());
        unique_privs.insert(pair.private_key.expose_unredacted_secret());
    }

    // All keys must be unique
    EXPECT_EQ(unique_pubs.size(), kBatchCount);
    EXPECT_EQ(unique_privs.size(), kBatchCount);
}

TEST(OpenSslCryptoProviderTest, IdentityFingerprintComputation) {
    OpenSslCryptoProvider crypto;

    auto id_res = crypto.generate_identity_keypair();
    ASSERT_TRUE(id_res.is_ok());
    const auto& id_pair = id_res.value();

    auto fp_res = crypto.compute_identity_fingerprint(id_pair.public_key);
    ASSERT_TRUE(fp_res.is_ok());
    const auto& fp = fp_res.value();

    // Verify uppercase colon-separated format
    EXPECT_TRUE(CryptoIdentity::is_valid_fingerprint(fp));
    EXPECT_EQ(fp.size(), 102u);
    EXPECT_TRUE(fp.starts_with("SHA256:"));

    // Deterministic check: same key produces identical fingerprint
    auto fp2_res = crypto.compute_identity_fingerprint(id_pair.public_key);
    ASSERT_TRUE(fp2_res.is_ok());
    EXPECT_EQ(fp, fp2_res.value());

    // Different keys produce different fingerprints
    auto id2_res = crypto.generate_identity_keypair();
    ASSERT_TRUE(id2_res.is_ok());
    auto fp_diff = crypto.compute_identity_fingerprint(id2_res.value().public_key);
    ASSERT_TRUE(fp_diff.is_ok());
    EXPECT_NE(fp, fp_diff.value());

    // Empty key rejected
    auto err_res = crypto.compute_identity_fingerprint({});
    EXPECT_TRUE(err_res.is_error());
}

TEST(OpenSslCryptoProviderTest, GenerateDeviceIdentityAndMessaging) {
    OpenSslCryptoProvider crypto;

    auto dev_res = crypto.generate_device_identity();
    ASSERT_TRUE(dev_res.is_ok());
    const auto& identity = dev_res.value();

    EXPECT_FALSE(identity.identity_key().empty());
    EXPECT_FALSE(identity.fingerprint().empty());
    EXPECT_TRUE(CryptoIdentity::is_valid_fingerprint(identity.fingerprint()));
    EXPECT_EQ(identity.verification_status(), KeyVerificationStatus::Verified);
    EXPECT_FALSE(identity.signed_prekey().empty());
    EXPECT_FALSE(identity.signature().empty());

    // Verify the generated signed prekey validates under the generated identity
    auto verify_res = crypto.verify_signed_prekey(identity.identity_key_bytes(), identity.signed_prekey_bytes(),
                                                  identity.signature_bytes());
    ASSERT_TRUE(verify_res.is_ok());
    EXPECT_TRUE(verify_res.value());

    // Message encryption and decryption
    const DeviceId did("device-recip-1");
    auto enc_res = crypto.encrypt_message(did, "hello securecloud");
    ASSERT_TRUE(enc_res.is_ok());
    EXPECT_FALSE(enc_res.value().empty());

    auto dec_res = crypto.decrypt_message(did, enc_res.value());
    ASSERT_TRUE(dec_res.is_ok());
    EXPECT_EQ(dec_res.value(), "hello securecloud");

    // Fingerprint verification helper
    EXPECT_TRUE(crypto.verify_identity_fingerprint(did, identity.fingerprint()).value());
    EXPECT_FALSE(crypto.verify_identity_fingerprint(did, "invalid-fp").value());
    const DeviceId empty_did;
    EXPECT_FALSE(crypto.verify_identity_fingerprint(empty_did, identity.fingerprint()).value());
}

TEST(StubCryptoProviderTest, InterfaceComplianceAndFallbacks) {
    StubCryptoProvider stub;

    auto id_res = stub.generate_identity_keypair();
    ASSERT_TRUE(id_res.is_ok());
    EXPECT_EQ(id_res.value().public_key.size(), PrekeyPolicy::kEd25519PublicKeySize);

    auto spk_res = stub.generate_signed_prekey(id_res.value().private_key);
    ASSERT_TRUE(spk_res.is_ok());
    EXPECT_EQ(spk_res.value().public_key.size(), PrekeyPolicy::kX25519PublicKeySize);
    EXPECT_EQ(spk_res.value().signature.size(), PrekeyPolicy::kEd25519SignatureSize);

    auto otpk_res = stub.generate_one_time_prekeys(10, 1);
    ASSERT_TRUE(otpk_res.is_ok());
    EXPECT_EQ(otpk_res.value().size(), 10u);

    auto fp_res = stub.compute_identity_fingerprint(id_res.value().public_key);
    ASSERT_TRUE(fp_res.is_ok());
    EXPECT_TRUE(CryptoIdentity::is_valid_fingerprint(fp_res.value()));
}

} // namespace
