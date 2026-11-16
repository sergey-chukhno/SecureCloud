#include "application/interfaces/i_crypto_provider.hpp"
#include "domain/prekey_policy.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"

#include <gtest/gtest.h>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace securecloud::client;
using namespace securecloud::client::domain;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::infrastructure::adapters;

std::vector<uint8_t> hex_to_bytes(std::string_view hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        auto byte = static_cast<uint8_t>(std::stoi(std::string(hex.substr(i, 2)), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytes_to_hex(std::span<const uint8_t> bytes) {
    constexpr char hex_chars[] = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        s.push_back(hex_chars[(b >> 4) & 0x0f]);
        s.push_back(hex_chars[b & 0x0f]);
    }
    return s;
}

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

TEST(OpenSslCryptoProviderTest, DhKeyPairGeneration) {
    OpenSslCryptoProvider crypto;

    auto res1 = crypto.generate_dh_keypair();
    ASSERT_TRUE(res1.is_ok());
    const auto& pair1 = res1.value();

    EXPECT_EQ(pair1.public_key.size(), PrekeyPolicy::kX25519PublicKeySize);
    EXPECT_EQ(pair1.private_key.size(), PrekeyPolicy::kX25519PrivateKeySize);
    EXPECT_FALSE(pair1.private_key.empty());

    auto res2 = crypto.generate_dh_keypair();
    ASSERT_TRUE(res2.is_ok());
    const auto& pair2 = res2.value();

    EXPECT_NE(pair1.public_key, pair2.public_key);
    EXPECT_NE(pair1.private_key.expose_unredacted_secret(), pair2.private_key.expose_unredacted_secret());
}

TEST(OpenSslCryptoProviderTest, DiffieHellmanParityAndValidation) {
    OpenSslCryptoProvider crypto;

    // Alice generates keypair
    auto alice_res = crypto.generate_dh_keypair();
    ASSERT_TRUE(alice_res.is_ok());
    const auto& alice = alice_res.value();

    // Bob generates keypair
    auto bob_res = crypto.generate_dh_keypair();
    ASSERT_TRUE(bob_res.is_ok());
    const auto& bob = bob_res.value();

    // Alice computes shared secret using Bob's public key
    auto s_alice_res = crypto.diffie_hellman(alice.private_key, bob.public_key);
    ASSERT_TRUE(s_alice_res.is_ok());
    const auto& s_alice = s_alice_res.value();
    EXPECT_EQ(s_alice.size(), PrekeyPolicy::kSharedSecretSize);

    // Bob computes shared secret using Alice's public key
    auto s_bob_res = crypto.diffie_hellman(bob.private_key, alice.public_key);
    ASSERT_TRUE(s_bob_res.is_ok());
    const auto& s_bob = s_bob_res.value();
    EXPECT_EQ(s_bob.size(), PrekeyPolicy::kSharedSecretSize);

    // Assert parity
    EXPECT_EQ(s_alice.expose_unredacted_secret(), s_bob.expose_unredacted_secret());

    // Bad key sizes rejected
    securecloud::common::configuration::SecretString short_priv("too-short");
    EXPECT_TRUE(crypto.diffie_hellman(short_priv, bob.public_key).is_error());

    std::vector<uint8_t> short_pub(31, 0x01);
    EXPECT_TRUE(crypto.diffie_hellman(alice.private_key, short_pub).is_error());
}

TEST(OpenSslCryptoProviderTest, Rfc7748DiffieHellmanVector) {
    OpenSslCryptoProvider crypto;

    // RFC 7748 Section 6.1 (Curve25519)
    auto alice_priv_bytes = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    auto bob_pub_bytes = hex_to_bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const std::string expected_secret_hex = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    std::string priv_str(reinterpret_cast<const char*>(alice_priv_bytes.data()), alice_priv_bytes.size());
    securecloud::common::configuration::SecretString alice_priv(std::move(priv_str));

    auto dh_res = crypto.diffie_hellman(alice_priv, bob_pub_bytes);
    ASSERT_TRUE(dh_res.is_ok());

    const auto& secret = dh_res.value().expose_unredacted_secret();
    std::span<const uint8_t> secret_span(reinterpret_cast<const uint8_t*>(secret.data()), secret.size());
    EXPECT_EQ(bytes_to_hex(secret_span), expected_secret_hex);
}

TEST(OpenSslCryptoProviderTest, Rfc5869HkdfVectors) {
    OpenSslCryptoProvider crypto;

    // RFC 5869 Test Case 1 with SHA-256
    std::vector<uint8_t> ikm_bytes(22, 0x0b);
    std::string ikm_str(reinterpret_cast<const char*>(ikm_bytes.data()), ikm_bytes.size());
    securecloud::common::configuration::SecretString ikm(std::move(ikm_str));

    auto salt_bytes = hex_to_bytes("000102030405060708090a0b0c");
    auto info_bytes = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
    const std::string expected_prk_hex = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
    const std::string expected_okm_hex =
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

    // 1. Test hkdf_extract
    auto prk_res = crypto.hkdf_extract(salt_bytes, ikm);
    ASSERT_TRUE(prk_res.is_ok());
    const auto& prk_str = prk_res.value().expose_unredacted_secret();
    std::span<const uint8_t> prk_span(reinterpret_cast<const uint8_t*>(prk_str.data()), prk_str.size());
    EXPECT_EQ(bytes_to_hex(prk_span), expected_prk_hex);

    // 2. Test hkdf_expand
    auto okm_res = crypto.hkdf_expand(prk_res.value(), info_bytes, 42);
    ASSERT_TRUE(okm_res.is_ok());
    const auto& okm_str = okm_res.value().expose_unredacted_secret();
    std::span<const uint8_t> okm_span(reinterpret_cast<const uint8_t*>(okm_str.data()), okm_str.size());
    EXPECT_EQ(bytes_to_hex(okm_span), expected_okm_hex);

    // 3. Test combined hkdf_extract_and_expand
    auto combined_res = crypto.hkdf_extract_and_expand(salt_bytes, ikm, info_bytes, 42);
    ASSERT_TRUE(combined_res.is_ok());
    const auto& comb_str = combined_res.value().expose_unredacted_secret();
    std::span<const uint8_t> comb_span(reinterpret_cast<const uint8_t*>(comb_str.data()), comb_str.size());
    EXPECT_EQ(bytes_to_hex(comb_span), expected_okm_hex);
}

TEST(OpenSslCryptoProviderTest, Aes256GcmEncryptionDecryptionRoundtrip) {
    OpenSslCryptoProvider crypto;

    std::vector<uint8_t> key_bytes(32, 0x42);
    std::string key_str(reinterpret_cast<const char*>(key_bytes.data()), key_bytes.size());
    securecloud::common::configuration::SecretString key(std::move(key_str));

    std::vector<uint8_t> iv(12, 0x99);
    const std::string plaintext_str = "Signal Double Ratchet Payload with Forward Secrecy";
    std::span<const uint8_t> plaintext(reinterpret_cast<const uint8_t*>(plaintext_str.data()), plaintext_str.size());
    const std::string aad_str = "Header:Seq=1,Prev=0";
    std::span<const uint8_t> aad(reinterpret_cast<const uint8_t*>(aad_str.data()), aad_str.size());

    // 1. Valid encryption
    auto enc_res = crypto.encrypt_aes_gcm(key, iv, plaintext, aad);
    ASSERT_TRUE(enc_res.is_ok());
    const auto& ct = enc_res.value();

    EXPECT_EQ(ct.ciphertext.size(), plaintext.size());
    EXPECT_EQ(ct.iv, iv);
    EXPECT_EQ(ct.auth_tag.size(), PrekeyPolicy::kAeadGcmTagSize);
    EXPECT_NE(std::string(reinterpret_cast<const char*>(ct.ciphertext.data()), ct.ciphertext.size()), plaintext_str);

    // 2. Valid decryption
    auto dec_res = crypto.decrypt_aes_gcm(key, ct.iv, ct.ciphertext, ct.auth_tag, aad);
    ASSERT_TRUE(dec_res.is_ok());
    EXPECT_EQ(dec_res.value().expose_unredacted_secret(), plaintext_str);

    // 3. Tampered ciphertext rejected
    auto corrupted_ct = ct.ciphertext;
    corrupted_ct[0] ^= 0x01;
    EXPECT_TRUE(crypto.decrypt_aes_gcm(key, ct.iv, corrupted_ct, ct.auth_tag, aad).is_error());

    // 4. Tampered auth tag rejected
    auto corrupted_tag = ct.auth_tag;
    corrupted_tag[0] ^= 0x01;
    EXPECT_TRUE(crypto.decrypt_aes_gcm(key, ct.iv, ct.ciphertext, corrupted_tag, aad).is_error());

    // 5. Tampered AAD rejected
    const std::string bad_aad_str = "Header:Seq=2,Prev=0";
    std::span<const uint8_t> bad_aad(reinterpret_cast<const uint8_t*>(bad_aad_str.data()), bad_aad_str.size());
    EXPECT_TRUE(crypto.decrypt_aes_gcm(key, ct.iv, ct.ciphertext, ct.auth_tag, bad_aad).is_error());

    // 6. Empty plaintext roundtrip works
    auto empty_enc = crypto.encrypt_aes_gcm(key, iv, {}, aad);
    ASSERT_TRUE(empty_enc.is_ok());
    auto empty_dec = crypto.decrypt_aes_gcm(key, iv, empty_enc.value().ciphertext, empty_enc.value().auth_tag, aad);
    ASSERT_TRUE(empty_dec.is_ok());
    EXPECT_TRUE(empty_dec.value().empty());

    // 7. Invalid parameters rejected
    securecloud::common::configuration::SecretString bad_key("short-key");
    EXPECT_TRUE(crypto.encrypt_aes_gcm(bad_key, iv, plaintext, aad).is_error());

    std::vector<uint8_t> bad_iv(11, 0x01);
    EXPECT_TRUE(crypto.encrypt_aes_gcm(key, bad_iv, plaintext, aad).is_error());
}

TEST(OpenSslCryptoProviderTest, MutualSafetyNumberComputation) {
    OpenSslCryptoProvider crypto;

    UserId user_alice("550e8400-e29b-41d4-a716-446655440000");
    UserId user_bob("6ba7b810-9dad-11d1-80b4-00c04fd430c8");

    auto alice_id = crypto.generate_identity_keypair();
    ASSERT_TRUE(alice_id.is_ok());

    auto bob_id = crypto.generate_identity_keypair();
    ASSERT_TRUE(bob_id.is_ok());

    // Alice calculates safety number with Bob
    auto sn_alice_res =
        crypto.compute_safety_number(user_alice, alice_id.value().public_key, user_bob, bob_id.value().public_key);
    ASSERT_TRUE(sn_alice_res.is_ok());
    const auto& sn_alice = sn_alice_res.value();

    // Bob calculates safety number with Alice
    auto sn_bob_res =
        crypto.compute_safety_number(user_bob, bob_id.value().public_key, user_alice, alice_id.value().public_key);
    ASSERT_TRUE(sn_bob_res.is_ok());
    const auto& sn_bob = sn_bob_res.value();

    // Mutual symmetry invariant: SN(Alice, Bob) == SN(Bob, Alice)
    EXPECT_EQ(sn_alice, sn_bob);

    // Format verification: 12 groups of 5 digits separated by spaces (71 characters)
    EXPECT_EQ(sn_alice.size(), 71u);
    for (std::size_t i = 0; i < sn_alice.size(); ++i) {
        if ((i + 1) % 6 == 0) {
            EXPECT_EQ(sn_alice[i], ' ');
        } else {
            EXPECT_TRUE(std::isdigit(static_cast<unsigned char>(sn_alice[i])));
        }
    }

    // Different identity produces different safety number
    auto charlie_id = crypto.generate_identity_keypair();
    ASSERT_TRUE(charlie_id.is_ok());
    auto sn_charlie =
        crypto.compute_safety_number(user_alice, alice_id.value().public_key, user_bob, charlie_id.value().public_key);
    ASSERT_TRUE(sn_charlie.is_ok());
    EXPECT_NE(sn_alice, sn_charlie.value());
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

    // Extended primitives compliance
    auto dh_key = stub.generate_dh_keypair();
    ASSERT_TRUE(dh_key.is_ok());
    EXPECT_EQ(dh_key.value().public_key.size(), PrekeyPolicy::kX25519PublicKeySize);

    auto dh_res = stub.diffie_hellman(dh_key.value().private_key, dh_key.value().public_key);
    ASSERT_TRUE(dh_res.is_ok());
    EXPECT_EQ(dh_res.value().size(), PrekeyPolicy::kSharedSecretSize);

    std::vector<uint8_t> salt(16, 0x01);
    auto hkdf_res = stub.hkdf_extract_and_expand(salt, dh_res.value(), {}, 32);
    ASSERT_TRUE(hkdf_res.is_ok());
    EXPECT_EQ(hkdf_res.value().size(), 32u);

    std::vector<uint8_t> iv(12, 0x02);
    std::string pt = "test";
    std::span<const uint8_t> pt_span(reinterpret_cast<const uint8_t*>(pt.data()), pt.size());
    auto enc = stub.encrypt_aes_gcm(hkdf_res.value(), iv, pt_span);
    ASSERT_TRUE(enc.is_ok());
    auto dec = stub.decrypt_aes_gcm(hkdf_res.value(), iv, enc.value().ciphertext, enc.value().auth_tag);
    ASSERT_TRUE(dec.is_ok());
    EXPECT_EQ(dec.value().expose_unredacted_secret(), pt);

    UserId u1("user1");
    UserId u2("user2");
    std::vector<uint8_t> id_bytes(32, 0x11);
    auto sn = stub.compute_safety_number(u1, id_bytes, u2, id_bytes);
    ASSERT_TRUE(sn.is_ok());
    EXPECT_EQ(sn.value().size(), 71u);
}

} // namespace
