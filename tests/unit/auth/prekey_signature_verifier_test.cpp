#include "auth/crypto/prekey_signature_verifier.hpp"

#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <vector>

namespace securecloud::auth::crypto::test {
namespace {

struct TestCryptoMaterial {
    std::vector<uint8_t> identity_public_key;
    std::vector<uint8_t> signed_prekey;
    std::vector<uint8_t> signature;
};

TestCryptoMaterial generate_valid_signed_prekey_bundle() {
    TestCryptoMaterial mat;

    // 1. Generate Ed25519 identity keypair
    EVP_PKEY_CTX* ed_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY_keygen_init(ed_ctx);
    EVP_PKEY* ed_pkey = nullptr;
    EVP_PKEY_keygen(ed_ctx, &ed_pkey);
    EVP_PKEY_CTX_free(ed_ctx);

    // Extract raw public key
    mat.identity_public_key.resize(32);
    std::size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(ed_pkey, mat.identity_public_key.data(), &pub_len);

    // 2. Generate X25519 signed prekey keypair
    EVP_PKEY_CTX* x_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY_keygen_init(x_ctx);
    EVP_PKEY* x_pkey = nullptr;
    EVP_PKEY_keygen(x_ctx, &x_pkey);
    EVP_PKEY_CTX_free(x_ctx);

    // Extract raw public key
    mat.signed_prekey.resize(32);
    std::size_t x_pub_len = 32;
    EVP_PKEY_get_raw_public_key(x_pkey, mat.signed_prekey.data(), &x_pub_len);
    EVP_PKEY_free(x_pkey);

    // 3. Sign the X25519 signed prekey with the Ed25519 identity key
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, ed_pkey);
    mat.signature.resize(64);
    std::size_t sig_len = 64;
    EVP_DigestSign(md_ctx, mat.signature.data(), &sig_len, mat.signed_prekey.data(), mat.signed_prekey.size());
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(ed_pkey);

    return mat;
}

TEST(PrekeySignatureVerifierTest, ValidSignaturePasses) {
    auto mat = generate_valid_signed_prekey_bundle();
    std::string error;
    bool ok = PrekeySignatureVerifier::verify(mat.identity_public_key, mat.signed_prekey, mat.signature, &error);
    EXPECT_TRUE(ok);
    EXPECT_TRUE(error.empty());
}

TEST(PrekeySignatureVerifierTest, TamperedSignatureRejected) {
    auto mat = generate_valid_signed_prekey_bundle();
    mat.signature[10] ^= 0x55; // Flip bits in signature

    std::string error;
    bool ok = PrekeySignatureVerifier::verify(mat.identity_public_key, mat.signed_prekey, mat.signature, &error);
    EXPECT_FALSE(ok);
    EXPECT_FALSE(error.empty());
}

TEST(PrekeySignatureVerifierTest, TamperedPrekeyRejected) {
    auto mat = generate_valid_signed_prekey_bundle();
    mat.signed_prekey[5] ^= 0xAA; // Flip bits in prekey payload

    std::string error;
    bool ok = PrekeySignatureVerifier::verify(mat.identity_public_key, mat.signed_prekey, mat.signature, &error);
    EXPECT_FALSE(ok);
    EXPECT_FALSE(error.empty());
}

TEST(PrekeySignatureVerifierTest, MismatchedIdentityKeyRejected) {
    auto mat1 = generate_valid_signed_prekey_bundle();
    auto mat2 = generate_valid_signed_prekey_bundle();

    // Verify bundle 1's signature against bundle 2's identity key
    std::string error;
    bool ok = PrekeySignatureVerifier::verify(mat2.identity_public_key, mat1.signed_prekey, mat1.signature, &error);
    EXPECT_FALSE(ok);
    EXPECT_FALSE(error.empty());
}

TEST(PrekeySignatureVerifierTest, InvalidLengthsRejected) {
    auto mat = generate_valid_signed_prekey_bundle();

    // Invalid signature length
    std::vector<uint8_t> short_sig(63, 0x01);
    std::string error;
    EXPECT_FALSE(PrekeySignatureVerifier::verify(mat.identity_public_key, mat.signed_prekey, short_sig, &error));

    // Invalid identity key length
    std::vector<uint8_t> short_id(31, 0x01);
    EXPECT_FALSE(PrekeySignatureVerifier::verify(short_id, mat.signed_prekey, mat.signature, &error));

    // Invalid signed prekey length
    std::vector<uint8_t> short_spk(31, 0x01);
    EXPECT_FALSE(PrekeySignatureVerifier::verify(mat.identity_public_key, short_spk, mat.signature, &error));
}

TEST(PrekeySignatureVerifierTest, ZeroKeyMaterialRejected) {
    std::vector<uint8_t> all_zeros(32, 0x00);
    std::vector<uint8_t> sig(64, 0x01);

    std::string error;
    EXPECT_FALSE(PrekeySignatureVerifier::verify(all_zeros, all_zeros, sig, &error));
}

} // namespace
} // namespace securecloud::auth::crypto::test
