#include "domain/crypto/double_ratchet_engine.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/prekey_policy.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"

#include <gtest/gtest.h>
#include <string>

namespace {

using namespace securecloud::client;
using namespace securecloud::client::domain;
using namespace securecloud::client::domain::crypto;
using namespace securecloud::client::infrastructure::adapters;
using namespace securecloud::client::application::interfaces;

TEST(RatchetModelsTest, HeaderAndMessageSerializationRoundtrip) {
    std::vector<uint8_t> dh_pub(PrekeyPolicy::kX25519PublicKeySize, 0x42);
    RatchetHeader header(dh_pub, 7, 13);

    auto header_bytes = header.serialize();
    EXPECT_EQ(header_bytes.size(), RatchetHeader::kSerializedSize);

    auto des_header_res = RatchetHeader::deserialize(header_bytes);
    ASSERT_TRUE(des_header_res.is_ok());
    const auto& restored_header = des_header_res.value();

    EXPECT_EQ(header, restored_header);
    EXPECT_EQ(restored_header.dh_pub(), dh_pub);
    EXPECT_EQ(restored_header.pn(), 7u);
    EXPECT_EQ(restored_header.n(), 13u);

    // Full Message roundtrip
    std::vector<uint8_t> ct = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    std::vector<uint8_t> iv(PrekeyPolicy::kAeadGcmIvSize, 0x11);
    std::vector<uint8_t> tag(PrekeyPolicy::kAeadGcmTagSize, 0x22);

    DoubleRatchetMessage msg{
        .header = header,
        .ciphertext = ct,
        .iv = iv,
        .auth_tag = tag,
    };

    auto msg_bytes = msg.serialize();
    EXPECT_FALSE(msg_bytes.empty());

    auto des_msg_res = DoubleRatchetMessage::deserialize(msg_bytes);
    ASSERT_TRUE(des_msg_res.is_ok());
    EXPECT_EQ(msg, des_msg_res.value());

    // Bad magic / truncated rejected
    EXPECT_TRUE(RatchetHeader::deserialize({}).is_error());
    std::vector<uint8_t> bad_magic = header_bytes;
    bad_magic[0] = 0x00;
    EXPECT_TRUE(RatchetHeader::deserialize(bad_magic).is_error());

    EXPECT_TRUE(DoubleRatchetMessage::deserialize({}).is_error());
}

TEST(DoubleRatchetEngineTest, AliceBobBasicExchange) {
    OpenSslCryptoProvider crypto;

    std::string sk_raw(PrekeyPolicy::kSharedSecretSize, 0x5A);
    securecloud::common::configuration::SecretString shared_secret(std::move(sk_raw));

    auto bob_dh_res = crypto.generate_dh_keypair();
    ASSERT_TRUE(bob_dh_res.is_ok());
    auto bob_dh = std::move(bob_dh_res).value();
    const auto bob_dh_pub = bob_dh.public_key;

    // 1. Initialize sessions
    auto alice_init = DoubleRatchetEngine::initialize_alice(crypto, shared_secret, bob_dh_pub);
    ASSERT_TRUE(alice_init.is_ok());
    auto alice_state = std::move(alice_init).value();

    auto bob_init = DoubleRatchetEngine::initialize_bob(crypto, shared_secret, std::move(bob_dh));
    ASSERT_TRUE(bob_init.is_ok());
    auto bob_state = std::move(bob_init).value();

    // 2. Alice sends message to Bob
    const std::string m1 = "Hello Bob! This is message 1.";
    std::span<const uint8_t> m1_span(reinterpret_cast<const uint8_t*>(m1.data()), m1.size());

    auto enc_res1 = DoubleRatchetEngine::ratchet_encrypt(crypto, alice_state, m1_span);
    ASSERT_TRUE(enc_res1.is_ok());
    const auto& msg1 = enc_res1.value();

    EXPECT_EQ(msg1.header.n(), 0u);
    EXPECT_EQ(msg1.header.pn(), 0u);

    // Bob decrypts
    auto dec_res1 = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, msg1);
    ASSERT_TRUE(dec_res1.is_ok());
    EXPECT_EQ(dec_res1.value().expose_unredacted_secret(), m1);

    // 3. Bob replies to Alice
    const std::string m2 = "Hi Alice! Received loud and clear.";
    std::span<const uint8_t> m2_span(reinterpret_cast<const uint8_t*>(m2.data()), m2.size());

    auto enc_res2 = DoubleRatchetEngine::ratchet_encrypt(crypto, bob_state, m2_span);
    ASSERT_TRUE(enc_res2.is_ok());
    const auto& msg2 = enc_res2.value();

    EXPECT_EQ(msg2.header.n(), 0u);

    // Alice decrypts
    auto dec_res2 = DoubleRatchetEngine::ratchet_decrypt(crypto, alice_state, msg2);
    ASSERT_TRUE(dec_res2.is_ok());
    EXPECT_EQ(dec_res2.value().expose_unredacted_secret(), m2);
}

TEST(DoubleRatchetEngineTest, MultiMessagePingPongInterleaving) {
    OpenSslCryptoProvider crypto;

    std::string sk_raw(PrekeyPolicy::kSharedSecretSize, 0x33);
    securecloud::common::configuration::SecretString shared_secret(std::move(sk_raw));

    auto bob_dh_res = crypto.generate_dh_keypair();
    ASSERT_TRUE(bob_dh_res.is_ok());
    auto bob_dh = std::move(bob_dh_res).value();
    const auto bob_dh_pub = bob_dh.public_key;

    auto alice_state = DoubleRatchetEngine::initialize_alice(crypto, shared_secret, bob_dh_pub).value();
    auto bob_state = DoubleRatchetEngine::initialize_bob(crypto, shared_secret, std::move(bob_dh)).value();

    for (int turn = 0; turn < 10; ++turn) {
        // Alice -> Bob
        const std::string a_msg = "Alice ping turn #" + std::to_string(turn);
        std::span<const uint8_t> a_span(reinterpret_cast<const uint8_t*>(a_msg.data()), a_msg.size());
        auto a_enc = DoubleRatchetEngine::ratchet_encrypt(crypto, alice_state, a_span).value();
        auto b_dec = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, a_enc).value();
        EXPECT_EQ(b_dec.expose_unredacted_secret(), a_msg);

        // Bob -> Alice
        const std::string b_msg = "Bob pong turn #" + std::to_string(turn);
        std::span<const uint8_t> b_span(reinterpret_cast<const uint8_t*>(b_msg.data()), b_msg.size());
        auto b_enc = DoubleRatchetEngine::ratchet_encrypt(crypto, bob_state, b_span).value();
        auto a_dec = DoubleRatchetEngine::ratchet_decrypt(crypto, alice_state, b_enc).value();
        EXPECT_EQ(a_dec.expose_unredacted_secret(), b_msg);
    }
}

TEST(DoubleRatchetEngineTest, ConsecutiveBurstMessages) {
    OpenSslCryptoProvider crypto;

    std::string sk_raw(PrekeyPolicy::kSharedSecretSize, 0x77);
    securecloud::common::configuration::SecretString shared_secret(std::move(sk_raw));

    auto bob_dh = crypto.generate_dh_keypair().value();
    const auto bob_dh_pub = bob_dh.public_key;

    auto alice_state = DoubleRatchetEngine::initialize_alice(crypto, shared_secret, bob_dh_pub).value();
    auto bob_state = DoubleRatchetEngine::initialize_bob(crypto, shared_secret, std::move(bob_dh)).value();

    // Alice sends burst of 5 messages
    std::vector<DoubleRatchetMessage> burst;
    for (int i = 0; i < 5; ++i) {
        const std::string text = "Burst msg #" + std::to_string(i);
        std::span<const uint8_t> span(reinterpret_cast<const uint8_t*>(text.data()), text.size());
        auto enc = DoubleRatchetEngine::ratchet_encrypt(crypto, alice_state, span).value();
        EXPECT_EQ(enc.header.n(), static_cast<uint32_t>(i));
        burst.push_back(std::move(enc));
    }

    // Bob decrypts all 5 in sequence
    for (int i = 0; i < 5; ++i) {
        auto dec = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, burst[static_cast<std::size_t>(i)]).value();
        EXPECT_EQ(dec.expose_unredacted_secret(), "Burst msg #" + std::to_string(i));
    }

    // Bob replies with 3 messages
    for (int i = 0; i < 3; ++i) {
        const std::string text = "Reply msg #" + std::to_string(i);
        std::span<const uint8_t> span(reinterpret_cast<const uint8_t*>(text.data()), text.size());
        auto enc = DoubleRatchetEngine::ratchet_encrypt(crypto, bob_state, span).value();
        EXPECT_EQ(enc.header.pn(), 0u);
        EXPECT_EQ(enc.header.n(), static_cast<uint32_t>(i));

        auto dec = DoubleRatchetEngine::ratchet_decrypt(crypto, alice_state, enc).value();
        EXPECT_EQ(dec.expose_unredacted_secret(), text);
    }
}

TEST(DoubleRatchetEngineTest, TamperedCiphertextAndHeaderRejection) {
    OpenSslCryptoProvider crypto;

    std::string sk_raw(PrekeyPolicy::kSharedSecretSize, 0x88);
    securecloud::common::configuration::SecretString shared_secret(std::move(sk_raw));

    auto bob_dh = crypto.generate_dh_keypair().value();
    const auto bob_dh_pub = bob_dh.public_key;

    auto alice_state = DoubleRatchetEngine::initialize_alice(crypto, shared_secret, bob_dh_pub).value();
    auto bob_state = DoubleRatchetEngine::initialize_bob(crypto, shared_secret, std::move(bob_dh)).value();

    const std::string plaintext = "Authenticity and Integrity Test Payload";
    std::span<const uint8_t> span(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    auto msg = DoubleRatchetEngine::ratchet_encrypt(crypto, alice_state, span).value();

    // 1. Tampered ciphertext rejected
    auto bad_ct_msg = msg;
    bad_ct_msg.ciphertext[0] ^= 0x01;
    EXPECT_TRUE(DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, bad_ct_msg).is_error());

    // 2. Tampered auth tag rejected
    auto bad_tag_msg = msg;
    bad_tag_msg.auth_tag[0] ^= 0x01;
    EXPECT_TRUE(DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, bad_tag_msg).is_error());

    // 3. Tampered IV rejected
    auto bad_iv_msg = msg;
    bad_iv_msg.iv[0] ^= 0x01;
    EXPECT_TRUE(DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, bad_iv_msg).is_error());

    // 4. Tampered Header rejected (AAD authentication check)
    auto bad_header_msg = msg;
    bad_header_msg.header = RatchetHeader(msg.header.dh_pub(), msg.header.pn(), msg.header.n() + 1);
    EXPECT_TRUE(DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, bad_header_msg).is_error());
}

TEST(DoubleRatchetEngineTest, StubCryptoProviderParity) {
    StubCryptoProvider stub;

    std::string sk_raw(PrekeyPolicy::kSharedSecretSize, 0x12);
    securecloud::common::configuration::SecretString shared_secret(std::move(sk_raw));

    auto bob_dh = stub.generate_dh_keypair().value();
    const auto bob_dh_pub = bob_dh.public_key;

    auto alice_state = DoubleRatchetEngine::initialize_alice(stub, shared_secret, bob_dh_pub).value();
    auto bob_state = DoubleRatchetEngine::initialize_bob(stub, shared_secret, std::move(bob_dh)).value();

    const std::string msg = "Stub Double Ratchet Test";
    std::span<const uint8_t> span(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    auto enc = DoubleRatchetEngine::ratchet_encrypt(stub, alice_state, span).value();
    auto dec = DoubleRatchetEngine::ratchet_decrypt(stub, bob_state, enc).value();
    EXPECT_EQ(dec.expose_unredacted_secret(), msg);
}

} // namespace
