#include "application/interfaces/i_crypto_provider.hpp"
#include "domain/crypto/double_ratchet_engine.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/crypto/ratchet_state.hpp"
#include "domain/crypto/skipped_keys_store.hpp"
#include "domain/crypto/x3dh_engine.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::client::domain::crypto {
namespace {

using securecloud::client::infrastructure::adapters::OpenSslCryptoProvider;
using securecloud::client::infrastructure::adapters::StubCryptoProvider;
using securecloud::common::configuration::SecretString;

TEST(SkippedKeysStoreTest, DirectStoreAndExtractSingleKey) {
    SkippedKeysStore store;
    EXPECT_TRUE(store.empty());
    EXPECT_EQ(store.size(), 0u);

    std::vector<uint8_t> dh_pub(32, 0x42);
    SecretString mk("super-secret-message-key-32bytes");

    auto store_res = store.store_key(dh_pub, 5, mk);
    EXPECT_TRUE(store_res.is_ok());
    EXPECT_FALSE(store.empty());
    EXPECT_EQ(store.size(), 1u);
    EXPECT_TRUE(store.has_key(dh_pub, 5));
    EXPECT_FALSE(store.has_key(dh_pub, 6));

    // Extract key
    auto extracted = store.extract_and_remove(dh_pub, 5);
    ASSERT_TRUE(extracted.has_value());
    EXPECT_EQ(extracted->expose_unredacted_secret(), "super-secret-message-key-32bytes");

    // Once extracted, key must be gone
    EXPECT_FALSE(store.has_key(dh_pub, 5));
    EXPECT_EQ(store.size(), 0u);
    EXPECT_TRUE(store.empty());

    // Subsequent extraction returns nullopt
    auto second_extract = store.extract_and_remove(dh_pub, 5);
    EXPECT_FALSE(second_extract.has_value());
}

TEST(SkippedKeysStoreTest, PruneExpiredKeys) {
    SkippedKeysStore store;
    std::vector<uint8_t> dh_pub(32, 0xAA);

    auto now = std::chrono::system_clock::now();
    auto old_time = now - std::chrono::hours(24 * 20); // 20 days old (expired)
    auto recent_time = now - std::chrono::hours(2);    // 2 hours old (valid)

    EXPECT_TRUE(store.store_key(dh_pub, 1, SecretString("key-1"), old_time).is_ok());
    EXPECT_TRUE(store.store_key(dh_pub, 2, SecretString("key-2"), old_time).is_ok());
    EXPECT_TRUE(store.store_key(dh_pub, 3, SecretString("key-3"), recent_time).is_ok());

    EXPECT_EQ(store.size(), 3u);

    // Prune with 14-day TTL
    std::size_t pruned = store.prune_expired(std::chrono::hours(24 * 14), now);
    EXPECT_EQ(pruned, 2u);
    EXPECT_EQ(store.size(), 1u);

    EXPECT_FALSE(store.has_key(dh_pub, 1));
    EXPECT_FALSE(store.has_key(dh_pub, 2));
    EXPECT_TRUE(store.has_key(dh_pub, 3));
}

TEST(SkippedKeysStoreTest, CapacityLimitEnforcement) {
    SkippedKeysStore store;
    std::vector<uint8_t> dh_pub(32, 0xBB);
    auto now = std::chrono::system_clock::now();

    for (std::size_t i = 0; i < SkippedKeysStore::kMaxSkippedKeys; ++i) {
        auto res = store.store_key(dh_pub, static_cast<uint32_t>(i), SecretString("key-" + std::to_string(i)), now);
        ASSERT_TRUE(res.is_ok());
    }

    EXPECT_EQ(store.size(), SkippedKeysStore::kMaxSkippedKeys);

    // Attempt to exceed capacity when none are expired
    auto overflow_res = store.store_key(dh_pub, 9999, SecretString("overflow-key"), now);
    EXPECT_FALSE(overflow_res.is_ok());
    EXPECT_EQ(store.size(), SkippedKeysStore::kMaxSkippedKeys);

    // Duplicate store of existing index is idempotent and does not fail
    auto dup_res = store.store_key(dh_pub, 0, SecretString("key-0"), now);
    EXPECT_TRUE(dup_res.is_ok());

    // Invalid parameters
    EXPECT_FALSE(store.store_key({}, 0, SecretString("key")).is_ok());
    EXPECT_FALSE(store.store_key(dh_pub, 0, SecretString("")).is_ok());

    // Clear wipes all
    store.clear();
    EXPECT_TRUE(store.empty());
    EXPECT_EQ(store.size(), 0u);
}

TEST(DoubleRatchetOutOfOrderTest, SymmetricChainReordering) {
    OpenSslCryptoProvider crypto;
    SecretString shared_secret(std::string(32, 0x5A));

    auto bob_dh_res = crypto.generate_dh_keypair();
    ASSERT_TRUE(bob_dh_res.is_ok());
    auto bob_dh = std::move(bob_dh_res).value();
    std::vector<uint8_t> bob_dh_pub = bob_dh.public_key;

    auto alice_res = DoubleRatchetEngine::initialize_alice(crypto, shared_secret, bob_dh_pub);
    ASSERT_TRUE(alice_res.is_ok());
    auto alice_state = std::move(alice_res).value();

    auto bob_res = DoubleRatchetEngine::initialize_bob(crypto, shared_secret, std::move(bob_dh));
    ASSERT_TRUE(bob_res.is_ok());
    auto bob_state = std::move(bob_res).value();

    // Alice generates 4 messages: #0, #1, #2, #3
    const std::string p0 = "Message 0: Initial greeting";
    const std::string p1 = "Message 1: Middle critical payload";
    const std::string p2 = "Message 2: Subsequent update";
    const std::string p3 = "Message 3: Final confirmation";

    auto m0_res = DoubleRatchetEngine::ratchet_encrypt(
        crypto, alice_state, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(p0.data()), p0.size()));
    ASSERT_TRUE(m0_res.is_ok());

    auto m1_res = DoubleRatchetEngine::ratchet_encrypt(
        crypto, alice_state, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(p1.data()), p1.size()));
    ASSERT_TRUE(m1_res.is_ok());

    auto m2_res = DoubleRatchetEngine::ratchet_encrypt(
        crypto, alice_state, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(p2.data()), p2.size()));
    ASSERT_TRUE(m2_res.is_ok());

    auto m3_res = DoubleRatchetEngine::ratchet_encrypt(
        crypto, alice_state, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(p3.data()), p3.size()));
    ASSERT_TRUE(m3_res.is_ok());

    // Bob receives message 0
    auto dec0 = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, m0_res.value());
    ASSERT_TRUE(dec0.is_ok());
    EXPECT_EQ(dec0.value().expose_unredacted_secret(), p0);
    EXPECT_EQ(bob_state.nr, 1u);
    EXPECT_EQ(bob_state.skipped_keys.size(), 0u);

    // Bob receives message 2 (skipping message 1!)
    auto dec2 = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, m2_res.value());
    ASSERT_TRUE(dec2.is_ok());
    EXPECT_EQ(dec2.value().expose_unredacted_secret(), p2);
    EXPECT_EQ(bob_state.nr, 3u);
    EXPECT_EQ(bob_state.skipped_keys.size(), 1u); // Key for message 1 stored!

    // Bob receives message 3
    auto dec3 = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, m3_res.value());
    ASSERT_TRUE(dec3.is_ok());
    EXPECT_EQ(dec3.value().expose_unredacted_secret(), p3);
    EXPECT_EQ(bob_state.nr, 4u);
    EXPECT_EQ(bob_state.skipped_keys.size(), 1u);

    // Bob finally receives delayed message 1
    auto dec1 = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, m1_res.value());
    ASSERT_TRUE(dec1.is_ok());
    EXPECT_EQ(dec1.value().expose_unredacted_secret(), p1);
    EXPECT_EQ(bob_state.skipped_keys.size(), 0u); // Key 1 consumed and purged!

    // Replaying message 1 must be rejected
    auto replay_m1 = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, m1_res.value());
    EXPECT_FALSE(replay_m1.is_ok());

    // Replaying message 0 or 2 must also be rejected
    EXPECT_FALSE(DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, m0_res.value()).is_ok());
    EXPECT_FALSE(DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, m2_res.value()).is_ok());
}

TEST(DoubleRatchetOutOfOrderTest, OutOfOrderAcrossDhRatchetTurn) {
    OpenSslCryptoProvider crypto;
    SecretString shared_secret(std::string(32, 0x6B));

    auto bob_dh = crypto.generate_dh_keypair().value();
    std::vector<uint8_t> bob_dh_pub = bob_dh.public_key;

    auto alice_state = DoubleRatchetEngine::initialize_alice(crypto, shared_secret, bob_dh_pub).value();
    auto bob_state = DoubleRatchetEngine::initialize_bob(crypto, shared_secret, std::move(bob_dh)).value();

    // Alice sends Epoch A: msg 0, msg 1
    const std::string a0 = "Epoch A - Msg 0";
    const std::string a1 = "Epoch A - Msg 1 (Delayed)";
    auto m_a0 =
        DoubleRatchetEngine::ratchet_encrypt(
            crypto, alice_state, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(a0.data()), a0.size()))
            .value();
    auto m_a1 =
        DoubleRatchetEngine::ratchet_encrypt(
            crypto, alice_state, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(a1.data()), a1.size()))
            .value();

    // Bob only receives Msg 0
    auto d_a0 = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, m_a0);
    ASSERT_TRUE(d_a0.is_ok());
    EXPECT_EQ(d_a0.value().expose_unredacted_secret(), a0);

    // Bob now replies to Alice (turning Bob's ratchet)
    const std::string b0 = "Epoch B - Bob Reply";
    auto m_b0 = DoubleRatchetEngine::ratchet_encrypt(
                    crypto, bob_state, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(b0.data()), b0.size()))
                    .value();

    // Alice receives Bob's reply (Alice turns her ratchet)
    auto d_b0 = DoubleRatchetEngine::ratchet_decrypt(crypto, alice_state, m_b0);
    ASSERT_TRUE(d_b0.is_ok());
    EXPECT_EQ(d_b0.value().expose_unredacted_secret(), b0);

    // Alice sends Epoch C message (with new DH key, PN=2 because she sent 2 msgs in Epoch A)
    const std::string a2 = "Epoch C - Msg 0 from Alice";
    auto m_a2 =
        DoubleRatchetEngine::ratchet_encrypt(
            crypto, alice_state, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(a2.data()), a2.size()))
            .value();
    EXPECT_EQ(m_a2.header.pn(), 2u);

    // Bob receives Epoch C message BEFORE receiving delayed Epoch A message 1!
    auto d_a2 = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, m_a2);
    ASSERT_TRUE(d_a2.is_ok());
    EXPECT_EQ(d_a2.value().expose_unredacted_secret(), a2);
    EXPECT_EQ(bob_state.skipped_keys.size(), 1u); // Key for Epoch A Msg 1 was stored!

    // Delayed Epoch A Msg 1 finally arrives at Bob
    auto d_a1 = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, m_a1);
    ASSERT_TRUE(d_a1.is_ok());
    EXPECT_EQ(d_a1.value().expose_unredacted_secret(), a1);
    EXPECT_EQ(bob_state.skipped_keys.size(), 0u); // Consumed!

    // Replay of delayed Epoch A Msg 1 fails
    EXPECT_FALSE(DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, m_a1).is_ok());
}

TEST(DoubleRatchetOutOfOrderTest, ExcessiveSkipGapRejected) {
    OpenSslCryptoProvider crypto;
    SecretString shared_secret(std::string(32, 0x7C));

    auto bob_dh = crypto.generate_dh_keypair().value();
    std::vector<uint8_t> bob_dh_pub = bob_dh.public_key;

    auto alice_state = DoubleRatchetEngine::initialize_alice(crypto, shared_secret, bob_dh_pub).value();
    auto bob_state = DoubleRatchetEngine::initialize_bob(crypto, shared_secret, std::move(bob_dh)).value();

    const std::string p = "Normal message";
    auto normal_msg =
        DoubleRatchetEngine::ratchet_encrypt(
            crypto, alice_state, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(p.data()), p.size()))
            .value();

    // Craft a message with gap > 2000
    DoubleRatchetMessage malicious_msg{
        .header = RatchetHeader(normal_msg.header.dh_pub(), 0, 5000),
        .ciphertext = normal_msg.ciphertext,
        .iv = normal_msg.iv,
        .auth_tag = normal_msg.auth_tag,
    };

    auto dec_res = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, malicious_msg);
    EXPECT_FALSE(dec_res.is_ok());
    EXPECT_EQ(bob_state.skipped_keys.size(), 0u);
}

TEST(DoubleRatchetOutOfOrderTest, StubCryptoProviderParity) {
    StubCryptoProvider stub_crypto;
    SecretString shared_secret(std::string(32, 0x8D));

    auto bob_dh = stub_crypto.generate_dh_keypair().value();
    std::vector<uint8_t> bob_dh_pub = bob_dh.public_key;

    auto alice_state = DoubleRatchetEngine::initialize_alice(stub_crypto, shared_secret, bob_dh_pub).value();
    auto bob_state = DoubleRatchetEngine::initialize_bob(stub_crypto, shared_secret, std::move(bob_dh)).value();

    const std::string m0_text = "Stub 0";
    const std::string m1_text = "Stub 1";

    auto m0 = DoubleRatchetEngine::ratchet_encrypt(
                  stub_crypto, alice_state,
                  std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(m0_text.data()), m0_text.size()))
                  .value();
    auto m1 = DoubleRatchetEngine::ratchet_encrypt(
                  stub_crypto, alice_state,
                  std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(m1_text.data()), m1_text.size()))
                  .value();

    // Bob receives m1 first (skipping m0)
    auto dec1 = DoubleRatchetEngine::ratchet_decrypt(stub_crypto, bob_state, m1);
    ASSERT_TRUE(dec1.is_ok());
    EXPECT_EQ(dec1.value().expose_unredacted_secret(), m1_text);
    EXPECT_EQ(bob_state.skipped_keys.size(), 1u);

    // Bob receives delayed m0
    auto dec0 = DoubleRatchetEngine::ratchet_decrypt(stub_crypto, bob_state, m0);
    ASSERT_TRUE(dec0.is_ok());
    EXPECT_EQ(dec0.value().expose_unredacted_secret(), m0_text);
    EXPECT_EQ(bob_state.skipped_keys.size(), 0u);
}

} // namespace
} // namespace securecloud::client::domain::crypto
