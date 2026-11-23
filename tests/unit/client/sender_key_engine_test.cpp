#include "domain/crypto/sender_key_engine.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::client::domain::crypto::test {
namespace {

std::vector<uint8_t> to_bytes(std::string_view s) {
    std::vector<uint8_t> out;
    out.reserve(s.size());
    for (char ch : s) {
        out.push_back(static_cast<uint8_t>(static_cast<unsigned char>(ch)));
    }
    return out;
}

TEST(SenderKeyEngineTest, DistributionAndInOrderGroupDecryptionAcrossMultiplePeers) {
    infrastructure::adapters::OpenSslCryptoProvider crypto;

    const SenderKeyId alice_key_id{
        .conversation_id = ConversationId("group-100"),
        .sender_user_id = UserId("alice"),
        .sender_device_id = DeviceId("alice-dev-1"),
        .key_epoch = 1,
    };

    auto alice_state_res = SenderKeyEngine::create_sender_key(alice_key_id);
    ASSERT_TRUE(alice_state_res.is_ok());
    SenderKeyState alice_state = std::move(alice_state_res.value());

    auto dist_res = SenderKeyEngine::create_distribution_message(alice_state);
    ASSERT_TRUE(dist_res.is_ok());

    const auto dist_bytes = dist_res.value().serialize();
    auto bob_dist_res = SenderKeyDistributionMessage::deserialize(dist_bytes);
    ASSERT_TRUE(bob_dist_res.is_ok());

    auto bob_state_res = SenderKeyEngine::process_distribution_message(bob_dist_res.value());
    auto charlie_state_res = SenderKeyEngine::process_distribution_message(bob_dist_res.value());
    ASSERT_TRUE(bob_state_res.is_ok());
    ASSERT_TRUE(charlie_state_res.is_ok());
    SenderKeyState bob_state = std::move(bob_state_res.value());
    SenderKeyState charlie_state = std::move(charlie_state_res.value());

    // Receive-only state cannot encrypt
    EXPECT_TRUE(SenderKeyEngine::encrypt(crypto, bob_state, to_bytes("forged")).is_error());

    // Alice encrypts 2 messages
    auto env1_res = SenderKeyEngine::encrypt(crypto, alice_state, to_bytes("Hello team!"));
    auto env2_res = SenderKeyEngine::encrypt(crypto, alice_state, to_bytes("Second group message"));
    ASSERT_TRUE(env1_res.is_ok());
    ASSERT_TRUE(env2_res.is_ok());
    EXPECT_EQ(alice_state.iteration, 2u);

    const auto wire1 = env1_res.value().serialize();
    const auto wire2 = env2_res.value().serialize();
    auto parsed1 = GroupEncryptedEnvelope::deserialize(wire1);
    auto parsed2 = GroupEncryptedEnvelope::deserialize(wire2);
    ASSERT_TRUE(parsed1.is_ok());
    ASSERT_TRUE(parsed2.is_ok());

    auto bob_pt1 = SenderKeyEngine::decrypt(crypto, bob_state, parsed1.value());
    auto bob_pt2 = SenderKeyEngine::decrypt(crypto, bob_state, parsed2.value());
    ASSERT_TRUE(bob_pt1.is_ok());
    ASSERT_TRUE(bob_pt2.is_ok());
    EXPECT_EQ(bob_pt1.value().expose_unredacted_secret(), "Hello team!");
    EXPECT_EQ(bob_pt2.value().expose_unredacted_secret(), "Second group message");

    auto charlie_pt1 = SenderKeyEngine::decrypt(crypto, charlie_state, parsed1.value());
    auto charlie_pt2 = SenderKeyEngine::decrypt(crypto, charlie_state, parsed2.value());
    ASSERT_TRUE(charlie_pt1.is_ok());
    ASSERT_TRUE(charlie_pt2.is_ok());
    EXPECT_EQ(charlie_pt1.value().expose_unredacted_secret(), "Hello team!");
    EXPECT_EQ(charlie_pt2.value().expose_unredacted_secret(), "Second group message");
}

TEST(SenderKeyEngineTest, OutOfOrderDecryptionAndAntiReplayEnforcement) {
    infrastructure::adapters::OpenSslCryptoProvider crypto;

    const SenderKeyId key_id{
        .conversation_id = ConversationId("group-200"),
        .sender_user_id = UserId("alice"),
        .sender_device_id = DeviceId("alice-dev-1"),
        .key_epoch = 1,
    };

    SenderKeyState alice = SenderKeyEngine::create_sender_key(key_id).value();
    SenderKeyState bob =
        SenderKeyEngine::process_distribution_message(SenderKeyEngine::create_distribution_message(alice).value())
            .value();

    auto e0 = SenderKeyEngine::encrypt(crypto, alice, to_bytes("msg-0")).value();
    auto e1 = SenderKeyEngine::encrypt(crypto, alice, to_bytes("msg-1")).value();
    auto e2 = SenderKeyEngine::encrypt(crypto, alice, to_bytes("msg-2")).value();

    // Deliver out of order: e2 -> e0 -> e1
    auto d2 = SenderKeyEngine::decrypt(crypto, bob, e2);
    ASSERT_TRUE(d2.is_ok());
    EXPECT_EQ(d2.value().expose_unredacted_secret(), "msg-2");
    EXPECT_EQ(bob.skipped_message_keys.size(), 2u);

    auto d0 = SenderKeyEngine::decrypt(crypto, bob, e0);
    ASSERT_TRUE(d0.is_ok());
    EXPECT_EQ(d0.value().expose_unredacted_secret(), "msg-0");

    // Replaying e0 or e2 must fail closed
    EXPECT_TRUE(SenderKeyEngine::decrypt(crypto, bob, e0).is_error());
    EXPECT_TRUE(SenderKeyEngine::decrypt(crypto, bob, e2).is_error());

    auto d1 = SenderKeyEngine::decrypt(crypto, bob, e1);
    ASSERT_TRUE(d1.is_ok());
    EXPECT_EQ(d1.value().expose_unredacted_secret(), "msg-1");
    EXPECT_TRUE(bob.skipped_message_keys.empty());
}

TEST(SenderKeyEngineTest, RejectsTamperedSignatureCiphertextEpochAndExcessiveSkip) {
    infrastructure::adapters::OpenSslCryptoProvider crypto;

    const SenderKeyId key_id{
        .conversation_id = ConversationId("group-300"),
        .sender_user_id = UserId("alice"),
        .sender_device_id = DeviceId("alice-dev-1"),
        .key_epoch = 1,
    };

    SenderKeyState alice = SenderKeyEngine::create_sender_key(key_id).value();
    SenderKeyState bob =
        SenderKeyEngine::process_distribution_message(SenderKeyEngine::create_distribution_message(alice).value())
            .value();

    const GroupEncryptedEnvelope valid = SenderKeyEngine::encrypt(crypto, alice, to_bytes("Authentic")).value();

    // 1. Tampered ciphertext
    {
        GroupEncryptedEnvelope bad_ct = valid;
        bad_ct.ciphertext[0] ^= 0xFFu;
        EXPECT_TRUE(SenderKeyEngine::decrypt(crypto, bob, bad_ct).is_error());
    }

    // 2. Tampered signature
    {
        GroupEncryptedEnvelope bad_sig = valid;
        bad_sig.signature[0] ^= 0xFFu;
        EXPECT_TRUE(SenderKeyEngine::decrypt(crypto, bob, bad_sig).is_error());
    }

    // 3. Epoch mismatch (rotated epoch 2 cannot be decrypted by epoch 1 state)
    {
        SenderKeyId epoch2_id = key_id;
        epoch2_id.key_epoch = 2;
        SenderKeyState alice_e2 = SenderKeyEngine::create_sender_key(epoch2_id).value();
        const GroupEncryptedEnvelope e2_env =
            SenderKeyEngine::encrypt(crypto, alice_e2, to_bytes("Post-removal")).value();
        EXPECT_TRUE(SenderKeyEngine::decrypt(crypto, bob, e2_env).is_error());
    }

    // 4. Excessive iteration skip (> kMaxGroupSkip)
    {
        for (uint32_t i = 1; i <= SenderKeyEngine::kMaxGroupSkip + 2; ++i) {
            (void)SenderKeyEngine::encrypt(crypto, alice, to_bytes("advance"));
        }
        const GroupEncryptedEnvelope far_env = SenderKeyEngine::encrypt(crypto, alice, to_bytes("too-far")).value();
        EXPECT_TRUE(SenderKeyEngine::decrypt(crypto, bob, far_env).is_error());
    }

    // State was never corrupted by failed decryptions, so valid envelope still decrypts!
    auto ok = SenderKeyEngine::decrypt(crypto, bob, valid);
    ASSERT_TRUE(ok.is_ok());
    EXPECT_EQ(ok.value().expose_unredacted_secret(), "Authentic");
}

TEST(SenderKeyEngineTest, SenderKeyStateSerializationRoundTrip) {
    const SenderKeyId key_id{
        .conversation_id = ConversationId("group-400"),
        .sender_user_id = UserId("alice"),
        .sender_device_id = DeviceId("alice-dev-1"),
        .key_epoch = 3,
    };

    SenderKeyState original = SenderKeyEngine::create_sender_key(key_id).value();
    original.iteration = 4;
    original.skipped_message_keys.emplace(1u, common::configuration::SecretString(std::string(32, 'k')));

    const auto bytes = original.serialize();
    auto decoded_res = SenderKeyState::deserialize(bytes);
    ASSERT_TRUE(decoded_res.is_ok());
    EXPECT_EQ(decoded_res.value().id, original.id);
    EXPECT_EQ(decoded_res.value().iteration, 4u);
    EXPECT_EQ(decoded_res.value().chain_key, original.chain_key);
    EXPECT_EQ(decoded_res.value().signing_public_key, original.signing_public_key);
    EXPECT_EQ(decoded_res.value().signing_private_key, original.signing_private_key);
    EXPECT_EQ(decoded_res.value().skipped_message_keys.size(), 1u);
}

} // namespace
} // namespace securecloud::client::domain::crypto::test
