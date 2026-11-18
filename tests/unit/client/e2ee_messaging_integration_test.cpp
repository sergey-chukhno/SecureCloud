#include "application/client_config.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "domain/conversation.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/device_id.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/prekey_policy.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace securecloud::client::application {
namespace {

using infrastructure::adapters::DefaultGatewayClient;
using infrastructure::adapters::KeyStorageHelper;
using infrastructure::adapters::MemoryLocalStore;
using infrastructure::adapters::MemorySecureStorage;
using infrastructure::adapters::OpenSslCryptoProvider;
using managers::MessagingManager;
using managers::RatchetSessionManager;
using securecloud::common::configuration::SecretString;

struct E2EClientEndpoint {
    domain::UserId user_id;
    domain::DeviceId device_id;
    std::vector<uint8_t> identity_public_key;
    std::unique_ptr<MemorySecureStorage> secure_storage;
    std::unique_ptr<MemoryLocalStore> local_store;
    interfaces::DeviceCryptoDirectoryEntry dir_entry;
    std::unique_ptr<RatchetSessionManager> ratchet_mgr;
    std::unique_ptr<MessagingManager> messaging_mgr;
};

E2EClientEndpoint create_e2e_endpoint(interfaces::ICryptoProvider& crypto, DefaultGatewayClient& gateway,
                                      const std::string& uid_str, const std::string& did_str, bool with_otpk = true) {
    domain::UserId uid(uid_str);
    domain::DeviceId did(did_str);
    auto secure_storage = std::make_unique<MemorySecureStorage>();
    auto local_store = std::make_unique<MemoryLocalStore>();

    auto id_pair = crypto.generate_identity_keypair().value();
    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key).value();

    std::unordered_map<std::string, SecretString> otpk_privates;
    std::optional<std::vector<uint8_t>> otpk_pub;
    std::string otpk_id;

    if (with_otpk) {
        auto otpk_pair = crypto.generate_dh_keypair().value();
        otpk_pub = otpk_pair.public_key;
        otpk_id = did_str + "-otpk-01";
        otpk_privates.emplace(otpk_id, std::move(otpk_pair.private_key));
    }

    const auto id_pub = id_pair.public_key;
    domain::DevicePrivateBundle priv_bundle(did, id_pair.public_key, std::move(id_pair.private_key), spk_res.public_key,
                                            std::move(spk_res.private_key), spk_res.signature,
                                            std::move(otpk_privates));
    KeyStorageHelper::save_bundle(*secure_storage, priv_bundle);

    interfaces::DeviceCryptoDirectoryEntry dir_entry{
        .device_id = did,
        .identity_key = id_pub,
        .signed_prekey = spk_res.public_key,
        .signed_prekey_signature = spk_res.signature,
        .one_time_prekey = otpk_pub,
        .one_time_prekey_id = otpk_id,
        .status = domain::DeviceAuthorizationStatus::Authorized,
        .identity_key_fingerprint = crypto.compute_identity_fingerprint(id_pub).value_or(""),
        .remaining_one_time_prekeys = with_otpk ? 1 : 0,
        .signed_prekey_created_at = std::chrono::system_clock::now(),
    };

    auto ratchet_mgr = std::make_unique<RatchetSessionManager>(gateway, *secure_storage, crypto, uid, did);
    auto messaging_mgr = std::make_unique<MessagingManager>(gateway, *local_store, crypto, ratchet_mgr.get());

    return E2EClientEndpoint{
        .user_id = std::move(uid),
        .device_id = std::move(did),
        .identity_public_key = id_pub,
        .secure_storage = std::move(secure_storage),
        .local_store = std::move(local_store),
        .dir_entry = std::move(dir_entry),
        .ratchet_mgr = std::move(ratchet_mgr),
        .messaging_mgr = std::move(messaging_mgr),
    };
}

bool check_anti_plaintext_heuristic(std::string_view payload) noexcept {
    if (payload.empty()) {
        return false;
    }
    const size_t sample_len = std::min<size_t>(payload.size(), 256);
    std::string_view sample = payload.substr(0, sample_len);

    size_t non_ws = 0;
    while (non_ws < sample.size() && std::isspace(static_cast<unsigned char>(sample[non_ws]))) {
        ++non_ws;
    }
    if (non_ws + 1 < sample.size()) {
        if (sample[non_ws] == '{' &&
            (sample[non_ws + 1] == '"' || sample[non_ws + 1] == ' ' || sample[non_ws + 1] == '\n')) {
            return true;
        }
        if (sample[non_ws] == '[' && (sample[non_ws + 1] == '{' || sample[non_ws + 1] == '"')) {
            return true;
        }
    }

    if (sample_len >= 16) {
        size_t printable_count = 0;
        for (char c : sample) {
            unsigned char uc = static_cast<unsigned char>(c);
            if ((uc >= 0x20 && uc <= 0x7E) || uc == '\r' || uc == '\n' || uc == '\t') {
                ++printable_count;
            }
        }
        if (static_cast<double>(printable_count) / static_cast<double>(sample_len) >= 0.90) {
            return true;
        }
    }
    return false;
}

} // namespace

// ============================================================================
// Test 1: Full 1:1 Conversation Lifecycle & Bidirectional Double Ratchet
// ============================================================================
TEST(E2EEMessagingIntegrationTest, FullConversationLifecycleAndBidirectionalRatchet) {
    OpenSslCryptoProvider crypto;
    ClientConfig config;
    DefaultGatewayClient gateway(config);

    auto alice = create_e2e_endpoint(crypto, gateway, "usr-alice", "dev-alice-phone");
    auto bob = create_e2e_endpoint(crypto, gateway, "usr-bob", "dev-bob-phone");

    // Populate simulated gateway directory for both users
    gateway.set_simulated_user_directory(alice.user_id, {alice.dir_entry});
    gateway.set_simulated_user_directory(bob.user_id, {bob.dir_entry});

    // 1. Establish direct conversations on both local stores
    auto conv_a_res = alice.messaging_mgr->open_direct_conversation(alice.user_id, bob.user_id, "Bob");
    ASSERT_TRUE(conv_a_res.is_ok());
    const auto conv_id = conv_a_res.value().conversation_id();

    auto conv_b_res = bob.messaging_mgr->open_direct_conversation(bob.user_id, alice.user_id, "Alice");
    ASSERT_TRUE(conv_b_res.is_ok());

    // 2. Alice sends initial message to Bob (triggers X3DH handshake + Ratchet init)
    const std::string msg1_text = "Hello Bob! Signal Double Ratchet session initialized.";
    auto send1_res =
        alice.messaging_mgr->send_message(conv_id, alice.user_id, alice.device_id, bob.device_id, msg1_text);
    ASSERT_TRUE(send1_res.is_ok());

    // 3. Bob processes inbound payload via Double Ratchet
    domain::crypto::PerDeviceDeliveryPayload payload1{
        .recipient_user_id = bob.user_id,
        .recipient_device_id = bob.device_id,
        .ciphertext_blob = send1_res.value().encrypted_envelope_ref(),
        .ephemeral_public_key = {},
        .iv = {},
        .auth_tag = {},
        .algorithm = "AES-256-GCM",
    };

    auto recv1_res =
        bob.messaging_mgr->process_inbound_message(conv_id, alice.user_id, alice.device_id, payload1, 0, "Alice");
    ASSERT_TRUE(recv1_res.is_ok());
    EXPECT_EQ(recv1_res.value().encrypted_envelope_ref(), msg1_text);
    EXPECT_TRUE(bob.ratchet_mgr->has_session(alice.user_id, alice.device_id));

    // Verify Bob's single-use OTPK was consumed and wiped from storage
    auto bob_bundle_after = KeyStorageHelper::load_bundle(*bob.secure_storage, bob.device_id);
    ASSERT_TRUE(bob_bundle_after.is_ok());
    EXPECT_FALSE(bob_bundle_after.value().has_one_time_prekey(bob.dir_entry.one_time_prekey_id));

    // 4. Bob replies to Alice (advancing DH ratchet step)
    const std::string reply1_text = "Acknowledged Alice! Double Ratchet receiver initialized.";
    auto reply1_res =
        bob.messaging_mgr->send_message(conv_id, bob.user_id, bob.device_id, alice.device_id, reply1_text);
    ASSERT_TRUE(reply1_res.is_ok());

    domain::crypto::PerDeviceDeliveryPayload reply_payload{
        .recipient_user_id = alice.user_id,
        .recipient_device_id = alice.device_id,
        .ciphertext_blob = reply1_res.value().encrypted_envelope_ref(),
        .ephemeral_public_key = {},
        .iv = {},
        .auth_tag = {},
        .algorithm = "AES-256-GCM",
    };

    auto alice_recv_res =
        alice.messaging_mgr->process_inbound_message(conv_id, bob.user_id, bob.device_id, reply_payload, 0, "Bob");
    ASSERT_TRUE(alice_recv_res.is_ok());
    EXPECT_EQ(alice_recv_res.value().encrypted_envelope_ref(), reply1_text);

    // 5. Multi-message exchanges across successive ratchet steps
    for (int i = 2; i <= 6; ++i) {
        const std::string a_to_b = "Alice packet #" + std::to_string(i);
        auto a_send = alice.messaging_mgr->send_message(conv_id, alice.user_id, alice.device_id, bob.device_id, a_to_b);
        ASSERT_TRUE(a_send.is_ok());

        domain::crypto::PerDeviceDeliveryPayload p{
            .recipient_user_id = bob.user_id,
            .recipient_device_id = bob.device_id,
            .ciphertext_blob = a_send.value().encrypted_envelope_ref(),
            .ephemeral_public_key = {},
            .iv = {},
            .auth_tag = {},
            .algorithm = "AES-256-GCM",
        };
        auto b_recv =
            bob.messaging_mgr->process_inbound_message(conv_id, alice.user_id, alice.device_id, p, 0, "Alice");
        ASSERT_TRUE(b_recv.is_ok());
        EXPECT_EQ(b_recv.value().encrypted_envelope_ref(), a_to_b);

        const std::string b_to_a = "Bob response #" + std::to_string(i);
        auto b_send = bob.messaging_mgr->send_message(conv_id, bob.user_id, bob.device_id, alice.device_id, b_to_a);
        ASSERT_TRUE(b_send.is_ok());

        domain::crypto::PerDeviceDeliveryPayload p_reply{
            .recipient_user_id = alice.user_id,
            .recipient_device_id = alice.device_id,
            .ciphertext_blob = b_send.value().encrypted_envelope_ref(),
            .ephemeral_public_key = {},
            .iv = {},
            .auth_tag = {},
            .algorithm = "AES-256-GCM",
        };
        auto a_recv =
            alice.messaging_mgr->process_inbound_message(conv_id, bob.user_id, bob.device_id, p_reply, 0, "Bob");
        ASSERT_TRUE(a_recv.is_ok());
        EXPECT_EQ(a_recv.value().encrypted_envelope_ref(), b_to_a);
    }

    EXPECT_EQ(alice.ratchet_mgr->active_session_count(), 1U);
    EXPECT_EQ(bob.ratchet_mgr->active_session_count(), 1U);
}

// ============================================================================
// Test 2: Multi-Device Fan-out Across Recipients & Companion Devices
// ============================================================================
TEST(E2EEMessagingIntegrationTest, MultiDeviceFanoutAcrossParticipantsAndCompanions) {
    OpenSslCryptoProvider crypto;
    ClientConfig config;
    DefaultGatewayClient gateway(config);

    // Alice has phone + desktop companion
    auto alice_phone = create_e2e_endpoint(crypto, gateway, "usr-alice", "dev-alice-phone");
    auto alice_desktop = create_e2e_endpoint(crypto, gateway, "usr-alice", "dev-alice-desktop");

    // Bob has phone + laptop
    auto bob_phone = create_e2e_endpoint(crypto, gateway, "usr-bob", "dev-bob-phone");
    auto bob_laptop = create_e2e_endpoint(crypto, gateway, "usr-bob", "dev-bob-laptop");

    gateway.set_simulated_user_directory(alice_phone.user_id, {alice_phone.dir_entry, alice_desktop.dir_entry});
    gateway.set_simulated_user_directory(bob_phone.user_id, {bob_phone.dir_entry, bob_laptop.dir_entry});

    const std::string broadcast_msg = "Critical Security Alert: Rotate Enclave Credentials Immediately";
    std::span<const uint8_t> pt_span(reinterpret_cast<const uint8_t*>(broadcast_msg.data()), broadcast_msg.size());

    // Alice phone encrypts fan-out for both participants (Alice + Bob)
    std::vector<domain::UserId> participants = {alice_phone.user_id, bob_phone.user_id};
    auto fanout_res = alice_phone.ratchet_mgr->encrypt_fanout_for_participants(participants, pt_span);
    ASSERT_TRUE(fanout_res.is_ok());

    const auto& payloads = fanout_res.value();
    // Expected 3 payloads: Bob phone, Bob laptop, and Alice desktop companion (omitting Alice phone itself)
    ASSERT_EQ(payloads.size(), 3U);

    bool bob_phone_decrypted = false;
    bool bob_laptop_decrypted = false;
    bool alice_desktop_decrypted = false;

    for (const auto& payload : payloads) {
        if (payload.recipient_user_id == bob_phone.user_id && payload.recipient_device_id == bob_phone.device_id) {
            auto dec =
                bob_phone.ratchet_mgr->decrypt_payload_from_device(alice_phone.user_id, alice_phone.device_id, payload);
            ASSERT_TRUE(dec.is_ok());
            EXPECT_EQ(dec.value().expose_unredacted_secret(), broadcast_msg);
            bob_phone_decrypted = true;
        } else if (payload.recipient_user_id == bob_laptop.user_id &&
                   payload.recipient_device_id == bob_laptop.device_id) {
            auto dec = bob_laptop.ratchet_mgr->decrypt_payload_from_device(alice_phone.user_id, alice_phone.device_id,
                                                                           payload);
            ASSERT_TRUE(dec.is_ok());
            EXPECT_EQ(dec.value().expose_unredacted_secret(), broadcast_msg);
            bob_laptop_decrypted = true;
        } else if (payload.recipient_user_id == alice_desktop.user_id &&
                   payload.recipient_device_id == alice_desktop.device_id) {
            auto dec = alice_desktop.ratchet_mgr->decrypt_payload_from_device(alice_phone.user_id,
                                                                              alice_phone.device_id, payload);
            ASSERT_TRUE(dec.is_ok());
            EXPECT_EQ(dec.value().expose_unredacted_secret(), broadcast_msg);
            alice_desktop_decrypted = true;
        }
    }

    EXPECT_TRUE(bob_phone_decrypted);
    EXPECT_TRUE(bob_laptop_decrypted);
    EXPECT_TRUE(alice_desktop_decrypted);
}

// ============================================================================
// Test 3: Out-of-Order Packet Delivery & Skipped Message Key Store
// ============================================================================
TEST(E2EEMessagingIntegrationTest, OutOfOrderDeliveryAndReplayPrevention) {
    OpenSslCryptoProvider crypto;
    ClientConfig config;
    DefaultGatewayClient gateway(config);

    auto alice = create_e2e_endpoint(crypto, gateway, "usr-alice", "dev-alice-phone");
    auto bob = create_e2e_endpoint(crypto, gateway, "usr-bob", "dev-bob-phone");

    gateway.set_simulated_user_directory(bob.user_id, {bob.dir_entry});

    // 1. Initial handshake message establishes the Double Ratchet session
    const std::string init_msg = "Handshake: Establishing Double Ratchet session";
    std::span<const uint8_t> init_span(reinterpret_cast<const uint8_t*>(init_msg.data()), init_msg.size());
    auto init_enc = alice.ratchet_mgr->encrypt_payload_for_device(bob.user_id, bob.device_id, init_span);
    ASSERT_TRUE(init_enc.is_ok());
    auto init_dec = bob.ratchet_mgr->decrypt_payload_from_device(alice.user_id, alice.device_id, init_enc.value());
    ASSERT_TRUE(init_dec.is_ok());
    EXPECT_EQ(init_dec.value().expose_unredacted_secret(), init_msg);

    // 2. Alice prepares 5 sequential messages in one epoch
    std::vector<std::string> messages = {
        "Packet 0: System diagnostic initiated",
        "Packet 1: Loading TLS certificates",
        "Packet 2: Verifying mTLS handshake parameters",
        "Packet 3: Cryptographic keys attested by TPM enclave",
        "Packet 4: Secure communication channel operational",
    };

    std::vector<domain::crypto::PerDeviceDeliveryPayload> payloads;
    for (const auto& msg : messages) {
        std::span<const uint8_t> pt_span(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        auto enc_res = alice.ratchet_mgr->encrypt_payload_for_device(bob.user_id, bob.device_id, pt_span);
        ASSERT_TRUE(enc_res.is_ok());
        payloads.push_back(enc_res.value());
    }

    // 3. Network reorders delivery to Bob: Packet 4 arrives first, then 1, 3, 0, 2
    const std::vector<std::size_t> arrival_order = {4, 1, 3, 0, 2};

    for (std::size_t idx : arrival_order) {
        auto dec_res = bob.ratchet_mgr->decrypt_payload_from_device(alice.user_id, alice.device_id, payloads[idx]);
        ASSERT_TRUE(dec_res.is_ok()) << "Failed to decrypt packet index: " << idx;
        EXPECT_EQ(dec_res.value().expose_unredacted_secret(), messages[idx]);
    }

    // 4. Replay attack prevention: attempting to re-deliver Packet 1 must fail
    auto replay_res = bob.ratchet_mgr->decrypt_payload_from_device(alice.user_id, alice.device_id, payloads[1]);
    EXPECT_TRUE(replay_res.is_error()) << "Replay attack was unexpectedly accepted!";
}

// ============================================================================
// Test 4: Post-Compromise Security Recovery (Healing Asymmetric Ratchet Step)
// ============================================================================
TEST(E2EEMessagingIntegrationTest, PostCompromiseSecurityHealing) {
    OpenSslCryptoProvider crypto;
    ClientConfig config;
    DefaultGatewayClient gateway(config);

    auto alice = create_e2e_endpoint(crypto, gateway, "usr-alice", "dev-alice-phone");
    auto bob = create_e2e_endpoint(crypto, gateway, "usr-bob", "dev-bob-phone");

    gateway.set_simulated_user_directory(bob.user_id, {bob.dir_entry});
    gateway.set_simulated_user_directory(alice.user_id, {alice.dir_entry});

    // 1. Initial message exchange to establish session
    const std::string msg1 = "Epoch 0 initial exchange";
    std::span<const uint8_t> pt1(reinterpret_cast<const uint8_t*>(msg1.data()), msg1.size());
    auto enc1 = alice.ratchet_mgr->encrypt_payload_for_device(bob.user_id, bob.device_id, pt1);
    ASSERT_TRUE(enc1.is_ok());

    auto dec1 = bob.ratchet_mgr->decrypt_payload_from_device(alice.user_id, alice.device_id, enc1.value());
    ASSERT_TRUE(dec1.is_ok());

    // 2. Bob replies to turn the DH Ratchet, mixing in fresh asymmetric entropy
    const std::string msg2 = "Epoch 1 DH ratchet step reply";
    std::span<const uint8_t> pt2(reinterpret_cast<const uint8_t*>(msg2.data()), msg2.size());
    auto enc2 = bob.ratchet_mgr->encrypt_payload_for_device(alice.user_id, alice.device_id, pt2);
    ASSERT_TRUE(enc2.is_ok());

    auto dec2 = alice.ratchet_mgr->decrypt_payload_from_device(bob.user_id, bob.device_id, enc2.value());
    ASSERT_TRUE(dec2.is_ok());

    // 3. Alice sends Epoch 2 message with another fresh DH ratchet step
    const std::string msg3 = "Epoch 2 post-compromise healed payload";
    std::span<const uint8_t> pt3(reinterpret_cast<const uint8_t*>(msg3.data()), msg3.size());
    auto enc3 = alice.ratchet_mgr->encrypt_payload_for_device(bob.user_id, bob.device_id, pt3);
    ASSERT_TRUE(enc3.is_ok());

    // Verify Bob successfully decrypts the healed session
    auto dec3 = bob.ratchet_mgr->decrypt_payload_from_device(alice.user_id, alice.device_id, enc3.value());
    ASSERT_TRUE(dec3.is_ok());
    EXPECT_EQ(dec3.value().expose_unredacted_secret(), msg3);
}

// ============================================================================
// Test 5: Client Restart and Secure Session Resumption Across Process Lifecycle
// ============================================================================
TEST(E2EEMessagingIntegrationTest, SessionPersistenceAndResumptionAcrossClientRestart) {
    OpenSslCryptoProvider crypto;
    ClientConfig config;
    DefaultGatewayClient gateway(config);

    auto alice = create_e2e_endpoint(crypto, gateway, "usr-alice", "dev-alice-phone");
    auto bob = create_e2e_endpoint(crypto, gateway, "usr-bob", "dev-bob-phone");

    gateway.set_simulated_user_directory(bob.user_id, {bob.dir_entry});

    // 1. Initial exchange
    const std::string msg_pre = "Session established before shutdown";
    std::span<const uint8_t> pt_pre(reinterpret_cast<const uint8_t*>(msg_pre.data()), msg_pre.size());
    auto enc_pre = alice.ratchet_mgr->encrypt_payload_for_device(bob.user_id, bob.device_id, pt_pre);
    ASSERT_TRUE(enc_pre.is_ok());

    auto dec_pre = bob.ratchet_mgr->decrypt_payload_from_device(alice.user_id, alice.device_id, enc_pre.value());
    ASSERT_TRUE(dec_pre.is_ok());
    EXPECT_EQ(dec_pre.value().expose_unredacted_secret(), msg_pre);

    // 2. Simulate Bob process crash / restart:
    // Destroy Bob's RatchetSessionManager and instantiate a new one pointing to the same storage
    bob.ratchet_mgr.reset();

    auto bob_restarted_mgr =
        std::make_unique<RatchetSessionManager>(gateway, *bob.secure_storage, crypto, bob.user_id, bob.device_id);

    EXPECT_FALSE(bob_restarted_mgr->has_session(alice.user_id, alice.device_id));
    auto load_res = bob_restarted_mgr->load_all_sessions();
    ASSERT_TRUE(load_res.is_ok());
    EXPECT_TRUE(bob_restarted_mgr->has_session(alice.user_id, alice.device_id));

    // 3. Alice sends a post-restart message (without X3DH header)
    const std::string msg_post = "Message delivered seamlessly after client restart!";
    std::span<const uint8_t> pt_post(reinterpret_cast<const uint8_t*>(msg_post.data()), msg_post.size());
    auto enc_post = alice.ratchet_mgr->encrypt_payload_for_device(bob.user_id, bob.device_id, pt_post);
    ASSERT_TRUE(enc_post.is_ok());

    // 4. Restarted Bob decrypts post-restart message using persisted ratchet state
    auto dec_post = bob_restarted_mgr->decrypt_payload_from_device(alice.user_id, alice.device_id, enc_post.value());
    ASSERT_TRUE(dec_post.is_ok());
    EXPECT_EQ(dec_post.value().expose_unredacted_secret(), msg_post);
}

// ============================================================================
// Test 6: Backend E2E Envelope Rules & Anti-Plaintext Compliance
// ============================================================================
TEST(E2EEMessagingIntegrationTest, BackendEnvelopeValidationAndTamperResistance) {
    OpenSslCryptoProvider crypto;
    ClientConfig config;
    DefaultGatewayClient gateway(config);

    auto alice = create_e2e_endpoint(crypto, gateway, "usr-alice", "dev-alice-phone");
    auto bob = create_e2e_endpoint(crypto, gateway, "usr-bob", "dev-bob-phone");

    gateway.set_simulated_user_directory(bob.user_id, {bob.dir_entry});

    const std::string plaintext = "Top Secret Zero-Trust Enclave Payload";
    std::span<const uint8_t> pt_span(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());

    auto enc_res = alice.ratchet_mgr->encrypt_payload_for_device(bob.user_id, bob.device_id, pt_span);
    ASSERT_TRUE(enc_res.is_ok());

    const auto& payload = enc_res.value();

    // 1. Verify compliance with ProtocolVersionPolicy & E2EEnvelopeValidator bounds:
    EXPECT_EQ(payload.algorithm, "AES-256-GCM");
    EXPECT_GE(payload.iv.size(), 12U);
    EXPECT_GE(payload.auth_tag.size(), 16U);
    EXPECT_GE(payload.ephemeral_public_key.size(), 32U);
    EXPECT_FALSE(payload.ciphertext_blob.empty());

    // 2. Anti-plaintext heuristic: ciphertext must NOT look like plaintext or structured JSON
    EXPECT_FALSE(check_anti_plaintext_heuristic(payload.ciphertext_blob));

    // Verify heuristic correctly flags unencrypted text
    EXPECT_TRUE(check_anti_plaintext_heuristic("{\"type\":\"message\",\"content\":\"unencrypted\"}"));
    EXPECT_TRUE(check_anti_plaintext_heuristic("This is an unencrypted plaintext message sent by an attacker"));

    // 3. Cryptographic Tamper Resistance:
    // A) Mutating a ciphertext byte must cause AEAD authentication failure
    auto tampered_payload = payload;
    tampered_payload.ciphertext_blob[tampered_payload.ciphertext_blob.size() - 5] ^= 0x55;
    auto fail_tamper_ct =
        bob.ratchet_mgr->decrypt_payload_from_device(alice.user_id, alice.device_id, tampered_payload);
    EXPECT_TRUE(fail_tamper_ct.is_error());

    // B) Mutating an auth tag byte must cause authentication failure
    auto tampered_tag = payload;
    tampered_tag.auth_tag[0] ^= 0xAA;
    // Re-pack into serialized envelope
    auto env_res = domain::crypto::EncryptedMessageEnvelope::deserialize(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(payload.ciphertext_blob.data()), payload.ciphertext_blob.size()));
    ASSERT_TRUE(env_res.is_ok());
    auto env = env_res.value();
    env.ratchet_message.auth_tag[0] ^= 0xAA;
    auto tampered_env_bytes = env.serialize();
    tampered_tag.ciphertext_blob =
        std::string(reinterpret_cast<const char*>(tampered_env_bytes.data()), tampered_env_bytes.size());

    auto fail_tamper_tag = bob.ratchet_mgr->decrypt_payload_from_device(alice.user_id, alice.device_id, tampered_tag);
    EXPECT_TRUE(fail_tamper_tag.is_error());
}

// ============================================================================
// Test 7: 60-Digit Mutual Safety Number Verification ($IK_A \parallel IK_B$)
// ============================================================================
TEST(E2EEMessagingIntegrationTest, SafetyNumberVerificationAndRotationAlert) {
    OpenSslCryptoProvider crypto;
    ClientConfig config;
    DefaultGatewayClient gateway(config);

    auto alice = create_e2e_endpoint(crypto, gateway, "usr-alice@securecloud.org", "dev-alice-phone");
    auto bob = create_e2e_endpoint(crypto, gateway, "usr-bob@securecloud.org", "dev-bob-phone");

    // 1. Compute mutual safety numbers from both perspectives
    auto sn_alice_view =
        crypto.compute_safety_number(alice.user_id, alice.identity_public_key, bob.user_id, bob.identity_public_key);
    ASSERT_TRUE(sn_alice_view.is_ok());

    auto sn_bob_view =
        crypto.compute_safety_number(bob.user_id, bob.identity_public_key, alice.user_id, alice.identity_public_key);
    ASSERT_TRUE(sn_bob_view.is_ok());

    // Commutativity: both parties must compute identical Safety Numbers regardless of who initiated
    EXPECT_EQ(sn_alice_view.value(), sn_bob_view.value());

    // Verify 60-digit formatting: 12 blocks of 5 digits separated by 11 single spaces
    // Total string length: 12 * 5 + 11 = 71 characters
    const std::string sn = sn_alice_view.value();
    EXPECT_EQ(sn.length(), 71U);

    size_t space_count = 0;
    size_t digit_count = 0;
    for (size_t i = 0; i < sn.length(); ++i) {
        if ((i + 1) % 6 == 0) {
            EXPECT_EQ(sn[i], ' ') << "Expected space at index " << i;
            ++space_count;
        } else {
            EXPECT_TRUE(std::isdigit(static_cast<unsigned char>(sn[i])))
                << "Expected digit at index " << i << " but got " << sn[i];
            ++digit_count;
        }
    }
    EXPECT_EQ(space_count, 11U);
    EXPECT_EQ(digit_count, 60U);

    // 2. Identity Key Rotation detection:
    // If Bob rotates his identity key, the Safety Number must change
    auto bob_new_id_pair = crypto.generate_identity_keypair().value();
    auto sn_after_rotation =
        crypto.compute_safety_number(alice.user_id, alice.identity_public_key, bob.user_id, bob_new_id_pair.public_key);
    ASSERT_TRUE(sn_after_rotation.is_ok());
    EXPECT_NE(sn_alice_view.value(), sn_after_rotation.value());

    // 3. ADR-008 Outbound Messaging Guard:
    // If a contact's status is KeyChanged, stage_outbound_message must reject outbound submission
    auto conv_res = alice.messaging_mgr->open_direct_conversation(alice.user_id, bob.user_id);
    ASSERT_TRUE(conv_res.is_ok());

    domain::Contact bob_contact(bob.user_id, "Bob", domain::KeyVerificationStatus::KeyChanged,
                                sn_after_rotation.value(), false, sn_after_rotation.value(), "Engineer",
                                domain::PresenceStatus::Online, 1);
    ASSERT_TRUE(alice.local_store->save_contact(bob_contact).is_ok());

    auto blocked_send = alice.messaging_mgr->stage_outbound_message(
        conv_res.value().conversation_id(), alice.user_id, alice.device_id, "Attempted send during key change");
    EXPECT_TRUE(blocked_send.is_error());
    EXPECT_NE(blocked_send.error().user_message().find("ADR-008"), std::string::npos);
}

} // namespace securecloud::client::application
