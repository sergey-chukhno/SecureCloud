#include "application/client_config.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "domain/crypto/sender_key_models.hpp"
#include "domain/device_private_bundle.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::client::application::managers::test {
namespace {

using namespace domain;
using namespace domain::crypto;
using namespace infrastructure::adapters;

struct PeerNode {
    UserId uid;
    DeviceId did;
    OpenSslCryptoProvider crypto;
    MemorySecureStorage storage;
    MemoryLocalStore local_store;
    DefaultGatewayClient gateway;
    std::unique_ptr<RatchetSessionManager> ratchet;
    std::unique_ptr<MessagingManager> messaging;
    std::vector<uint8_t> ik_pub;
    std::vector<uint8_t> spk_pub;
    std::vector<uint8_t> spk_sig;
    std::vector<uint8_t> otk_pub;
    std::string otk_id;

    PeerNode(std::string u, std::string d)
        : uid(std::move(u)), did(std::move(d)), gateway(ClientConfig::create_default()) {
        auto ik = crypto.generate_identity_keypair().value();
        auto spk = crypto.generate_signed_prekey(ik.private_key).value();
        auto otk = crypto.generate_dh_keypair().value();

        ik_pub = ik.public_key;
        spk_pub = spk.public_key;
        spk_sig = spk.signature;
        otk_pub = otk.public_key;
        otk_id = did.value() + "-otpk-01";

        std::unordered_map<std::string, common::configuration::SecretString> otk_privs;
        otk_privs.emplace(otk_id, std::move(otk.private_key));
        domain::DevicePrivateBundle priv_bundle(did, ik.public_key, std::move(ik.private_key), spk.public_key,
                                                std::move(spk.private_key), spk.signature, std::move(otk_privs));
        (void)KeyStorageHelper::save_bundle(storage, priv_bundle);

        ratchet = std::make_unique<RatchetSessionManager>(gateway, storage, crypto, uid, did);
        messaging = std::make_unique<MessagingManager>(gateway, local_store, crypto, ratchet.get(), &storage);
    }

    interfaces::DeviceCryptoDirectoryEntry directory_entry() const {
        interfaces::DeviceCryptoDirectoryEntry e;
        e.device_id = did;
        e.identity_key = ik_pub;
        e.signed_prekey = spk_pub;
        e.signed_prekey_signature = spk_sig;
        e.one_time_prekey = otk_pub;
        e.one_time_prekey_id = otk_id;
        e.status = DeviceAuthorizationStatus::Authorized;
        return e;
    }
};

TEST(GroupMessagingPipelineTest, DirectFanOutSubmitsEncryptedPayloadsToGatewayWithoutPlaintext) {
    PeerNode alice("alice", "alice-dev-1");
    PeerNode bob("bob", "bob-dev-1");

    alice.gateway.set_simulated_user_directory(bob.uid, {bob.directory_entry()});
    alice.gateway.set_simulated_user_directory(alice.uid, {alice.directory_entry()});

    auto conv = alice.messaging->open_direct_conversation(alice.uid, bob.uid, "Bob").value();
    const std::string secret_text = "Confidential direct message payload";

    auto send_res = alice.messaging->stage_outbound_message(conv.conversation_id(), alice.uid, alice.did, secret_text);
    ASSERT_TRUE(send_res.is_ok());

    ASSERT_EQ(alice.gateway.submitted_fanouts().size(), 1u);
    const auto& req = alice.gateway.submitted_fanouts()[0];
    EXPECT_EQ(req.conversation_id, conv.conversation_id());
    ASSERT_EQ(req.device_payloads.size(), 1u);
    EXPECT_EQ(req.device_payloads[0].recipient_device_id, bob.did);
    EXPECT_EQ(req.device_payloads[0].ciphertext_blob.find(secret_text), std::string::npos);

    auto bob_dec =
        bob.messaging->process_inbound_message(conv.conversation_id(), alice.uid, alice.did, req.device_payloads[0]);
    ASSERT_TRUE(bob_dec.is_ok());
    EXPECT_EQ(bob_dec.value().encrypted_envelope_ref(), secret_text);
}

TEST(GroupMessagingPipelineTest, AdminRbacRemovalRotatesEpochAndIsolatesRemovedAndLateJoinMembers) {
    PeerNode alice("alice", "alice-dev-1");
    PeerNode bob("bob", "bob-dev-1");
    PeerNode charlie("charlie", "charlie-dev-1");
    PeerNode dave("dave", "dave-dev-1");

    alice.gateway.set_simulated_user_directory(alice.uid, {alice.directory_entry()});
    alice.gateway.set_simulated_user_directory(bob.uid, {bob.directory_entry()});
    alice.gateway.set_simulated_user_directory(charlie.uid, {charlie.directory_entry()});
    alice.gateway.set_simulated_user_directory(dave.uid, {dave.directory_entry()});

    // 1. Alice creates group -> Alice is Admin, Bob & Charlie are Members
    auto conv = alice.messaging->create_group_conversation(alice.uid, "SecOps", {bob.uid, charlie.uid}).value();
    EXPECT_TRUE(conv.is_admin(alice.uid));
    EXPECT_FALSE(conv.is_admin(bob.uid));
    EXPECT_EQ(conv.sender_key_epoch(), 1u);

    // Sync group metadata to Bob's local store to verify RBAC enforcement on non-admin
    ASSERT_TRUE(bob.local_store.save_conversation(conv).is_ok());
    EXPECT_TRUE(bob.messaging->add_group_participant(conv.conversation_id(), bob.uid, dave.uid).is_error());
    EXPECT_TRUE(bob.messaging->remove_group_participant(conv.conversation_id(), bob.uid, charlie.uid).is_error());

    // 2. Alice sends Epoch 1 message -> distributes SenderKey(epoch=1) to Bob & Charlie, then sends SCG envelope
    const std::string epoch1_msg = "Epoch 1: Initial group secret";
    auto send1 = alice.messaging->stage_outbound_message(conv.conversation_id(), alice.uid, alice.did, epoch1_msg);
    ASSERT_TRUE(send1.is_ok());
    EXPECT_EQ(send1.value().sender_key_epoch(), 1u);

    ASSERT_EQ(alice.gateway.submitted_fanouts().size(), 2u);
    const auto& skd1_req = alice.gateway.submitted_fanouts()[0];
    const auto& grp1_req = alice.gateway.submitted_fanouts()[1];
    ASSERT_TRUE(grp1_req.group_envelope_bytes.has_value());

    // Deliver SKD(epoch=1) pairwise to Bob and Charlie
    for (const auto& payload : skd1_req.device_payloads) {
        if (payload.recipient_device_id == bob.did) {
            auto pt = bob.ratchet->decrypt_payload_from_device(alice.uid, alice.did, payload).value();
            const auto& raw = pt.expose_unredacted_secret();
            std::vector<uint8_t> bytes(raw.begin(), raw.end());
            auto dist = SenderKeyDistributionMessage::deserialize(bytes).value();
            ASSERT_TRUE(bob.messaging->process_inbound_sender_key_distribution(alice.uid, alice.did, dist).is_ok());
        } else if (payload.recipient_device_id == charlie.did) {
            auto pt = charlie.ratchet->decrypt_payload_from_device(alice.uid, alice.did, payload).value();
            const auto& raw = pt.expose_unredacted_secret();
            std::vector<uint8_t> bytes(raw.begin(), raw.end());
            auto dist = SenderKeyDistributionMessage::deserialize(bytes).value();
            ASSERT_TRUE(charlie.messaging->process_inbound_sender_key_distribution(alice.uid, alice.did, dist).is_ok());
        }
    }

    auto bob_in1 = bob.messaging->process_inbound_group_message(conv.conversation_id(), alice.uid, alice.did,
                                                                *grp1_req.group_envelope_bytes);
    auto charlie_in1 = charlie.messaging->process_inbound_group_message(conv.conversation_id(), alice.uid, alice.did,
                                                                        *grp1_req.group_envelope_bytes);
    ASSERT_TRUE(bob_in1.is_ok());
    ASSERT_TRUE(charlie_in1.is_ok());
    EXPECT_EQ(bob_in1.value().encrypted_envelope_ref(), epoch1_msg);
    EXPECT_EQ(charlie_in1.value().encrypted_envelope_ref(), epoch1_msg);

    // 3. Alice (Admin) removes Charlie & adds Dave -> epoch rotates 1 -> 2
    ASSERT_TRUE(alice.messaging->remove_group_participant(conv.conversation_id(), alice.uid, charlie.uid).is_ok());
    ASSERT_TRUE(alice.messaging->add_group_participant(conv.conversation_id(), alice.uid, dave.uid).is_ok());
    EXPECT_EQ(alice.messaging->get_conversation(conv.conversation_id()).value().sender_key_epoch(), 2u);

    alice.gateway.clear_submitted_fanouts();
    const std::string epoch2_msg = "Epoch 2: Post-removal rotated secret";
    auto send2 = alice.messaging->stage_outbound_message(conv.conversation_id(), alice.uid, alice.did, epoch2_msg);
    ASSERT_TRUE(send2.is_ok());
    EXPECT_EQ(send2.value().sender_key_epoch(), 2u);

    ASSERT_EQ(alice.gateway.submitted_fanouts().size(), 2u);
    const auto& skd2_req = alice.gateway.submitted_fanouts()[0];
    const auto& grp2_req = alice.gateway.submitted_fanouts()[1];
    ASSERT_TRUE(grp2_req.group_envelope_bytes.has_value());

    // SKD(epoch=2) only goes to Bob & Dave, NEVER Charlie
    for (const auto& payload : skd2_req.device_payloads) {
        EXPECT_NE(payload.recipient_device_id, charlie.did);
        if (payload.recipient_device_id == bob.did) {
            auto pt = bob.ratchet->decrypt_payload_from_device(alice.uid, alice.did, payload).value();
            const auto& raw = pt.expose_unredacted_secret();
            auto dist = SenderKeyDistributionMessage::deserialize(std::vector<uint8_t>(raw.begin(), raw.end())).value();
            ASSERT_TRUE(bob.messaging->process_inbound_sender_key_distribution(alice.uid, alice.did, dist).is_ok());
        } else if (payload.recipient_device_id == dave.did) {
            auto pt = dave.ratchet->decrypt_payload_from_device(alice.uid, alice.did, payload).value();
            const auto& raw = pt.expose_unredacted_secret();
            auto dist = SenderKeyDistributionMessage::deserialize(std::vector<uint8_t>(raw.begin(), raw.end())).value();
            ASSERT_TRUE(dave.messaging->process_inbound_sender_key_distribution(alice.uid, alice.did, dist).is_ok());
        }
    }

    // Bob & Dave decrypt epoch 2; Charlie fails to decrypt epoch 2; Dave fails to decrypt historical epoch 1
    auto bob_in2 = bob.messaging->process_inbound_group_message(conv.conversation_id(), alice.uid, alice.did,
                                                                *grp2_req.group_envelope_bytes);
    auto dave_in2 = dave.messaging->process_inbound_group_message(conv.conversation_id(), alice.uid, alice.did,
                                                                  *grp2_req.group_envelope_bytes);
    ASSERT_TRUE(bob_in2.is_ok());
    ASSERT_TRUE(dave_in2.is_ok());
    EXPECT_EQ(bob_in2.value().encrypted_envelope_ref(), epoch2_msg);
    EXPECT_EQ(dave_in2.value().encrypted_envelope_ref(), epoch2_msg);

    EXPECT_TRUE(charlie.messaging
                    ->process_inbound_group_message(conv.conversation_id(), alice.uid, alice.did,
                                                    *grp2_req.group_envelope_bytes)
                    .is_error());
    EXPECT_TRUE(dave.messaging
                    ->process_inbound_group_message(conv.conversation_id(), alice.uid, alice.did,
                                                    *grp1_req.group_envelope_bytes)
                    .is_error());
}

TEST(GroupMessagingPipelineTest, Adr008KeyChangedAndBlockedGuardsEnforcedOnGroupMessaging) {
    PeerNode alice("alice", "alice-dev-1");
    PeerNode bob("bob", "bob-dev-1");

    alice.gateway.set_simulated_user_directory(alice.uid, {alice.directory_entry()});
    alice.gateway.set_simulated_user_directory(bob.uid, {bob.directory_entry()});

    auto conv = alice.messaging->create_group_conversation(alice.uid, "Guarded", {bob.uid}).value();

    // KeyChanged on Bob halts outbound group messaging
    Contact bob_contact(bob.uid, "Bob", KeyVerificationStatus::KeyChanged);
    ASSERT_TRUE(alice.local_store.save_contact(bob_contact).is_ok());

    EXPECT_TRUE(
        alice.messaging->stage_outbound_message(conv.conversation_id(), alice.uid, alice.did, "Blocked").is_error());
    EXPECT_TRUE(alice.messaging->distribute_sender_key(conv.conversation_id(), alice.uid, alice.did).is_error());

    // Blocked sender on Bob drops inbound group distribution & envelope pre-decryption
    Contact alice_blocked(alice.uid, "Alice", KeyVerificationStatus::Verified, "fp", true);
    ASSERT_TRUE(bob.local_store.save_contact(alice_blocked).is_ok());

    const auto fake_env = std::vector<uint8_t>{'S', 'C', 'G', 0x01};
    EXPECT_TRUE(bob.messaging->process_inbound_group_message(conv.conversation_id(), alice.uid, alice.did, fake_env)
                    .is_error());
}

} // namespace
} // namespace securecloud::client::application::managers::test
