#include "application/client_config.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "domain/contact.hpp"
#include "domain/crypto/sender_key_models.hpp"
#include "domain/device_private_bundle.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::client::application::managers::test {
namespace {

using namespace domain;
using namespace domain::crypto;
using namespace infrastructure::adapters;

struct PersistentDeviceNode {
    UserId uid;
    DeviceId did;
    std::filesystem::path db_path;
    OpenSslCryptoProvider crypto;
    MemorySecureStorage storage;
    std::unique_ptr<SqlCipherLocalStore> local_store;
    DefaultGatewayClient gateway;
    std::unique_ptr<RatchetSessionManager> ratchet;
    std::unique_ptr<MessagingManager> messaging;
    std::vector<uint8_t> ik_pub;
    std::vector<uint8_t> spk_pub;
    std::vector<uint8_t> spk_sig;
    std::vector<uint8_t> otk_pub;
    std::string otk_id;

    PersistentDeviceNode(std::string u, std::string d, std::filesystem::path db_file)
        : uid(std::move(u)), did(std::move(d)), db_path(std::move(db_file)), gateway(ClientConfig::create_default()) {
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

        boot_subsystems();
    }

    void boot_subsystems() {
        local_store = std::make_unique<SqlCipherLocalStore>(storage, crypto);
        EXPECT_TRUE(local_store->open(db_path.string()).is_ok());
        ratchet = std::make_unique<RatchetSessionManager>(gateway, storage, crypto, uid, did);
        messaging = std::make_unique<MessagingManager>(gateway, *local_store, crypto, ratchet.get(), &storage);
    }

    void restart_workstation() {
        messaging.reset();
        ratchet.reset();
        if (local_store) {
            EXPECT_TRUE(local_store->close().is_ok());
            local_store.reset();
        }
        boot_subsystems();
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

class DirectAndGroupMessagingIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_e2e_msg_int_" + suffix);
        std::filesystem::create_directories(temp_dir_);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    static std::string read_raw_bytes(const std::filesystem::path& path) {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open()) {
            return {};
        }
        return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    }

    static void distribute_sender_key_pairwise(PersistentDeviceNode& sender,
                                               const interfaces::FanOutSubmissionRequest& skd_req,
                                               std::vector<PersistentDeviceNode*> recipients) {
        for (const auto& payload : skd_req.device_payloads) {
            for (auto* rec : recipients) {
                if (payload.recipient_device_id == rec->did) {
                    auto pt = rec->ratchet->decrypt_payload_from_device(sender.uid, sender.did, payload).value();
                    const auto& raw = pt.expose_unredacted_secret();
                    std::vector<uint8_t> bytes(raw.begin(), raw.end());
                    auto dist = SenderKeyDistributionMessage::deserialize(bytes).value();
                    ASSERT_TRUE(
                        rec->messaging->process_inbound_sender_key_distribution(sender.uid, sender.did, dist).is_ok());
                }
            }
        }
    }

    std::filesystem::path temp_dir_;
};

TEST_F(DirectAndGroupMessagingIntegrationTest, Scenario1MultiWorkstationDirectFanOutAndRestartDurability) {
    PersistentDeviceNode alice1("alice", "alice-dev-1", temp_dir_ / "alice1.db");
    PersistentDeviceNode alice2("alice", "alice-dev-2", temp_dir_ / "alice2.db");
    PersistentDeviceNode bob1("bob", "bob-dev-1", temp_dir_ / "bob1.db");
    PersistentDeviceNode bob2("bob", "bob-dev-2", temp_dir_ / "bob2.db");

    const std::vector<interfaces::DeviceCryptoDirectoryEntry> alice_dir{alice1.directory_entry(),
                                                                        alice2.directory_entry()};
    const std::vector<interfaces::DeviceCryptoDirectoryEntry> bob_dir{bob1.directory_entry(), bob2.directory_entry()};

    for (auto* node : {&alice1, &alice2, &bob1, &bob2}) {
        node->gateway.set_simulated_user_directory(alice1.uid, alice_dir);
        node->gateway.set_simulated_user_directory(bob1.uid, bob_dir);
    }

    auto conv = alice1.messaging->open_direct_conversation(alice1.uid, bob1.uid, "Bob").value();
    const std::string secret_one = "SCENARIO_1_SECRET_DIRECT_ALPHA_9481";

    auto send1 = alice1.messaging->stage_outbound_message(conv.conversation_id(), alice1.uid, alice1.did, secret_one);
    ASSERT_TRUE(send1.is_ok());

    ASSERT_EQ(alice1.gateway.submitted_fanouts().size(), 1u);
    const auto& req1 = alice1.gateway.submitted_fanouts()[0];
    // Multi-device fan-out: Bob's 2 devices + Alice's companion device (3 targets)
    ASSERT_EQ(req1.device_payloads.size(), 3u);
    for (const auto& payload : req1.device_payloads) {
        EXPECT_EQ(payload.ciphertext_blob.find(secret_one), std::string::npos);
        if (payload.recipient_device_id == alice2.did) {
            auto dec =
                alice2.messaging->process_inbound_message(conv.conversation_id(), alice1.uid, alice1.did, payload);
            ASSERT_TRUE(dec.is_ok());
            EXPECT_EQ(dec.value().encrypted_envelope_ref(), secret_one);
        } else if (payload.recipient_device_id == bob1.did) {
            auto dec = bob1.messaging->process_inbound_message(conv.conversation_id(), alice1.uid, alice1.did, payload);
            ASSERT_TRUE(dec.is_ok());
            EXPECT_EQ(dec.value().encrypted_envelope_ref(), secret_one);
        } else if (payload.recipient_device_id == bob2.did) {
            auto dec = bob2.messaging->process_inbound_message(conv.conversation_id(), alice1.uid, alice1.did, payload);
            ASSERT_TRUE(dec.is_ok());
            EXPECT_EQ(dec.value().encrypted_envelope_ref(), secret_one);
        } else {
            FAIL() << "Unexpected recipient device: " << payload.recipient_device_id.value();
        }
    }

    // Restart both workstations against SQLCipher + persistent ISecureStorage
    alice1.restart_workstation();
    bob1.restart_workstation();

    // Verify raw SQLCipher .db files contain zero plaintext
    const std::string alice_raw = read_raw_bytes(alice1.db_path);
    const std::string bob_raw = read_raw_bytes(bob1.db_path);
    EXPECT_FALSE(alice_raw.empty());
    EXPECT_FALSE(bob_raw.empty());
    EXPECT_EQ(alice_raw.find(secret_one), std::string::npos);
    EXPECT_EQ(bob_raw.find(secret_one), std::string::npos);

    // Verify persisted history survives restart and post-restart messaging continues cleanly
    auto alice_msgs = alice1.messaging->get_conversation_messages(conv.conversation_id(), 50).value();
    auto bob_msgs = bob1.messaging->get_conversation_messages(conv.conversation_id(), 50).value();
    ASSERT_EQ(alice_msgs.size(), 1u);
    ASSERT_EQ(bob_msgs.size(), 1u);
    EXPECT_EQ(alice_msgs[0].encrypted_envelope_ref(), secret_one);
    EXPECT_EQ(bob_msgs[0].encrypted_envelope_ref(), secret_one);

    const std::string secret_two = "SCENARIO_1_POST_RESTART_BETA_7712";
    auto send2 = alice1.messaging->stage_outbound_message(conv.conversation_id(), alice1.uid, alice1.did, secret_two);
    ASSERT_TRUE(send2.is_ok());
    const auto& req2 = alice1.gateway.submitted_fanouts().back();
    for (const auto& payload : req2.device_payloads) {
        if (payload.recipient_device_id == bob1.did) {
            auto dec = bob1.messaging->process_inbound_message(conv.conversation_id(), alice1.uid, alice1.did, payload);
            ASSERT_TRUE(dec.is_ok());
            EXPECT_EQ(dec.value().encrypted_envelope_ref(), secret_two);
        }
    }
}

TEST_F(DirectAndGroupMessagingIntegrationTest, Scenario2GroupMessagingDistributionAndOutOfOrderMultiDeviceDecryption) {
    PersistentDeviceNode alice1("alice", "alice-dev-1", temp_dir_ / "alice1.db");
    PersistentDeviceNode bob1("bob", "bob-dev-1", temp_dir_ / "bob1.db");
    PersistentDeviceNode bob2("bob", "bob-dev-2", temp_dir_ / "bob2.db");
    PersistentDeviceNode charlie1("charlie", "charlie-dev-1", temp_dir_ / "charlie1.db");

    const std::vector<interfaces::DeviceCryptoDirectoryEntry> alice_dir{alice1.directory_entry()};
    const std::vector<interfaces::DeviceCryptoDirectoryEntry> bob_dir{bob1.directory_entry(), bob2.directory_entry()};
    const std::vector<interfaces::DeviceCryptoDirectoryEntry> charlie_dir{charlie1.directory_entry()};

    alice1.gateway.set_simulated_user_directory(alice1.uid, alice_dir);
    alice1.gateway.set_simulated_user_directory(bob1.uid, bob_dir);
    alice1.gateway.set_simulated_user_directory(charlie1.uid, charlie_dir);

    auto conv =
        alice1.messaging->create_group_conversation(alice1.uid, "SecOps Alpha", {bob1.uid, charlie1.uid}).value();

    const std::string msg1 = "SCENARIO_2_GROUP_MSG_ONE";
    const std::string msg2 = "SCENARIO_2_GROUP_MSG_TWO";
    ASSERT_TRUE(alice1.messaging->stage_outbound_message(conv.conversation_id(), alice1.uid, alice1.did, msg1).is_ok());
    ASSERT_TRUE(alice1.messaging->stage_outbound_message(conv.conversation_id(), alice1.uid, alice1.did, msg2).is_ok());

    ASSERT_EQ(alice1.gateway.submitted_fanouts().size(), 3u); // SKD(1), Group(1), Group(2)
    const auto& skd_req = alice1.gateway.submitted_fanouts()[0];
    const auto& grp_req1 = alice1.gateway.submitted_fanouts()[1];
    const auto& grp_req2 = alice1.gateway.submitted_fanouts()[2];
    ASSERT_TRUE(grp_req1.group_envelope_bytes.has_value());
    ASSERT_TRUE(grp_req2.group_envelope_bytes.has_value());

    distribute_sender_key_pairwise(alice1, skd_req, {&bob1, &bob2, &charlie1});

    // In-order decryption on bob1 and charlie1
    EXPECT_EQ(bob1.messaging
                  ->process_inbound_group_message(conv.conversation_id(), alice1.uid, alice1.did,
                                                  *grp_req1.group_envelope_bytes)
                  .value()
                  .encrypted_envelope_ref(),
              msg1);
    EXPECT_EQ(bob1.messaging
                  ->process_inbound_group_message(conv.conversation_id(), alice1.uid, alice1.did,
                                                  *grp_req2.group_envelope_bytes)
                  .value()
                  .encrypted_envelope_ref(),
              msg2);
    EXPECT_EQ(charlie1.messaging
                  ->process_inbound_group_message(conv.conversation_id(), alice1.uid, alice1.did,
                                                  *grp_req1.group_envelope_bytes)
                  .value()
                  .encrypted_envelope_ref(),
              msg1);

    // Out-of-order decryption on bob2 (msg2 arrives before msg1)
    EXPECT_EQ(bob2.messaging
                  ->process_inbound_group_message(conv.conversation_id(), alice1.uid, alice1.did,
                                                  *grp_req2.group_envelope_bytes)
                  .value()
                  .encrypted_envelope_ref(),
              msg2);
    EXPECT_EQ(bob2.messaging
                  ->process_inbound_group_message(conv.conversation_id(), alice1.uid, alice1.did,
                                                  *grp_req1.group_envelope_bytes)
                  .value()
                  .encrypted_envelope_ref(),
              msg1);
}

TEST_F(DirectAndGroupMessagingIntegrationTest, Scenario3MembershipRemovalNonAdminRbacAndMandatoryRotation) {
    PersistentDeviceNode alice1("alice", "alice-dev-1", temp_dir_ / "alice1.db");
    PersistentDeviceNode bob1("bob", "bob-dev-1", temp_dir_ / "bob1.db");
    PersistentDeviceNode charlie1("charlie", "charlie-dev-1", temp_dir_ / "charlie1.db");

    alice1.gateway.set_simulated_user_directory(alice1.uid, {alice1.directory_entry()});
    alice1.gateway.set_simulated_user_directory(bob1.uid, {bob1.directory_entry()});
    alice1.gateway.set_simulated_user_directory(charlie1.uid, {charlie1.directory_entry()});

    auto conv = alice1.messaging->create_group_conversation(alice1.uid, "RBAC Ops", {bob1.uid, charlie1.uid}).value();
    ASSERT_TRUE(charlie1.local_store->save_conversation(conv).is_ok());

    // Charlie (Member) cannot remove Bob
    EXPECT_TRUE(
        charlie1.messaging->remove_group_participant(conv.conversation_id(), charlie1.uid, bob1.uid).is_error());

    // Alice sends epoch 1 message
    ASSERT_TRUE(
        alice1.messaging->stage_outbound_message(conv.conversation_id(), alice1.uid, alice1.did, "Epoch1").is_ok());
    distribute_sender_key_pairwise(alice1, alice1.gateway.submitted_fanouts()[0], {&bob1, &charlie1});

    // Alice (Admin) removes Charlie -> epoch rotates 1 -> 2
    ASSERT_TRUE(alice1.messaging->remove_group_participant(conv.conversation_id(), alice1.uid, charlie1.uid).is_ok());
    EXPECT_EQ(alice1.messaging->get_conversation(conv.conversation_id()).value().sender_key_epoch(), 2u);

    alice1.gateway.clear_submitted_fanouts();
    const std::string epoch2_secret = "SCENARIO_3_POST_REMOVAL_EPOCH2";
    ASSERT_TRUE(alice1.messaging->stage_outbound_message(conv.conversation_id(), alice1.uid, alice1.did, epoch2_secret)
                    .is_ok());
    ASSERT_EQ(alice1.gateway.submitted_fanouts().size(), 2u);
    const auto& skd2 = alice1.gateway.submitted_fanouts()[0];
    const auto& grp2 = alice1.gateway.submitted_fanouts()[1];
    for (const auto& payload : skd2.device_payloads) {
        EXPECT_NE(payload.recipient_device_id, charlie1.did);
    }
    distribute_sender_key_pairwise(alice1, skd2, {&bob1});

    EXPECT_EQ(
        bob1.messaging
            ->process_inbound_group_message(conv.conversation_id(), alice1.uid, alice1.did, *grp2.group_envelope_bytes)
            .value()
            .encrypted_envelope_ref(),
        epoch2_secret);
    EXPECT_TRUE(
        charlie1.messaging
            ->process_inbound_group_message(conv.conversation_id(), alice1.uid, alice1.did, *grp2.group_envelope_bytes)
            .is_error());
}

TEST_F(DirectAndGroupMessagingIntegrationTest, Scenario4LateJoinMemberForwardSecrecyBoundary) {
    PersistentDeviceNode alice1("alice", "alice-dev-1", temp_dir_ / "alice1.db");
    PersistentDeviceNode bob1("bob", "bob-dev-1", temp_dir_ / "bob1.db");
    PersistentDeviceNode charlie1("charlie", "charlie-dev-1", temp_dir_ / "charlie1.db");
    PersistentDeviceNode dave1("dave", "dave-dev-1", temp_dir_ / "dave1.db");

    alice1.gateway.set_simulated_user_directory(alice1.uid, {alice1.directory_entry()});
    alice1.gateway.set_simulated_user_directory(bob1.uid, {bob1.directory_entry()});
    alice1.gateway.set_simulated_user_directory(charlie1.uid, {charlie1.directory_entry()});
    alice1.gateway.set_simulated_user_directory(dave1.uid, {dave1.directory_entry()});

    auto conv =
        alice1.messaging->create_group_conversation(alice1.uid, "Secrecy Boundary", {bob1.uid, charlie1.uid}).value();

    ASSERT_TRUE(
        alice1.messaging->stage_outbound_message(conv.conversation_id(), alice1.uid, alice1.did, "Epoch1 Secret")
            .is_ok());
    const auto& skd1 = alice1.gateway.submitted_fanouts()[0];
    const auto grp1_bytes = *alice1.gateway.submitted_fanouts()[1].group_envelope_bytes;
    distribute_sender_key_pairwise(alice1, skd1, {&bob1, &charlie1});

    // Charlie is removed and Dave joins at epoch 2
    ASSERT_TRUE(alice1.messaging->remove_group_participant(conv.conversation_id(), alice1.uid, charlie1.uid).is_ok());
    ASSERT_TRUE(alice1.messaging->add_group_participant(conv.conversation_id(), alice1.uid, dave1.uid).is_ok());
    EXPECT_EQ(alice1.messaging->get_conversation(conv.conversation_id()).value().sender_key_epoch(), 2u);

    alice1.gateway.clear_submitted_fanouts();
    const std::string epoch2_secret = "SCENARIO_4_EPOCH2_LATE_JOIN_OK";
    ASSERT_TRUE(alice1.messaging->stage_outbound_message(conv.conversation_id(), alice1.uid, alice1.did, epoch2_secret)
                    .is_ok());
    const auto& skd2 = alice1.gateway.submitted_fanouts()[0];
    const auto grp2_bytes = *alice1.gateway.submitted_fanouts()[1].group_envelope_bytes;
    distribute_sender_key_pairwise(alice1, skd2, {&bob1, &dave1});

    auto dave_in2 =
        dave1.messaging->process_inbound_group_message(conv.conversation_id(), alice1.uid, alice1.did, grp2_bytes);
    ASSERT_TRUE(dave_in2.is_ok()) << dave_in2.error().user_message();
    EXPECT_EQ(dave_in2.value().encrypted_envelope_ref(), epoch2_secret);
    // Dave cannot decrypt historical epoch 1 ciphertext captured before his join
    EXPECT_TRUE(
        dave1.messaging->process_inbound_group_message(conv.conversation_id(), alice1.uid, alice1.did, grp1_bytes)
            .is_error());
}

TEST_F(DirectAndGroupMessagingIntegrationTest, Scenario5Adr008GuardsAndTamperedDbOrEnvelopeFailClosed) {
    PersistentDeviceNode alice1("alice", "alice-dev-1", temp_dir_ / "alice1.db");
    PersistentDeviceNode bob1("bob", "bob-dev-1", temp_dir_ / "bob1.db");

    alice1.gateway.set_simulated_user_directory(alice1.uid, {alice1.directory_entry()});
    alice1.gateway.set_simulated_user_directory(bob1.uid, {bob1.directory_entry()});

    auto direct_conv = alice1.messaging->open_direct_conversation(alice1.uid, bob1.uid, "Bob").value();
    auto group_conv = alice1.messaging->create_group_conversation(alice1.uid, "Guarded Group", {bob1.uid}).value();

    // 1. ADR-008 KeyChanged halts both 1:1 and group sends until acknowledged
    Contact bob_changed(bob1.uid, "Bob", KeyVerificationStatus::KeyChanged, "old-fp", false);
    ASSERT_TRUE(alice1.local_store->save_contact(bob_changed).is_ok());

    EXPECT_TRUE(
        alice1.messaging->stage_outbound_message(direct_conv.conversation_id(), alice1.uid, alice1.did, "Blocked 1:1")
            .is_error());
    EXPECT_TRUE(
        alice1.messaging->stage_outbound_message(group_conv.conversation_id(), alice1.uid, alice1.did, "Blocked group")
            .is_error());

    // Acknowledge & verify key change restores outbound sends
    bob_changed.set_verification_status(KeyVerificationStatus::Verified);
    ASSERT_TRUE(alice1.local_store->save_contact(bob_changed).is_ok());
    ASSERT_TRUE(
        alice1.messaging->stage_outbound_message(group_conv.conversation_id(), alice1.uid, alice1.did, "Allowed group")
            .is_ok());
    const auto valid_grp_bytes = *alice1.gateway.submitted_fanouts().back().group_envelope_bytes;

    // 2. Tampered SCG envelope fails closed on Bob
    auto tampered = valid_grp_bytes;
    tampered.back() ^= 0xFF;
    distribute_sender_key_pairwise(alice1, alice1.gateway.submitted_fanouts()[0], {&bob1});
    EXPECT_TRUE(
        bob1.messaging->process_inbound_group_message(group_conv.conversation_id(), alice1.uid, alice1.did, tampered)
            .is_error());

    // 3. Blocked sender drops inbound group packet pre-decryption
    Contact alice_blocked(alice1.uid, "Alice", KeyVerificationStatus::Verified, "fp", true);
    ASSERT_TRUE(bob1.local_store->save_contact(alice_blocked).is_ok());
    EXPECT_TRUE(
        bob1.messaging
            ->process_inbound_group_message(group_conv.conversation_id(), alice1.uid, alice1.did, valid_grp_bytes)
            .is_error());

    // 4. Opening existing SqlCipherLocalStore with wrong master key fails closed
    ASSERT_TRUE(alice1.local_store->close().is_ok());
    MemorySecureStorage wrong_storage;
    ASSERT_TRUE(wrong_storage
                    .store_secret(SqlCipherLocalStore::kMasterKeyId,
                                  common::configuration::SecretString(
                                      "0000000000000000000000000000000000000000000000000000000000000000"))
                    .is_ok());
    SqlCipherLocalStore wrong_store(wrong_storage, alice1.crypto);
    EXPECT_TRUE(wrong_store.open(alice1.db_path.string()).is_error());
}

} // namespace
} // namespace securecloud::client::application::managers::test
