#include "application/client_config.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "domain/crypto/sender_key_models.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/file_transfer.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::client::application::managers::test {
namespace {

using namespace domain;
using namespace infrastructure::adapters;
using namespace std::chrono_literals;

struct PeerCryptoFixture {
    UserId user_id;
    DeviceId device_id;
    MemorySecureStorage storage;
    interfaces::DeviceCryptoDirectoryEntry dir_entry;
};

void init_peer_fixture(PeerCryptoFixture& peer, OpenSslCryptoProvider& crypto, const std::string& uid,
                       const std::string& did) {
    peer.user_id = UserId(uid);
    peer.device_id = DeviceId(did);

    auto ik = crypto.generate_identity_keypair().value();
    auto spk = crypto.generate_signed_prekey(ik.private_key).value();
    auto otk = crypto.generate_dh_keypair().value();

    DevicePrivateBundle bundle(peer.device_id, ik.public_key, std::move(ik.private_key), spk.public_key,
                               std::move(spk.private_key), spk.signature);
    bundle.add_one_time_prekey(did + "-otk-1", std::move(otk.private_key));
    EXPECT_TRUE(KeyStorageHelper::save_bundle(peer.storage, bundle).is_ok());

    peer.dir_entry = interfaces::DeviceCryptoDirectoryEntry{
        .device_id = peer.device_id,
        .identity_key = ik.public_key,
        .signed_prekey = spk.public_key,
        .signed_prekey_signature = spk.signature,
        .one_time_prekey = otk.public_key,
        .one_time_prekey_id = did + "-otk-1",
        .identity_key_fingerprint = "",
    };
}

class OfflineOutboxReplayTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("securecloud_outbox_replay_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = (temp_dir_ / "client_vault.db").string();
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    std::filesystem::path write_temp_file(const std::string& name, std::size_t bytes, uint8_t fill) {
        const auto p = temp_dir_ / name;
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        std::vector<char> buf(bytes, static_cast<char>(fill));
        out.write(buf.data(), static_cast<std::streamsize>(buf.size()));
        out.close();
        return p;
    }

    std::filesystem::path temp_dir_;
    std::string db_path_;
};

TEST_F(OfflineOutboxReplayTest, DirectAndGroupMessagesSurviveRestartAndReplayWithoutResteppingRatchets) {
    OpenSslCryptoProvider crypto;
    DefaultGatewayClient gateway(ClientConfig::create_default());

    PeerCryptoFixture alice;
    PeerCryptoFixture bob;
    init_peer_fixture(alice, crypto, "alice", "alice-dev-1");
    init_peer_fixture(bob, crypto, "bob", "bob-dev-1");
    gateway.set_simulated_user_directory(alice.user_id, {alice.dir_entry});
    gateway.set_simulated_user_directory(bob.user_id, {bob.dir_entry});

    MemoryLocalStore bob_store;
    ASSERT_TRUE(bob_store.open("bob-mem").is_ok());
    RatchetSessionManager bob_ratchet(gateway, bob.storage, crypto, bob.user_id, bob.device_id);
    MessagingManager bob_mm(gateway, bob_store, crypto, &bob_ratchet, &bob.storage);

    ConversationId direct_cid;
    ConversationId group_cid;
    uint64_t group_epoch = 0;
    std::string direct_idem_key;
    std::string group_idem_key;
    MessageId direct_mid;
    MessageId group_mid;

    std::string ratchet_state_snapshot;
    std::string sender_key_snapshot;

    {
        SqlCipherLocalStore alice_store(alice.storage, crypto);
        ASSERT_TRUE(alice_store.open(db_path_).is_ok());
        RatchetSessionManager alice_ratchet(gateway, alice.storage, crypto, alice.user_id, alice.device_id);
        MessagingManager alice_mm(gateway, alice_store, crypto, &alice_ratchet, &alice.storage);

        auto direct_conv = alice_mm.open_direct_conversation(alice.user_id, bob.user_id, "Bob").value();
        direct_cid = direct_conv.conversation_id();
        ASSERT_TRUE(bob_mm.open_direct_conversation(bob.user_id, alice.user_id, "Alice").is_ok());

        // Establish pairwise X3DH / Double Ratchet session online first
        auto warmup = alice_mm.stage_outbound_message(direct_cid, alice.user_id, alice.device_id, "Warmup");
        ASSERT_TRUE(warmup.is_ok());
        ASSERT_EQ(gateway.submitted_fanouts().size(), 1U);
        ASSERT_TRUE(bob_mm
                        .process_inbound_message(direct_cid, alice.user_id, alice.device_id,
                                                 gateway.submitted_fanouts()[0].device_payloads[0])
                        .is_ok());
        gateway.clear_submitted_fanouts();

        // Create a brand-new group conversation before going offline
        auto group_conv = alice_mm.create_group_conversation(alice.user_id, "Ops Offline Group", {bob.user_id}).value();
        group_cid = group_conv.conversation_id();
        group_epoch = group_conv.sender_key_epoch();
        ASSERT_TRUE(bob_store.save_conversation(group_conv).is_ok());

        // Go offline and draft both a 1:1 message and the first-ever group message (triggers SKD + group msg)
        alice_mm.set_offline_mode(true);
        gateway.set_simulated_submission_failure(true, "Offline");

        auto direct_staged =
            alice_mm.stage_outbound_message(direct_cid, alice.user_id, alice.device_id, "Offline 1:1 secret");
        ASSERT_TRUE(direct_staged.is_ok());
        EXPECT_EQ(direct_staged.value().delivery_state(), DeliveryState::LocalPending);
        direct_idem_key = direct_staged.value().idempotency_key();
        direct_mid = direct_staged.value().message_id();

        auto group_staged =
            alice_mm.stage_outbound_message(group_cid, alice.user_id, alice.device_id, "Offline group launch");
        ASSERT_TRUE(group_staged.is_ok());
        EXPECT_EQ(group_staged.value().delivery_state(), DeliveryState::LocalPending);
        group_idem_key = group_staged.value().idempotency_key();
        group_mid = group_staged.value().message_id();

        EXPECT_TRUE(gateway.submitted_fanouts().empty());
        EXPECT_EQ(alice_mm.pending_outbox_count(), 3U); // 1:1 msg + group SKD + group msg

        // Snapshot persisted cryptographic state right after offline encryption
        const std::string ratchet_key = "ratchet_session:" + bob.user_id.value() + ":" + bob.device_id.value();
        auto r_snap = alice.storage.get_secret(ratchet_key);
        ASSERT_TRUE(r_snap.is_ok());
        ratchet_state_snapshot = r_snap.value().expose_unredacted_secret();

        const crypto::SenderKeyId sk_id{
            .conversation_id = group_cid,
            .sender_user_id = alice.user_id,
            .sender_device_id = alice.device_id,
            .key_epoch = group_epoch,
        };
        auto sk_snap = alice.storage.get_secret(sk_id.storage_key());
        ASSERT_TRUE(sk_snap.is_ok());
        sender_key_snapshot = sk_snap.value().expose_unredacted_secret();

        ASSERT_TRUE(alice_store.close().is_ok());
    }

    // Full app restart against the same encrypted SQLCipher database
    SqlCipherLocalStore reopened_store(alice.storage, crypto);
    ASSERT_TRUE(reopened_store.open(db_path_).is_ok());
    RatchetSessionManager restarted_ratchet(gateway, alice.storage, crypto, alice.user_id, alice.device_id);
    MessagingManager restarted_mm(gateway, reopened_store, crypto, &restarted_ratchet, &alice.storage);

    EXPECT_EQ(restarted_mm.pending_outbox_count(), 3U);
    EXPECT_EQ(restarted_mm.pending_retry_count(), 2U);

    // Reconnect and flush outbox
    gateway.set_simulated_submission_failure(false);
    const std::size_t flushed = restarted_mm.flush_offline_outbox();
    EXPECT_EQ(flushed, 3U);
    EXPECT_EQ(restarted_mm.pending_outbox_count(), 0U);
    EXPECT_EQ(restarted_mm.pending_retry_count(), 0U);

    // Cryptographic Safety Invariant (ADR-008): ratchets must NOT have stepped a second time during replay
    const std::string ratchet_key = "ratchet_session:" + bob.user_id.value() + ":" + bob.device_id.value();
    EXPECT_EQ(alice.storage.get_secret(ratchet_key).value().expose_unredacted_secret(), ratchet_state_snapshot);

    const crypto::SenderKeyId sk_id{
        .conversation_id = group_cid,
        .sender_user_id = alice.user_id,
        .sender_device_id = alice.device_id,
        .key_epoch = group_epoch,
    };
    EXPECT_EQ(alice.storage.get_secret(sk_id.storage_key()).value().expose_unredacted_secret(), sender_key_snapshot);

    // Local delivery states transitioned monotonically to Accepted
    EXPECT_EQ(reopened_store.get_message(direct_cid, direct_mid).value().delivery_state(), DeliveryState::Accepted);
    EXPECT_EQ(reopened_store.get_message(group_cid, group_mid).value().delivery_state(), DeliveryState::Accepted);

    // Verify wire submissions preserve original idempotency keys and Bob decrypts both 1:1 and Group messages
    const auto& fanouts = gateway.submitted_fanouts();
    ASSERT_EQ(fanouts.size(), 3U);

    int skd_index = -1;
    int group_index = -1;
    for (int i = 0; i < static_cast<int>(fanouts.size()); ++i) {
        const auto& req = fanouts[static_cast<std::size_t>(i)];
        if (req.idempotency_key == direct_idem_key) {
            ASSERT_EQ(req.device_payloads.size(), 1U);
            auto dec =
                bob_mm.process_inbound_message(direct_cid, alice.user_id, alice.device_id, req.device_payloads[0]);
            ASSERT_TRUE(dec.is_ok());
            EXPECT_EQ(dec.value().encrypted_envelope_ref(), "Offline 1:1 secret");
        } else if (req.idempotency_key == group_idem_key + "-skd") {
            skd_index = i;
            ASSERT_EQ(req.device_payloads.size(), 1U);
            auto dec_skd =
                bob_ratchet.decrypt_payload_from_device(alice.user_id, alice.device_id, req.device_payloads[0]);
            ASSERT_TRUE(dec_skd.is_ok());
            const std::string raw = dec_skd.value().expose_unredacted_secret();
            std::vector<uint8_t> skd_bytes(raw.begin(), raw.end());
            auto dist_msg = crypto::SenderKeyDistributionMessage::deserialize(skd_bytes);
            ASSERT_TRUE(dist_msg.is_ok());
            ASSERT_TRUE(bob_mm.process_inbound_sender_key_distribution(alice.user_id, alice.device_id, dist_msg.value())
                            .is_ok());
        } else if (req.idempotency_key == group_idem_key) {
            group_index = i;
            ASSERT_TRUE(req.group_envelope_bytes.has_value());
            auto dec_grp = bob_mm.process_inbound_group_message(group_cid, alice.user_id, alice.device_id,
                                                                *req.group_envelope_bytes);
            ASSERT_TRUE(dec_grp.is_ok());
            EXPECT_EQ(dec_grp.value().encrypted_envelope_ref(), "Offline group launch");
        }
    }
    EXPECT_GE(skd_index, 0);
    EXPECT_GE(group_index, 0);
    EXPECT_LT(skd_index, group_index);
}

TEST_F(OfflineOutboxReplayTest, OfflineDeliveryAcksAndPrivacyGatedReadReceiptsFlushAndSuppress) {
    OpenSslCryptoProvider crypto;
    MemorySecureStorage alice_storage;
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const UserId alice("alice");
    const DeviceId alice_dev("alice-dev-1");
    const UserId bob("bob");
    const DeviceId bob_dev("bob-dev-1");
    ConversationId cid;

    {
        SqlCipherLocalStore store(alice_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        MessagingManager mm(gateway, store, crypto, nullptr, &alice_storage);
        mm.set_local_device_id(alice_dev);
        ASSERT_TRUE(mm.set_read_receipts_enabled(true).is_ok());

        cid = mm.open_direct_conversation(alice, bob, "Bob").value().conversation_id();

        // Go offline -> inbound message queues DeliveryAck, reading queues ReadReceipt while clearing unread_count
        mm.set_offline_mode(true);
        gateway.set_simulated_failure(true, "Offline");

        RealtimeEvent ev1;
        ev1.type = RealtimeEventType::InboundDirectMessage;
        ev1.conversation_id = cid;
        ev1.message_id = MessageId("msg-in-ack-1");
        ev1.actor_user_id = bob;
        ev1.actor_device_id = bob_dev;
        ev1.server_sequence_number = 10ULL;
        ev1.direct_payload = crypto::PerDeviceDeliveryPayload{
            .recipient_user_id = {},
            .recipient_device_id = alice_dev,
            .ciphertext_blob = crypto.encrypt_message(bob_dev, "Hello offline").value(),
            .ephemeral_public_key = {},
            .iv = {},
            .auth_tag = {},
        };
        ASSERT_TRUE(mm.process_inbound_realtime_event(ev1).is_ok());
        EXPECT_TRUE(gateway.sent_delivery_acks().empty());

        ASSERT_TRUE(mm.mark_conversation_read(cid, alice, alice_dev).is_ok());
        EXPECT_EQ(mm.get_conversation(cid).value().unread_count(), 0U);
        EXPECT_TRUE(gateway.sent_read_receipts().empty());
        EXPECT_EQ(mm.pending_outbox_count(), 2U); // 1 DeliveryAck + 1 ReadReceipt

        ASSERT_TRUE(store.close().is_ok());
    }

    // Restart, disable read receipts BEFORE flushing -> DeliveryAck flushes, ReadReceipt is purged
    {
        SqlCipherLocalStore reopened(alice_storage, crypto);
        ASSERT_TRUE(reopened.open(db_path_).is_ok());
        MessagingManager mm(gateway, reopened, crypto, nullptr, &alice_storage);
        mm.set_local_device_id(alice_dev);

        ASSERT_TRUE(mm.set_read_receipts_enabled(false).is_ok());
        EXPECT_EQ(mm.pending_outbox_count(), 1U);

        gateway.set_simulated_failure(false);
        EXPECT_EQ(mm.flush_offline_outbox(), 1U);
        ASSERT_EQ(gateway.sent_delivery_acks().size(), 1U);
        EXPECT_EQ(gateway.sent_delivery_acks()[0].message_id, MessageId("msg-in-ack-1"));
        EXPECT_TRUE(gateway.sent_read_receipts().empty());

        // Re-enable read receipts, receive msg-in-ack-2 offline, mark read, then flush online -> both flush
        ASSERT_TRUE(mm.set_read_receipts_enabled(true).is_ok());
        mm.set_offline_mode(true);
        RealtimeEvent ev2;
        ev2.type = RealtimeEventType::InboundDirectMessage;
        ev2.conversation_id = cid;
        ev2.message_id = MessageId("msg-in-ack-2");
        ev2.actor_user_id = bob;
        ev2.actor_device_id = bob_dev;
        ev2.server_sequence_number = 11ULL;
        ev2.direct_payload = crypto::PerDeviceDeliveryPayload{
            .recipient_user_id = {},
            .recipient_device_id = alice_dev,
            .ciphertext_blob = crypto.encrypt_message(bob_dev, "Second offline").value(),
            .ephemeral_public_key = {},
            .iv = {},
            .auth_tag = {},
        };
        ASSERT_TRUE(mm.process_inbound_realtime_event(ev2).is_ok());
        ASSERT_TRUE(mm.mark_conversation_read(cid, alice, alice_dev).is_ok());
        EXPECT_EQ(mm.pending_outbox_count(), 2U);

        mm.set_offline_mode(false);
        EXPECT_EQ(mm.flush_offline_outbox(), 2U);
        EXPECT_EQ(gateway.sent_delivery_acks().size(), 2U);
        ASSERT_EQ(gateway.sent_read_receipts().size(), 1U);
        EXPECT_EQ(gateway.sent_read_receipts()[0].message_id, MessageId("msg-in-ack-2"));
    }
}

TEST_F(OfflineOutboxReplayTest, PriorityAndFifoDrainOrderAndExpirationWithPostRestartManualRetry) {
    OpenSslCryptoProvider crypto;
    DefaultGatewayClient gateway(ClientConfig::create_default());

    PeerCryptoFixture alice;
    PeerCryptoFixture bob;
    init_peer_fixture(alice, crypto, "alice", "alice-dev-1");
    init_peer_fixture(bob, crypto, "bob", "bob-dev-1");
    PeerCryptoFixture charlie;
    init_peer_fixture(charlie, crypto, "charlie", "charlie-dev-1");
    gateway.set_simulated_user_directory(bob.user_id, {bob.dir_entry});
    gateway.set_simulated_user_directory(charlie.user_id, {charlie.dir_entry});

    ConversationId conv_bob_id;
    ConversationId conv_charlie_id;
    std::string norm1_idem;
    std::string norm2_idem;
    std::string urgent_idem;
    std::string emerg_idem;
    MessageId failed_mid;
    std::string failed_idem;

    {
        SqlCipherLocalStore store(alice.storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        RatchetSessionManager ratchet(gateway, alice.storage, crypto, alice.user_id, alice.device_id);
        MessagingManager mm(gateway, store, crypto, &ratchet, &alice.storage);

        conv_bob_id = mm.open_direct_conversation(alice.user_id, bob.user_id, "Bob").value().conversation_id();
        conv_charlie_id =
            mm.open_direct_conversation(alice.user_id, charlie.user_id, "Charlie").value().conversation_id();

        // Warm up sessions
        ASSERT_TRUE(mm.stage_outbound_message(conv_bob_id, alice.user_id, alice.device_id, "Warm Bob").is_ok());
        ASSERT_TRUE(mm.stage_outbound_message(conv_charlie_id, alice.user_id, alice.device_id, "Warm Charlie").is_ok());
        gateway.clear_submitted_fanouts();

        // Queue mixed priority messages while offline
        mm.set_offline_mode(true);
        norm1_idem = mm.stage_outbound_message(conv_bob_id, alice.user_id, alice.device_id, "Normal 1", 0)
                         .value()
                         .idempotency_key();
        std::this_thread::sleep_for(2ms);
        norm2_idem = mm.stage_outbound_message(conv_bob_id, alice.user_id, alice.device_id, "Normal 2", 0)
                         .value()
                         .idempotency_key();
        std::this_thread::sleep_for(2ms);
        urgent_idem = mm.stage_outbound_message(conv_charlie_id, alice.user_id, alice.device_id, "Urgent", 2)
                          .value()
                          .idempotency_key();
        std::this_thread::sleep_for(2ms);
        emerg_idem = mm.stage_outbound_message(conv_charlie_id, alice.user_id, alice.device_id, "Emergency", 3)
                         .value()
                         .idempotency_key();

        // Flush -> Emergency (3) -> Urgent (2) -> Normal 1 (0, earlier) -> Normal 2 (0, later)
        mm.set_offline_mode(false);
        EXPECT_EQ(mm.flush_offline_outbox(), 4U);
        ASSERT_EQ(gateway.submitted_fanouts().size(), 4U);
        EXPECT_EQ(gateway.submitted_fanouts()[0].idempotency_key, emerg_idem);
        EXPECT_EQ(gateway.submitted_fanouts()[1].idempotency_key, urgent_idem);
        EXPECT_EQ(gateway.submitted_fanouts()[2].idempotency_key, norm1_idem);
        EXPECT_EQ(gateway.submitted_fanouts()[3].idempotency_key, norm2_idem);
        gateway.clear_submitted_fanouts();

        // Test expiration -> Failed state + pending counts drop to 0, while manual retry payload survives restart
        RetryPolicyConfig cfg;
        cfg.initial_backoff = 50ms;
        cfg.max_backoff = 200ms;
        cfg.max_attempts = 2;
        mm.set_retry_policy(cfg);

        gateway.set_simulated_submission_failure(true, "Persistent outage");
        auto exp_msg = mm.stage_outbound_message(conv_bob_id, alice.user_id, alice.device_id, "Expires then retried");
        ASSERT_TRUE(exp_msg.is_ok());
        failed_mid = exp_msg.value().message_id();
        failed_idem = exp_msg.value().idempotency_key();

        mm.process_retry_queue(std::chrono::steady_clock::now() + 1s);
        EXPECT_EQ(mm.pending_retry_count(), 0U);
        EXPECT_EQ(mm.pending_outbox_count(), 0U);
        EXPECT_EQ(store.get_message(conv_bob_id, failed_mid).value().delivery_state(), DeliveryState::Failed);

        ASSERT_TRUE(store.close().is_ok());
    }

    // Restart and manually retry the failed message -> replays original ciphertext & idempotency_key
    SqlCipherLocalStore reopened(alice.storage, crypto);
    ASSERT_TRUE(reopened.open(db_path_).is_ok());
    RatchetSessionManager restarted_ratchet(gateway, alice.storage, crypto, alice.user_id, alice.device_id);
    MessagingManager restarted_mm(gateway, reopened, crypto, &restarted_ratchet, &alice.storage);

    gateway.set_simulated_submission_failure(false);
    auto retried = restarted_mm.retry_failed_message(conv_bob_id, failed_mid);
    ASSERT_TRUE(retried.is_ok());
    EXPECT_EQ(retried.value().delivery_state(), DeliveryState::Accepted);
    EXPECT_EQ(retried.value().idempotency_key(), failed_idem);
    ASSERT_EQ(gateway.submitted_fanouts().size(), 1U);
    EXPECT_EQ(gateway.submitted_fanouts()[0].idempotency_key, failed_idem);
}

TEST_F(OfflineOutboxReplayTest, FileManagerResumesNetworkInterruptedTransfersWhileRespectingUserPause) {
    OpenSslCryptoProvider crypto;
    MemorySecureStorage storage;
    SqlCipherLocalStore store(storage, crypto);
    ASSERT_TRUE(store.open(db_path_).is_ok());
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const UserId alice("alice");
    const DeviceId alice_dev("alice-dev-1");
    const UserId bob("bob");
    const ConversationId cid("conv-files-offline");
    ASSERT_TRUE(store.save_conversation(Conversation(cid, ConversationType::Direct, "Files")).is_ok());

    FileManager fm(gateway, crypto, &store, &storage, nullptr);
    fm.set_local_identity(alice, alice_dev);
    ASSERT_TRUE(fm.set_wire_chunk_size(4096U).is_ok());

    const auto file_net = write_temp_file("net_interrupted.bin", 9000U, 0x41U);
    const auto file_user_pause = write_temp_file("user_paused.bin", 9000U, 0x42U);

    // 1. Network-interrupted upload on chunk 1 -> auto-paused with non-empty error_message
    gateway.set_simulated_chunk_failure(1U, "Simulated link drop");
    auto net_res = fm.start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice,
        .owner_device_id = alice_dev,
        .peer_user_id = bob,
        .local_file_path = file_net.string(),
        .sender_display_name = "",
        .dispatch_key_envelope = false,
    });
    ASSERT_TRUE(net_res.is_error());
    gateway.set_simulated_chunk_failure(std::nullopt);

    const auto transfers_after_net = fm.list_transfers(cid).value();
    ASSERT_EQ(transfers_after_net.size(), 1U);
    const std::string net_transfer_id = transfers_after_net[0].transfer_id;
    EXPECT_EQ(transfers_after_net[0].status, FileTransferStatus::Paused);
    EXPECT_FALSE(transfers_after_net[0].error_message.empty());

    // 2. Explicitly user-paused upload -> Paused with empty error_message
    fm.set_progress_callback([&fm](const FileTransferRecord& rec) {
        if (rec.file_name == "user_paused.bin" && rec.completed_chunks == 1U &&
            rec.status == FileTransferStatus::InProgress) {
            (void)fm.pause_transfer(rec.transfer_id);
        }
    });
    auto paused_res = fm.start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice,
        .owner_device_id = alice_dev,
        .peer_user_id = bob,
        .local_file_path = file_user_pause.string(),
        .sender_display_name = "",
        .dispatch_key_envelope = false,
    });
    ASSERT_TRUE(paused_res.is_ok());
    const std::string user_paused_id = paused_res.value().record.transfer_id;
    EXPECT_EQ(paused_res.value().record.status, FileTransferStatus::Paused);
    EXPECT_TRUE(paused_res.value().record.error_message.empty());
    fm.set_progress_callback(nullptr);

    // 3. Unstarted inbound attachment key envelope -> Pending with empty local_path
    FileAttachmentKeyEnvelope env;
    env.file_id = "file-inbound-unstarted";
    env.file_key_hex = common::configuration::SecretString(std::string(64U, 'a'));
    env.file_name = "remote.pdf";
    env.plaintext_size_bytes = 500ULL;
    env.encrypted_size_bytes = 528ULL;
    env.chunk_size_bytes = 4096U;
    env.chunk_count = 1U;
    env.ciphertext_sha256 = std::string(64U, 'b');
    env.plaintext_sha256 = std::string(64U, 'c');
    auto inbound_rec = fm.ingest_inbound_key_envelope(cid, bob, env);
    ASSERT_TRUE(inbound_rec.is_ok());

    // Reconnect catch-up resumes ONLY the network-interrupted transfer
    const auto resumed = fm.resume_interrupted_transfers();
    ASSERT_TRUE(resumed.is_ok());
    EXPECT_EQ(resumed.value(), 1U);

    EXPECT_EQ(fm.get_transfer(net_transfer_id).value().status, FileTransferStatus::Completed);
    EXPECT_EQ(fm.get_transfer(user_paused_id).value().status, FileTransferStatus::Paused);
    EXPECT_EQ(fm.get_transfer(inbound_rec.value().transfer_id).value().status, FileTransferStatus::Pending);
}

} // namespace
} // namespace securecloud::client::application::managers::test
