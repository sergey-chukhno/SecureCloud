#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "domain/crypto/sender_key_models.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/directory_user_entry.hpp"
#include "domain/file_transfer.hpp"
#include "domain/realtime_events.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "ui/app_view_model.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/workspace_view_model.hpp"

#include <QCoreApplication>
#include <QSignalSpy>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::client::tests {
namespace {

using namespace application;
using namespace application::managers;
using namespace domain;
using namespace infrastructure::adapters;
using namespace ui;
using namespace std::chrono_literals;

struct E2ePeerIdentity {
    UserId user_id;
    DeviceId device_id;
    std::vector<uint8_t> identity_public_key;
    MemorySecureStorage storage;
    application::interfaces::DeviceCryptoDirectoryEntry dir_entry;
};

void init_e2e_peer(E2ePeerIdentity& peer, OpenSslCryptoProvider& crypto, const std::string& uid,
                   const std::string& did) {
    peer.user_id = UserId(uid);
    peer.device_id = DeviceId(did);

    auto ik = crypto.generate_identity_keypair().value();
    auto spk = crypto.generate_signed_prekey(ik.private_key).value();
    auto otk = crypto.generate_dh_keypair().value();
    peer.identity_public_key = ik.public_key;

    DevicePrivateBundle bundle(peer.device_id, ik.public_key, std::move(ik.private_key), spk.public_key,
                               std::move(spk.private_key), spk.signature);
    bundle.add_one_time_prekey(did + "-otk-1", std::move(otk.private_key));
    ASSERT_TRUE(KeyStorageHelper::save_bundle(peer.storage, bundle).is_ok());

    peer.dir_entry = application::interfaces::DeviceCryptoDirectoryEntry{
        .device_id = peer.device_id,
        .identity_key = ik.public_key,
        .signed_prekey = spk.public_key,
        .signed_prekey_signature = spk.signature,
        .one_time_prekey = otk.public_key,
        .one_time_prekey_id = did + "-otk-1",
        .identity_key_fingerprint = "",
    };
}

class OfflineCatchUpSyncIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("securecloud_e2e_offline_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = (temp_dir_ / "alice_vault.db").string();
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

TEST_F(OfflineCatchUpSyncIntegrationTest,
       Scenario1_OfflineDraftingSqlCipherRestartAndPriorityOrderedPreEncryptedFlush) {
    OpenSslCryptoProvider crypto;
    DefaultGatewayClient gateway(ClientConfig::create_default());

    E2ePeerIdentity alice;
    E2ePeerIdentity bob;
    init_e2e_peer(alice, crypto, "alice", "alice-dev-1");
    init_e2e_peer(bob, crypto, "bob", "bob-dev-1");
    gateway.set_simulated_user_directory(alice.user_id, {alice.dir_entry});
    gateway.set_simulated_user_directory(bob.user_id, {bob.dir_entry});

    MemoryLocalStore bob_store;
    ASSERT_TRUE(bob_store.open("bob-mem").is_ok());
    RatchetSessionManager bob_ratchet(gateway, bob.storage, crypto, bob.user_id, bob.device_id);
    MessagingManager bob_mm(gateway, bob_store, crypto, &bob_ratchet, &bob.storage);

    ConversationId direct_cid;
    ConversationId group_cid;
    uint64_t group_epoch = 0;
    std::string norm_idem;
    std::string urgent_idem;
    std::string emerg_idem;
    std::string group_idem;
    std::string ratchet_snapshot;
    std::string sender_key_snapshot;

    {
        SqlCipherLocalStore alice_store(alice.storage, crypto);
        ASSERT_TRUE(alice_store.open(db_path_).is_ok());
        RatchetSessionManager alice_ratchet(gateway, alice.storage, crypto, alice.user_id, alice.device_id);
        MessagingManager alice_mm(gateway, alice_store, crypto, &alice_ratchet, &alice.storage);
        alice_mm.set_local_device_id(alice.device_id);
        ASSERT_TRUE(alice_mm.set_read_receipts_enabled(true).is_ok());

        SyncManager alice_sm(gateway, ClientConfig::create_default());
        alice_sm.set_local_store(&alice_store);
        alice_sm.set_messaging_manager(&alice_mm);
        alice_sm.set_local_identity(alice.user_id, alice.device_id);

        auto direct_conv = alice_mm.open_direct_conversation(alice.user_id, bob.user_id, "Bob").value();
        direct_cid = direct_conv.conversation_id();
        ASSERT_TRUE(bob_mm.open_direct_conversation(bob.user_id, alice.user_id, "Alice").is_ok());

        // Establish pairwise X3DH / Double Ratchet session online
        auto warmup = alice_mm.stage_outbound_message(direct_cid, alice.user_id, alice.device_id, "Warmup");
        ASSERT_TRUE(warmup.is_ok());
        ASSERT_EQ(gateway.submitted_fanouts().size(), 1U);
        ASSERT_TRUE(bob_mm
                        .process_inbound_message(direct_cid, alice.user_id, alice.device_id,
                                                 gateway.submitted_fanouts()[0].device_payloads[0])
                        .is_ok());
        gateway.clear_submitted_fanouts();

        // Bob sends a message to Alice so Alice has an unread peer message to mark read while offline
        auto bob_to_alice = bob_mm.stage_outbound_message(direct_cid, bob.user_id, bob.device_id, "From Bob");
        ASSERT_TRUE(bob_to_alice.is_ok());
        ASSERT_EQ(gateway.submitted_fanouts().size(), 1U);
        RealtimeEvent bob_ev;
        bob_ev.type = RealtimeEventType::InboundDirectMessage;
        bob_ev.conversation_id = direct_cid;
        bob_ev.message_id = MessageId("msg-bob-read-me");
        bob_ev.actor_user_id = bob.user_id;
        bob_ev.actor_device_id = bob.device_id;
        bob_ev.server_sequence_number = 1ULL;
        bob_ev.direct_payload = gateway.submitted_fanouts()[0].device_payloads[0];
        ASSERT_TRUE(alice_mm.process_inbound_realtime_event(bob_ev).is_ok());
        gateway.clear_submitted_fanouts();

        auto group_conv = alice_mm.create_group_conversation(alice.user_id, "Ops Offline", {bob.user_id}).value();
        group_cid = group_conv.conversation_id();
        group_epoch = group_conv.sender_key_epoch();
        ASSERT_TRUE(bob_store.save_conversation(group_conv).is_ok());

        // Go Offline via SyncManager -> draft Normal, Urgent, Emergency direct messages + 1 group message + ReadReceipt
        ASSERT_TRUE(alice_sm.set_simulated_offline(true).is_ok());
        gateway.set_simulated_submission_failure(true, "Offline");

        norm_idem = alice_mm.stage_outbound_message(direct_cid, alice.user_id, alice.device_id, "Normal offline", 0)
                        .value()
                        .idempotency_key();
        std::this_thread::sleep_for(2ms);
        urgent_idem = alice_mm.stage_outbound_message(direct_cid, alice.user_id, alice.device_id, "Urgent offline", 2)
                          .value()
                          .idempotency_key();
        std::this_thread::sleep_for(2ms);
        emerg_idem = alice_mm.stage_outbound_message(direct_cid, alice.user_id, alice.device_id, "Emergency offline", 3)
                         .value()
                         .idempotency_key();
        std::this_thread::sleep_for(2ms);
        group_idem = alice_mm.stage_outbound_message(group_cid, alice.user_id, alice.device_id, "Group offline", 1)
                         .value()
                         .idempotency_key();

        ASSERT_TRUE(alice_mm.mark_conversation_read(direct_cid, alice.user_id, alice.device_id).is_ok());
        EXPECT_EQ(alice_mm.get_conversation(direct_cid).value().unread_count(), 0U);
        EXPECT_TRUE(gateway.submitted_fanouts().empty());
        EXPECT_TRUE(gateway.sent_read_receipts().empty());
        EXPECT_EQ(alice_mm.pending_outbox_count(), 6U); // 3 direct + 1 SKD + 1 group + 1 ReadReceipt

        ratchet_snapshot =
            alice.storage.get_secret("ratchet_session:" + bob.user_id.value() + ":" + bob.device_id.value())
                .value()
                .expose_unredacted_secret();
        sender_key_snapshot = alice.storage
                                  .get_secret(crypto::SenderKeyId{
                                      .conversation_id = group_cid,
                                      .sender_user_id = alice.user_id,
                                      .sender_device_id = alice.device_id,
                                      .key_epoch = group_epoch,
                                  }
                                                  .storage_key())
                                  .value()
                                  .expose_unredacted_secret();

        ASSERT_TRUE(alice_store.close().is_ok());
    }

    // Full workstation restart against the same encrypted SQLCipher vault on disk
    SqlCipherLocalStore reopened_store(alice.storage, crypto);
    ASSERT_TRUE(reopened_store.open(db_path_).is_ok());
    RatchetSessionManager restarted_ratchet(gateway, alice.storage, crypto, alice.user_id, alice.device_id);
    MessagingManager restarted_mm(gateway, reopened_store, crypto, &restarted_ratchet, &alice.storage);
    restarted_mm.set_local_device_id(alice.device_id);

    SyncManager restarted_sm(gateway, ClientConfig::create_default());
    restarted_sm.set_local_store(&reopened_store);
    restarted_sm.set_messaging_manager(&restarted_mm);
    restarted_sm.set_local_identity(alice.user_id, alice.device_id);
    ASSERT_TRUE(restarted_sm.set_simulated_offline(true).is_ok());

    gateway.set_simulated_failure(false);
    gateway.set_simulated_submission_failure(false);

    // Reconnect triggers automatic 4-phase catch-up sync
    ASSERT_TRUE(restarted_sm.set_simulated_offline(false).is_ok());
    EXPECT_EQ(restarted_sm.connectivity_state(), ConnectivityState::Online);
    EXPECT_EQ(restarted_mm.pending_outbox_count(), 0U);

    // Verify ZERO ratchet re-stepping during replay (ADR-008)
    EXPECT_EQ(alice.storage.get_secret("ratchet_session:" + bob.user_id.value() + ":" + bob.device_id.value())
                  .value()
                  .expose_unredacted_secret(),
              ratchet_snapshot);
    EXPECT_EQ(alice.storage
                  .get_secret(crypto::SenderKeyId{
                      .conversation_id = group_cid,
                      .sender_user_id = alice.user_id,
                      .sender_device_id = alice.device_id,
                      .key_epoch = group_epoch,
                  }
                                  .storage_key())
                  .value()
                  .expose_unredacted_secret(),
              sender_key_snapshot);

    // Verify ReadReceipt flushed and all 5 encrypted submissions arrived in strict priority order:
    // Emergency (3) -> Urgent (2) -> Group SKD (1) -> Group Msg (1) -> Normal (0)
    ASSERT_EQ(gateway.sent_read_receipts().size(), 1U);
    EXPECT_EQ(gateway.sent_read_receipts()[0].message_id, MessageId("msg-bob-read-me"));

    const auto& fanouts = gateway.submitted_fanouts();
    ASSERT_EQ(fanouts.size(), 5U);
    EXPECT_EQ(fanouts[0].idempotency_key, emerg_idem);
    EXPECT_EQ(fanouts[1].idempotency_key, urgent_idem);
    EXPECT_EQ(fanouts[2].idempotency_key, group_idem + "-skd");
    EXPECT_EQ(fanouts[3].idempotency_key, group_idem);
    EXPECT_EQ(fanouts[4].idempotency_key, norm_idem);

    // Bob decrypts every single replayed direct and group ciphertext cleanly!
    EXPECT_EQ(bob_mm.process_inbound_message(direct_cid, alice.user_id, alice.device_id, fanouts[0].device_payloads[0])
                  .value()
                  .encrypted_envelope_ref(),
              "Emergency offline");
    EXPECT_EQ(bob_mm.process_inbound_message(direct_cid, alice.user_id, alice.device_id, fanouts[1].device_payloads[0])
                  .value()
                  .encrypted_envelope_ref(),
              "Urgent offline");

    const std::string raw_skd =
        bob_ratchet.decrypt_payload_from_device(alice.user_id, alice.device_id, fanouts[2].device_payloads[0])
            .value()
            .expose_unredacted_secret();
    std::vector<uint8_t> skd_bytes(raw_skd.begin(), raw_skd.end());
    ASSERT_TRUE(
        bob_mm
            .process_inbound_sender_key_distribution(
                alice.user_id, alice.device_id, crypto::SenderKeyDistributionMessage::deserialize(skd_bytes).value())
            .is_ok());
    EXPECT_EQ(
        bob_mm
            .process_inbound_group_message(group_cid, alice.user_id, alice.device_id, *fanouts[3].group_envelope_bytes)
            .value()
            .encrypted_envelope_ref(),
        "Group offline");
    EXPECT_EQ(bob_mm.process_inbound_message(direct_cid, alice.user_id, alice.device_id, fanouts[4].device_payloads[0])
                  .value()
                  .encrypted_envelope_ref(),
              "Normal offline");
}

TEST_F(OfflineCatchUpSyncIntegrationTest, Scenario2_MultiPageCatchUpSync125EventsAndDurableCursorCheckpointing) {
    OpenSslCryptoProvider crypto;
    MemorySecureStorage storage;
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const UserId alice("alice");
    const DeviceId alice_dev("alice-dev-1");
    const UserId bob("bob");
    const DeviceId bob_dev("bob-dev-1");
    ConversationId cid;

    std::vector<RealtimeEvent> events;
    events.reserve(125U);

    {
        SqlCipherLocalStore store(storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        MessagingManager mm(gateway, store, crypto, nullptr, &storage);
        mm.set_local_device_id(alice_dev);
        cid = mm.open_direct_conversation(alice, bob, "Bob").value().conversation_id();

        for (uint64_t seq = 1ULL; seq <= 125ULL; ++seq) {
            RealtimeEvent ev;
            ev.type = RealtimeEventType::InboundDirectMessage;
            ev.conversation_id = cid;
            ev.message_id = MessageId("msg-e2e-page-" + std::to_string(seq));
            ev.actor_user_id = bob;
            ev.actor_device_id = bob_dev;
            ev.server_sequence_number = seq;
            ev.direct_payload = crypto::PerDeviceDeliveryPayload{
                .recipient_user_id = {},
                .recipient_device_id = alice_dev,
                .ciphertext_blob = crypto.encrypt_message(bob_dev, "Delta #" + std::to_string(seq)).value(),
                .ephemeral_public_key = {},
                .iv = {},
                .auth_tag = {},
            };
            events.push_back(std::move(ev));
        }
        gateway.set_simulated_conversation_messages(cid, events);

        SyncManager sm(gateway, ClientConfig::create_default());
        sm.set_local_store(&store);
        sm.set_messaging_manager(&mm);
        sm.set_local_identity(alice, alice_dev);

        const auto report = sm.execute_catch_up_sync(alice, alice_dev, 50U);
        ASSERT_TRUE(report.is_ok());
        EXPECT_EQ(report.value().messages_merged_count, 125U);
        EXPECT_EQ(report.value().duplicates_skipped_count, 0U);
        EXPECT_EQ(sm.conversation_cursor(cid), 125ULL);
        EXPECT_EQ(store.get_sync_cursor(alice_dev, cid).value().last_delivered_sequence, 125ULL);
        EXPECT_EQ(gateway.get_sync_cursor(alice_dev, cid).value().last_delivered_sequence, 125ULL);
        EXPECT_EQ(store.get_messages(cid, 200U).value().size(), 125U);
        ASSERT_TRUE(store.close().is_ok());
    }

    // Reopen after restart -> subsequent catch-up merges 0 redundant events
    SqlCipherLocalStore reopened(storage, crypto);
    ASSERT_TRUE(reopened.open(db_path_).is_ok());
    MessagingManager mm2(gateway, reopened, crypto, nullptr, &storage);
    mm2.set_local_device_id(alice_dev);
    SyncManager sm2(gateway, ClientConfig::create_default());
    sm2.set_local_store(&reopened);
    sm2.set_messaging_manager(&mm2);
    sm2.set_local_identity(alice, alice_dev);

    const auto report2 = sm2.execute_catch_up_sync(alice, alice_dev, 50U);
    ASSERT_TRUE(report2.is_ok());
    EXPECT_EQ(sm2.conversation_cursor(cid), 125ULL);
    EXPECT_EQ(report2.value().messages_merged_count, 0U);
    EXPECT_EQ(report2.value().duplicates_skipped_count, 0U);
}

TEST_F(OfflineCatchUpSyncIntegrationTest, Scenario3_IdempotentDeduplicationAndMonotonicDeliveryStateMerge) {
    OpenSslCryptoProvider crypto;
    MemorySecureStorage storage;
    MemoryLocalStore store;
    ASSERT_TRUE(store.open("mem").is_ok());
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const UserId alice("alice");
    const DeviceId alice_dev("alice-dev-1");
    const UserId bob("bob");
    const DeviceId bob_dev("bob-dev-1");

    MessagingManager mm(gateway, store, crypto, nullptr, &storage);
    mm.set_local_device_id(alice_dev);
    const auto cid = mm.open_direct_conversation(alice, bob, "Bob").value().conversation_id();

    // Overlapping message event + Read followed by stale out-of-order DeliveryAck
    RealtimeEvent msg_ev;
    msg_ev.type = RealtimeEventType::InboundDirectMessage;
    msg_ev.conversation_id = cid;
    msg_ev.message_id = MessageId("msg-dedupe-1");
    msg_ev.actor_user_id = bob;
    msg_ev.actor_device_id = bob_dev;
    msg_ev.server_sequence_number = 10ULL;
    msg_ev.direct_payload = crypto::PerDeviceDeliveryPayload{
        .recipient_user_id = {},
        .recipient_device_id = alice_dev,
        .ciphertext_blob = crypto.encrypt_message(bob_dev, "Single copy only").value(),
        .ephemeral_public_key = {},
        .iv = {},
        .auth_tag = {},
    };

    // Deliver once via real-time path, then replay in catch-up page alongside Read -> stale Delivered
    ASSERT_TRUE(mm.process_inbound_realtime_event(msg_ev).is_ok());

    RealtimeEvent read_ev;
    read_ev.type = RealtimeEventType::ReadReceipt;
    read_ev.conversation_id = cid;
    read_ev.message_id = MessageId("msg-dedupe-1");
    read_ev.server_sequence_number = 11ULL;

    RealtimeEvent stale_ack;
    stale_ack.type = RealtimeEventType::DeliveryAck;
    stale_ack.conversation_id = cid;
    stale_ack.message_id = MessageId("msg-dedupe-1");
    stale_ack.server_sequence_number = 12ULL;

    gateway.set_simulated_conversation_messages(cid, {msg_ev, read_ev, stale_ack});

    SyncManager sm(gateway, ClientConfig::create_default());
    sm.set_local_store(&store);
    sm.set_messaging_manager(&mm);
    sm.set_local_identity(alice, alice_dev);

    const auto report = sm.execute_catch_up_sync(alice, alice_dev);
    ASSERT_TRUE(report.is_ok());
    EXPECT_EQ(report.value().messages_merged_count, 0U);
    EXPECT_EQ(report.value().duplicates_skipped_count, 1U);

    const auto msgs = store.get_messages(cid, 50U).value();
    ASSERT_EQ(msgs.size(), 1U);
    EXPECT_EQ(msgs[0].delivery_state(), DeliveryState::Read); // Never regresses Read -> Delivered
}

TEST_F(OfflineCatchUpSyncIntegrationTest, Scenario4_RemoteGroupKeyChangeAndInterruptedFileTransferReconciliation) {
    OpenSslCryptoProvider crypto;
    MemorySecureStorage storage;
    SqlCipherLocalStore store(storage, crypto);
    ASSERT_TRUE(store.open(db_path_).is_ok());
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const UserId alice("alice");
    const DeviceId alice_dev("alice-dev-1");
    const UserId bob("bob");

    SafetyNumberEngine sn_engine(crypto, storage);
    ContactManager cm(store, gateway, sn_engine);
    auto alice_ik = crypto.generate_identity_keypair().value();
    auto bob_ik_v1 = crypto.generate_identity_keypair().value();
    auto bob_ik_v2 = crypto.generate_identity_keypair().value();
    cm.set_local_identity(alice, alice_ik.public_key);

    const DirectoryUserEntry bob_v1(bob, "@bob", "Bob", bob_ik_v1.public_key, "fp-v1", 1U);
    gateway.set_simulated_directory_users({bob_v1});
    ASSERT_TRUE(cm.add_contact_from_directory(bob_v1).is_ok());
    ASSERT_TRUE(cm.set_contact_verified(bob, true).is_ok());

    MessagingManager mm(gateway, store, crypto, nullptr, &storage);
    const auto direct_cid = mm.open_direct_conversation(alice, bob, "Bob").value().conversation_id();

    FileManager fm(gateway, crypto, &store, &storage, nullptr);
    fm.set_local_identity(alice, alice_dev);
    ASSERT_TRUE(fm.set_wire_chunk_size(4096U).is_ok());

    // Interrupt an upload at chunk 1/3
    const auto upload_path = write_temp_file("reconcile_upload.bin", 9000U, 0x77U);
    gateway.set_simulated_chunk_failure(1U, "Offline mid-upload");
    ASSERT_TRUE(fm.start_upload(FileUploadRequest{
                                    .conversation_id = direct_cid,
                                    .owner_user_id = alice,
                                    .owner_device_id = alice_dev,
                                    .peer_user_id = bob,
                                    .local_file_path = upload_path.string(),
                                    .sender_display_name = "",
                                    .dispatch_key_envelope = false,
                                })
                    .is_error());
    gateway.set_simulated_chunk_failure(std::nullopt);
    const std::string upload_tx_id = fm.list_transfers(direct_cid).value()[0].transfer_id;

    // While offline: new remote group created + Bob rotates identity key (v2)
    const ConversationId remote_group_cid("conv-e2e-remote-group");
    gateway.set_simulated_remote_conversations({
        RemoteConversationSummary{
            .conversation_id = remote_group_cid,
            .type = ConversationType::Group,
            .title = "Incident Response Team",
            .creator_user_id = bob,
            .created_at_ms = 1700000050000LL,
            .participant_user_ids = {alice, bob},
        },
    });
    gateway.set_simulated_directory_users({DirectoryUserEntry(bob, "@bob", "Bob", bob_ik_v2.public_key, "fp-v2", 2U)});

    SyncManager sm(gateway, ClientConfig::create_default());
    sm.set_local_store(&store);
    sm.set_messaging_manager(&mm);
    sm.set_contact_manager(&cm);
    sm.set_file_manager(&fm);
    sm.set_local_identity(alice, alice_dev);

    const auto report = sm.execute_catch_up_sync(alice, alice_dev);
    ASSERT_TRUE(report.is_ok());
    EXPECT_EQ(report.value().conversations_reconciled_count, 1U);
    EXPECT_EQ(report.value().transfers_resumed_count, 1U);

    // 1. New remote group exists locally
    ASSERT_TRUE(store.get_conversation(remote_group_cid).is_ok());
    EXPECT_EQ(store.get_conversation(remote_group_cid).value().title(), "Incident Response Team");

    // 2. Contact flagged KeyChanged (ADR-008), blocking unverified sends
    EXPECT_EQ(cm.get_contact(bob).value().verification_status(), KeyVerificationStatus::KeyChanged);
    EXPECT_TRUE(mm.stage_outbound_message(direct_cid, alice, alice_dev, "Blocked until verified").is_error());

    // 3. Interrupted file upload resumed cleanly to Completed (3/3)
    const auto tx = fm.get_transfer(upload_tx_id).value();
    EXPECT_EQ(tx.status, FileTransferStatus::Completed);
    EXPECT_EQ(tx.completed_chunks, tx.total_chunks);
}

TEST_F(OfflineCatchUpSyncIntegrationTest, Scenario5_FullWorkspaceAndAppViewModelReactiveUiLifecycle) {
    auto config = ClientConfig::create_default();
    auto gw = std::make_unique<DefaultGatewayClient>(config);
    auto* gateway_ptr = gw.get();
    auto store = std::make_unique<MemoryLocalStore>();
    ASSERT_TRUE(store->open("mem").is_ok());
    auto sec = std::make_unique<MemorySecureStorage>();
    auto crypto = std::make_unique<OpenSslCryptoProvider>();
    auto* crypto_ptr = crypto.get();

    auto bootstrap = ClientBootstrap::create_with_adapters(config, std::move(gw), std::move(store), std::move(sec),
                                                           std::move(crypto));
    ClientApplication app(std::move(bootstrap));
    ASSERT_TRUE(app.initialize().is_ok());

    NavigationController nav;
    AppViewModel app_vm(app, nav);
    app_vm.requestLogin(QStringLiteral("operator@securecloud.org"), QStringLiteral("pass123"));
    WorkspaceViewModel wvm(app, nav);

    const QString active_cid = wvm.selectedConversationId();
    ASSERT_FALSE(active_cid.isEmpty());

    QSignalSpy outbox_spy(&wvm, &WorkspaceViewModel::pendingOutboxCountChanged);
    std::vector<QString> states;
    QObject::connect(&wvm, &WorkspaceViewModel::connectivityStateChanged, &wvm,
                     [&]() { states.push_back(wvm.connectivityState()); });

    // Offline drafting -> LocalPending + pendingOutboxCount == 1 + AppViewModel Offline
    wvm.setSimulatedOfflineMode(true);
    EXPECT_TRUE(wvm.isOffline());
    EXPECT_EQ(app_vm.connectionStatus(), QStringLiteral("Offline"));
    ASSERT_TRUE(wvm.sendMessage(QStringLiteral("UI offline E2E draft")));
    EXPECT_EQ(wvm.pendingOutboxCount(), 1);
    EXPECT_GE(outbox_spy.count(), 1);

    // Seed missed remote message while offline
    RealtimeEvent ev;
    ev.type = RealtimeEventType::InboundDirectMessage;
    ev.conversation_id = ConversationId(active_cid.toStdString());
    ev.message_id = MessageId("msg-ui-e2e-missed");
    ev.actor_user_id = UserId("peer-e2e");
    ev.actor_device_id = DeviceId("peer-dev-1");
    ev.server_sequence_number = 77ULL;
    ev.direct_payload = crypto::PerDeviceDeliveryPayload{
        .recipient_user_id = {},
        .recipient_device_id = DeviceId("dev-local-01"),
        .ciphertext_blob = crypto_ptr->encrypt_message(DeviceId("peer-dev-1"), "Incoming E2E catch-up").value(),
        .ephemeral_public_key = {},
        .iv = {},
        .auth_tag = {},
    };
    gateway_ptr->set_simulated_conversation_messages(ev.conversation_id, {ev});

    // Reconnect -> Syncing -> Online, outbox drained, missed message rendered
    wvm.setSimulatedOfflineMode(false);
    EXPECT_FALSE(wvm.isOffline());
    EXPECT_EQ(wvm.connectivityState(), QStringLiteral("Online"));
    EXPECT_EQ(app_vm.connectionStatus(), QStringLiteral("Connected"));
    EXPECT_EQ(wvm.pendingOutboxCount(), 0);

    bool saw_syncing = false;
    for (const auto& st : states) {
        if (st == QStringLiteral("Syncing")) {
            saw_syncing = true;
        }
    }
    EXPECT_TRUE(saw_syncing);

    bool found_draft_accepted = false;
    bool found_missed_inbound = false;
    for (const QVariant& item : wvm.activeMessages()) {
        const QVariantMap m = item.toMap();
        if (m.value(QStringLiteral("text")).toString() == QStringLiteral("UI offline E2E draft")) {
            found_draft_accepted = (m.value(QStringLiteral("deliveryState")).toString() == QStringLiteral("Accepted"));
        } else if (m.value(QStringLiteral("text")).toString() == QStringLiteral("Incoming E2E catch-up")) {
            found_missed_inbound = true;
        }
    }
    EXPECT_TRUE(found_draft_accepted);
    EXPECT_TRUE(found_missed_inbound);

    (void)app.shutdown();
}

} // namespace
} // namespace securecloud::client::tests
