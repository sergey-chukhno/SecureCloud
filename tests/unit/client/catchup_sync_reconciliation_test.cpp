#include "application/client_config.hpp"
#include "application/managers/contact_manager.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "application/managers/sync_manager.hpp"
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
#include <string>
#include <vector>

namespace securecloud::client::application::managers::test {
namespace {

using namespace domain;
using namespace infrastructure::adapters;

class CatchUpSyncReconciliationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("securecloud_catchup_sync_" + suffix);
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

TEST_F(CatchUpSyncReconciliationTest, ConnectivityStateMachineTransitionsAndCallbackNotifications) {
    OpenSslCryptoProvider crypto;
    MemorySecureStorage storage;
    MemoryLocalStore store;
    ASSERT_TRUE(store.open("mem").is_ok());
    DefaultGatewayClient gateway(ClientConfig::create_default());
    MessagingManager mm(gateway, store, crypto, nullptr, &storage);
    SyncManager sm(gateway, ClientConfig::create_default());
    sm.set_local_store(&store);
    sm.set_messaging_manager(&mm);
    sm.set_local_identity(UserId("alice"), DeviceId("alice-dev-1"));

    std::vector<ConnectivityState> observed;
    const uint64_t sub_id = sm.subscribe_connectivity_state([&](ConnectivityState st) { observed.push_back(st); });

    EXPECT_EQ(sm.connectivity_state(), ConnectivityState::Online);
    EXPECT_FALSE(mm.is_offline_mode());

    // 1. Gateway health probe fails -> transitions Online -> Offline and enables MessagingManager offline mode
    gateway.set_simulated_failure(true, "Link down");
    auto c1 = sm.check_connectivity();
    ASSERT_TRUE(c1.is_ok());
    EXPECT_EQ(c1.value(), ConnectivityState::Offline);
    EXPECT_TRUE(mm.is_offline_mode());

    // 2. Gateway recovers -> check_connectivity transitions Offline -> Syncing -> Online
    gateway.set_simulated_failure(false);
    auto c2 = sm.check_connectivity();
    ASSERT_TRUE(c2.is_ok());
    EXPECT_EQ(c2.value(), ConnectivityState::Online);
    EXPECT_FALSE(mm.is_offline_mode());

    ASSERT_EQ(observed.size(), 3U);
    EXPECT_EQ(observed[0], ConnectivityState::Offline);
    EXPECT_EQ(observed[1], ConnectivityState::Syncing);
    EXPECT_EQ(observed[2], ConnectivityState::Online);

    // 3. Simulated offline toggle drives Offline -> Syncing -> Offline if gateway is down mid-sync
    observed.clear();
    ASSERT_TRUE(sm.set_simulated_offline(true).is_ok());
    EXPECT_EQ(sm.connectivity_state(), ConnectivityState::Offline);
    EXPECT_TRUE(mm.is_offline_mode());

    gateway.set_simulated_failure(true, "Still unreachable");
    auto toggle_fail = sm.set_simulated_offline(false);
    EXPECT_TRUE(toggle_fail.is_error());
    EXPECT_EQ(sm.connectivity_state(), ConnectivityState::Offline);
    EXPECT_TRUE(mm.is_offline_mode());

    ASSERT_EQ(observed.size(), 3U);
    EXPECT_EQ(observed[0], ConnectivityState::Offline);
    EXPECT_EQ(observed[1], ConnectivityState::Syncing);
    EXPECT_EQ(observed[2], ConnectivityState::Offline);

    sm.unsubscribe_connectivity_state(sub_id);
}

TEST_F(CatchUpSyncReconciliationTest, MultiPageCatchUpSyncPersistsCursorsAcrossRestartAndDeduplicates) {
    OpenSslCryptoProvider crypto;
    MemorySecureStorage storage;
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const UserId alice("alice");
    const DeviceId alice_dev("alice-dev-1");
    const UserId bob("bob");
    const DeviceId bob_dev("bob-dev-1");
    ConversationId cid;

    // Seed 120 unique messages (3 pages of 50 + 50 + 20)
    std::vector<RealtimeEvent> remote_events;
    remote_events.reserve(120U);

    {
        SqlCipherLocalStore store(storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        MessagingManager mm(gateway, store, crypto, nullptr, &storage);
        mm.set_local_device_id(alice_dev);

        cid = mm.open_direct_conversation(alice, bob, "Bob").value().conversation_id();

        for (uint64_t seq = 1ULL; seq <= 120ULL; ++seq) {
            RealtimeEvent ev;
            ev.type = RealtimeEventType::InboundDirectMessage;
            ev.conversation_id = cid;
            ev.message_id = MessageId("msg-catchup-" + std::to_string(seq));
            ev.actor_user_id = bob;
            ev.actor_device_id = bob_dev;
            ev.server_sequence_number = seq;
            ev.direct_payload = crypto::PerDeviceDeliveryPayload{
                .recipient_device_id = alice_dev,
                .ciphertext_blob = crypto.encrypt_message(bob_dev, "Payload #" + std::to_string(seq)).value(),
            };
            remote_events.push_back(std::move(ev));
        }

        // Pre-seed message #1 locally so we also verify duplicate skipping
        ASSERT_TRUE(mm.process_inbound_realtime_event(remote_events[0]).is_ok());
        gateway.set_simulated_conversation_messages(cid, remote_events);

        SyncManager sm(gateway, ClientConfig::create_default());
        sm.set_local_store(&store);
        sm.set_messaging_manager(&mm);
        sm.set_local_identity(alice, alice_dev);

        auto report_res = sm.execute_catch_up_sync(alice, alice_dev, 50U);
        ASSERT_TRUE(report_res.is_ok());
        EXPECT_EQ(report_res.value().messages_merged_count, 119U);
        EXPECT_EQ(report_res.value().duplicates_skipped_count, 1U);
        EXPECT_EQ(sm.conversation_cursor(cid), 120ULL);

        // Persisted in both SqlCipherLocalStore and Gateway
        EXPECT_EQ(store.get_sync_cursor(alice_dev, cid).value().last_delivered_sequence, 120ULL);
        EXPECT_EQ(gateway.get_sync_cursor(alice_dev, cid).value().last_delivered_sequence, 120ULL);
        EXPECT_EQ(store.get_messages(cid, 200U).value().size(), 120U);

        ASSERT_TRUE(store.close().is_ok());
    }

    // Restart against the same SQLCipher database -> hydrates cursor 120 and merges 0 duplicates
    SqlCipherLocalStore reopened(storage, crypto);
    ASSERT_TRUE(reopened.open(db_path_).is_ok());
    MessagingManager restarted_mm(gateway, reopened, crypto, nullptr, &storage);
    restarted_mm.set_local_device_id(alice_dev);
    SyncManager restarted_sm(gateway, ClientConfig::create_default());
    restarted_sm.set_local_store(&reopened);
    restarted_sm.set_messaging_manager(&restarted_mm);
    restarted_sm.set_local_identity(alice, alice_dev);

    auto second_report = restarted_sm.execute_catch_up_sync(alice, alice_dev, 50U);
    ASSERT_TRUE(second_report.is_ok());
    EXPECT_EQ(restarted_sm.conversation_cursor(cid), 120ULL);
    EXPECT_EQ(second_report.value().messages_merged_count, 0U);
    EXPECT_EQ(second_report.value().duplicates_skipped_count, 0U);
}

TEST_F(CatchUpSyncReconciliationTest, RemoteConversationAndContactReconciliationPreservesLocalState) {
    OpenSslCryptoProvider crypto;
    MemorySecureStorage storage;
    MemoryLocalStore store;
    ASSERT_TRUE(store.open("mem").is_ok());
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const UserId alice("alice");
    const DeviceId alice_dev("alice-dev-1");
    const UserId bob("bob");
    const UserId charlie("charlie");

    SafetyNumberEngine sn_engine(crypto, storage);
    ContactManager cm(store, gateway, sn_engine);
    auto alice_ik = crypto.generate_identity_keypair().value();
    auto bob_ik_v1 = crypto.generate_identity_keypair().value();
    auto bob_ik_v2 = crypto.generate_identity_keypair().value();
    cm.set_local_identity(alice, alice_ik.public_key);

    // Pin Bob as Verified with key v1
    const DirectoryUserEntry bob_entry_v1(bob, "@bob", "Bob", bob_ik_v1.public_key, "fp-bob-v1", 1U);
    gateway.set_simulated_directory_users({bob_entry_v1});
    ASSERT_TRUE(cm.add_contact_from_directory(bob_entry_v1).is_ok());
    ASSERT_TRUE(cm.set_contact_verified(bob, true).is_ok());
    EXPECT_EQ(cm.get_contact(bob).value().verification_status(), KeyVerificationStatus::Verified);

    // While offline, Bob rotates his identity key (v2) and a new remote group + title update occur
    gateway.set_simulated_directory_users(
        {DirectoryUserEntry(bob, "@bob", "Bob Updated", bob_ik_v2.public_key, "fp-bob-v2", 2U)});

    MessagingManager mm(gateway, store, crypto, nullptr, &storage);
    auto existing_group = mm.create_group_conversation(alice, "Old Title", {bob}).value();
    existing_group.set_unread_count(7U);
    existing_group.set_sender_key_epoch(5ULL);
    ASSERT_TRUE(store.save_conversation(existing_group).is_ok());

    const ConversationId new_remote_cid("conv-remote-new-1");
    gateway.set_simulated_remote_conversations({
        RemoteConversationSummary{
            .conversation_id = existing_group.conversation_id(),
            .type = ConversationType::Group,
            .title = "Renamed Ops Room",
            .creator_user_id = alice,
            .created_at_ms = 1700000000000LL,
            .participant_user_ids = {alice, bob, charlie},
        },
        RemoteConversationSummary{
            .conversation_id = new_remote_cid,
            .type = ConversationType::Direct,
            .title = "Charlie Direct",
            .creator_user_id = charlie,
            .created_at_ms = 1700000010000LL,
            .participant_user_ids = {alice, charlie},
        },
    });

    SyncManager sm(gateway, ClientConfig::create_default());
    sm.set_local_store(&store);
    sm.set_messaging_manager(&mm);
    sm.set_contact_manager(&cm);
    sm.set_local_identity(alice, alice_dev);

    auto report_res = sm.execute_catch_up_sync(alice, alice_dev);
    ASSERT_TRUE(report_res.is_ok());
    EXPECT_EQ(report_res.value().conversations_reconciled_count, 2U);
    EXPECT_GE(report_res.value().contacts_reconciled_count, 1U);

    // Existing conversation merged title + new participant while preserving unread_count and sender_key_epoch
    const auto merged_group = store.get_conversation(existing_group.conversation_id()).value();
    EXPECT_EQ(merged_group.title(), "Renamed Ops Room");
    EXPECT_TRUE(merged_group.has_participant(charlie));
    EXPECT_EQ(merged_group.unread_count(), 7U);
    EXPECT_EQ(merged_group.sender_key_epoch(), 5ULL);

    // New remote conversation inserted locally
    ASSERT_TRUE(store.get_conversation(new_remote_cid).is_ok());
    EXPECT_EQ(store.get_conversation(new_remote_cid).value().title(), "Charlie Direct");

    // Rotated Bob key flagged as KeyChanged (ADR-008)
    EXPECT_EQ(cm.get_contact(bob).value().verification_status(), KeyVerificationStatus::KeyChanged);
}

TEST_F(CatchUpSyncReconciliationTest, FullFourPhaseCatchUpFlushesOutboxResumesFilesAndIngestsInboundFileEnvelopes) {
    OpenSslCryptoProvider crypto;
    MemorySecureStorage storage;
    SqlCipherLocalStore store(storage, crypto);
    ASSERT_TRUE(store.open(db_path_).is_ok());
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const UserId alice("alice");
    const DeviceId alice_dev("alice-dev-1");
    const UserId bob("bob");
    const DeviceId bob_dev("bob-dev-1");

    auto bob_ik = crypto.generate_identity_keypair().value();
    auto bob_spk = crypto.generate_signed_prekey(bob_ik.private_key).value();
    auto bob_otk = crypto.generate_dh_keypair().value();
    gateway.set_simulated_user_directory(bob, {interfaces::DeviceCryptoDirectoryEntry{
                                                  .device_id = bob_dev,
                                                  .identity_key = bob_ik.public_key,
                                                  .signed_prekey = bob_spk.public_key,
                                                  .signed_prekey_signature = bob_spk.signature,
                                                  .one_time_prekey = bob_otk.public_key,
                                                  .one_time_prekey_id = "bob-otk-1",
                                              }});
    auto alice_ik = crypto.generate_identity_keypair().value();
    auto alice_spk = crypto.generate_signed_prekey(alice_ik.private_key).value();
    DevicePrivateBundle alice_bundle(alice_dev, alice_ik.public_key, std::move(alice_ik.private_key),
                                     alice_spk.public_key, std::move(alice_spk.private_key), alice_spk.signature);
    ASSERT_TRUE(KeyStorageHelper::save_bundle(storage, alice_bundle).is_ok());

    RatchetSessionManager ratchet(gateway, storage, crypto, alice, alice_dev);
    MessagingManager mm(gateway, store, crypto, &ratchet, &storage);
    mm.set_local_device_id(alice_dev);

    FileManager fm(gateway, crypto, &store, &storage, nullptr);
    fm.set_local_identity(alice, alice_dev);
    ASSERT_TRUE(fm.set_wire_chunk_size(4096U).is_ok());

    SyncManager sm(gateway, ClientConfig::create_default());
    sm.set_local_store(&store);
    sm.set_messaging_manager(&mm);
    sm.set_file_manager(&fm);
    sm.set_local_identity(alice, alice_dev);

    const auto conv = mm.open_direct_conversation(alice, bob, "Bob").value();
    const auto cid = conv.conversation_id();

    // Warm up pairwise ratchet session online
    ASSERT_TRUE(mm.stage_outbound_message(cid, alice, alice_dev, "Warmup").is_ok());
    gateway.clear_submitted_fanouts();

    // Start an upload that fails mid-transfer on chunk 1 due to network drop
    const auto upload_file = write_temp_file("offline_resume.bin", 9000U, 0x5AU);
    gateway.set_simulated_chunk_failure(1U, "Link dropped");
    ASSERT_TRUE(fm.start_upload(FileUploadRequest{
                                    .conversation_id = cid,
                                    .owner_user_id = alice,
                                    .owner_device_id = alice_dev,
                                    .peer_user_id = bob,
                                    .local_file_path = upload_file.string(),
                                    .dispatch_key_envelope = false,
                                })
                    .is_error());
    gateway.set_simulated_chunk_failure(std::nullopt);
    const std::string upload_tx_id = fm.list_transfers(cid).value()[0].transfer_id;

    // Flip offline via SyncManager and queue an outbound message
    ASSERT_TRUE(sm.set_simulated_offline(true).is_ok());
    ASSERT_TRUE(mm.stage_outbound_message(cid, alice, alice_dev, "Queued offline text").is_ok());
    EXPECT_EQ(mm.pending_outbox_count(), 1U);

    // Meanwhile Bob sends an inbound FileAttachmentKeyEnvelope while Alice is offline
    FileAttachmentKeyEnvelope inbound_env;
    inbound_env.file_id = "file-from-bob-offline";
    inbound_env.file_key_hex = common::configuration::SecretString(std::string(64U, 'd'));
    inbound_env.file_name = "briefing.pdf";
    inbound_env.plaintext_size_bytes = 2048ULL;
    inbound_env.encrypted_size_bytes = 2076ULL;
    inbound_env.chunk_size_bytes = 4096U;
    inbound_env.chunk_count = 1U;
    inbound_env.ciphertext_sha256 = std::string(64U, 'e');
    inbound_env.plaintext_sha256 = std::string(64U, 'f');

    // Use a separate MessagingManager without ratchet to verify inbound file envelope ingestion cleanly,
    // or encrypt the envelope for Alice's device using crypto_provider after detaching ratchet for inbound test
    mm.set_ratchet_session_manager(nullptr);
    RealtimeEvent file_ev;
    file_ev.type = RealtimeEventType::InboundDirectMessage;
    file_ev.conversation_id = cid;
    file_ev.message_id = MessageId("msg-bob-file-1");
    file_ev.actor_user_id = bob;
    file_ev.actor_device_id = bob_dev;
    file_ev.server_sequence_number = 5ULL;
    file_ev.direct_payload = crypto::PerDeviceDeliveryPayload{
        .recipient_device_id = alice_dev,
        .ciphertext_blob = crypto.encrypt_message(bob_dev, inbound_env.serialize()).value(),
    };
    gateway.set_simulated_conversation_messages(cid, {file_ev});

    // Reconnect via set_simulated_offline(false) -> automatically executes 4-phase catch-up!
    auto online_res = sm.set_simulated_offline(false);
    ASSERT_TRUE(online_res.is_ok());
    EXPECT_EQ(online_res.value(), ConnectivityState::Online);

    // Outbox drained, interrupted upload completed, AND inbound file envelope auto-registered in FileManager!
    EXPECT_EQ(mm.pending_outbox_count(), 0U);
    EXPECT_EQ(gateway.submitted_fanouts().size(), 1U);
    EXPECT_EQ(fm.get_transfer(upload_tx_id).value().status, FileTransferStatus::Completed);

    const auto all_transfers = fm.list_transfers(cid).value();
    ASSERT_EQ(all_transfers.size(), 2U);
    bool found_inbound_briefing = false;
    for (const auto& t : all_transfers) {
        if (t.file_id == "file-from-bob-offline") {
            found_inbound_briefing = true;
            EXPECT_EQ(t.direction, FileTransferDirection::Inbound);
            EXPECT_EQ(t.file_name, "briefing.pdf");
        }
    }
    EXPECT_TRUE(found_inbound_briefing);
}

} // namespace
} // namespace securecloud::client::application::managers::test
