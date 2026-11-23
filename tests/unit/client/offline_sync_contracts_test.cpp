#include "application/client_config.hpp"
#include "domain/offline_sync_models.hpp"
#include "domain/realtime_events.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::client::tests {
namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure::adapters;

TEST(OfflineSyncDomainTest, ConnectivityStateConversionsAndTransitions) {
    EXPECT_EQ(to_string(ConnectivityState::Online), "Online");
    EXPECT_EQ(to_string(ConnectivityState::Offline), "Offline");
    EXPECT_EQ(to_string(ConnectivityState::Syncing), "Syncing");

    EXPECT_EQ(connectivity_state_from_string("Online"), ConnectivityState::Online);
    EXPECT_EQ(connectivity_state_from_string("Offline"), ConnectivityState::Offline);
    EXPECT_EQ(connectivity_state_from_string("Syncing"), ConnectivityState::Syncing);
    EXPECT_FALSE(connectivity_state_from_string("Connecting").has_value());

    // Identity transitions are always valid.
    EXPECT_TRUE(can_transition_connectivity_state(ConnectivityState::Online, ConnectivityState::Online));
    EXPECT_TRUE(can_transition_connectivity_state(ConnectivityState::Offline, ConnectivityState::Offline));
    EXPECT_TRUE(can_transition_connectivity_state(ConnectivityState::Syncing, ConnectivityState::Syncing));

    // Direct Offline -> Online is forbidden: catch-up Syncing must run first.
    EXPECT_FALSE(can_transition_connectivity_state(ConnectivityState::Offline, ConnectivityState::Online));

    // Standard lifecycle paths.
    EXPECT_TRUE(can_transition_connectivity_state(ConnectivityState::Offline, ConnectivityState::Syncing));
    EXPECT_TRUE(can_transition_connectivity_state(ConnectivityState::Syncing, ConnectivityState::Online));
    EXPECT_TRUE(can_transition_connectivity_state(ConnectivityState::Syncing, ConnectivityState::Offline));
    EXPECT_TRUE(can_transition_connectivity_state(ConnectivityState::Online, ConnectivityState::Offline));
    EXPECT_TRUE(can_transition_connectivity_state(ConnectivityState::Online, ConnectivityState::Syncing));
}

TEST(OfflineSyncDomainTest, OperationTypeStringRoundTrips) {
    const std::array<OfflineOutboxOperationType, 4> types = {
        OfflineOutboxOperationType::EncryptedMessageSubmission,
        OfflineOutboxOperationType::DeliveryAck,
        OfflineOutboxOperationType::ReadReceipt,
        OfflineOutboxOperationType::FileKeyEnvelopeSubmission,
    };

    for (const auto op : types) {
        const auto parsed = offline_outbox_operation_type_from_string(to_string(op));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(*parsed, op);
    }
    EXPECT_FALSE(offline_outbox_operation_type_from_string("UnknownOp").has_value());
}

TEST(OfflineSyncDomainTest, FanOutPayloadHandlesBinaryNonUtf8AndGroupEnvelopeJsonRoundTrip) {
    const std::array<char, 8> raw_cipher = {'\xFF', '\x00', '\xFE', '\x80', '\xDE', '\xAD', '\xBE', '\xEF'};

    OfflineOutboxFanOutPayload payload;
    payload.conversation_id = ConversationId("conv-offline-fanout-1");
    payload.idempotency_key = "idem-offline-001";
    payload.priority = 10;
    payload.device_payloads.push_back(crypto::PerDeviceDeliveryPayload{
        .recipient_user_id = UserId("bob"),
        .recipient_device_id = DeviceId("bob-dev-1"),
        .ciphertext_blob = std::string(raw_cipher.data(), raw_cipher.size()),
        .ephemeral_public_key = std::vector<uint8_t>{0x01U, 0x81U, 0x00U, 0x7FU},
        .iv = std::vector<uint8_t>{0xAAU, 0xBBU, 0x00U, 0xCCU},
        .auth_tag = std::vector<uint8_t>{0x10U, 0x99U, 0xEEU, 0xFFU},
        .algorithm = "X25519-DoubleRatchet-AES256GCM",
    });
    payload.group_envelope_bytes = std::vector<uint8_t>{0x00U, 0xFFU, 0x7FU, 0x80U, 0xAAU, 0x55U};

    const std::string encoded = payload.to_json();
    const auto decoded = OfflineOutboxFanOutPayload::from_json(encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, payload);
    ASSERT_EQ(decoded->device_payloads.size(), 1U);
    EXPECT_EQ(decoded->device_payloads[0].ciphertext_blob.size(), raw_cipher.size());
    ASSERT_TRUE(decoded->group_envelope_bytes.has_value());
    EXPECT_EQ(*decoded->group_envelope_bytes, *payload.group_envelope_bytes);

    EXPECT_FALSE(OfflineOutboxFanOutPayload::from_json("not-json").has_value());
    EXPECT_FALSE(OfflineOutboxFanOutPayload::from_json(R"({"idempotency_key":"missing-conv"})").has_value());
    EXPECT_FALSE(
        OfflineOutboxFanOutPayload::from_json(
            R"({"conversation_id":"c1","idempotency_key":"k1","device_payloads":[{"recipient_user_id":"u1","recipient_device_id":"d1","ciphertext_blob_hex":"zz"}]})")
            .has_value());
}

TEST(OfflineSyncDomainTest, AckReceiptAndOutboxRecordJsonRoundTrips) {
    OfflineOutboxDeliveryAckPayload ack;
    ack.message_id = MessageId("msg-ack-1");
    ack.recipient_device_id = DeviceId("dev-1");
    ack.delivered_at_ms = 1700000001234LL;
    const auto decoded_ack = OfflineOutboxDeliveryAckPayload::from_json(ack.to_json());
    ASSERT_TRUE(decoded_ack.has_value());
    EXPECT_EQ(*decoded_ack, ack);
    EXPECT_FALSE(OfflineOutboxDeliveryAckPayload::from_json(R"({"message_id":"m1"})").has_value());

    OfflineOutboxReadReceiptPayload receipt;
    receipt.conversation_id = ConversationId("conv-rcpt-1");
    receipt.message_id = MessageId("msg-rcpt-1");
    receipt.reader_device_id = DeviceId("dev-2");
    receipt.read_at_ms = 1700000005678LL;
    const auto decoded_receipt = OfflineOutboxReadReceiptPayload::from_json(receipt.to_json());
    ASSERT_TRUE(decoded_receipt.has_value());
    EXPECT_EQ(*decoded_receipt, receipt);
    EXPECT_FALSE(OfflineOutboxReadReceiptPayload::from_json(R"({"conversation_id":"c1"})").has_value());

    OfflineOutboxRecord rec;
    rec.outbox_id = "outbox-001";
    rec.operation_type = OfflineOutboxOperationType::FileKeyEnvelopeSubmission;
    rec.conversation_id = ConversationId("conv-1");
    rec.message_id = MessageId("msg-1");
    rec.transfer_id = "tr-file-1";
    rec.idempotency_key = "idem-rec-1";
    rec.priority = 5;
    rec.payload_json = ack.to_json();
    rec.attempt_count = 2U;
    rec.created_at_ms = 1700000000000LL;
    rec.next_retry_at_ms = 1700000004000LL;
    rec.expires_at_ms = 1700604800000LL;
    rec.last_error = "Temporary offline timeout";

    const auto decoded_rec = OfflineOutboxRecord::from_json(rec.to_json());
    ASSERT_TRUE(decoded_rec.has_value());
    EXPECT_EQ(*decoded_rec, rec);

    EXPECT_FALSE(OfflineOutboxRecord::from_json("invalid").has_value());
    EXPECT_FALSE(OfflineOutboxRecord::from_json(R"({"outbox_id":"o1","operation_type":"BadOp","conversation_id":"c1"})")
                     .has_value());
    EXPECT_FALSE(
        OfflineOutboxRecord::from_json(R"({"outbox_id":"","operation_type":"DeliveryAck","conversation_id":"c1"})")
            .has_value());
}

TEST(OfflineSyncDomainTest, SyncCursorRecordJsonRoundTripAndMonotonicAdvance) {
    SyncCursorRecord cursor;
    cursor.device_id = DeviceId("dev-sync-1");
    cursor.conversation_id = ConversationId("conv-sync-1");
    cursor.last_delivered_sequence = 40ULL;
    cursor.last_sync_timestamp_ms = 1700000010000LL;
    cursor.sync_version = 2;

    const auto decoded = SyncCursorRecord::from_json(cursor.to_json());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, cursor);

    // Optional conversation_id allows global device-level cursor, while empty/missing device_id fails closed
    const auto global_cursor = SyncCursorRecord::from_json(R"({"device_id":"d1"})");
    ASSERT_TRUE(global_cursor.has_value());
    EXPECT_TRUE(global_cursor->conversation_id.empty());
    EXPECT_FALSE(SyncCursorRecord::from_json(R"({"conversation_id":"c1"})").has_value());
    EXPECT_FALSE(SyncCursorRecord::from_json(R"({"device_id":""})").has_value());

    EXPECT_FALSE(cursor.advance_monotonically(40ULL, 1700000020000LL));
    EXPECT_FALSE(cursor.advance_monotonically(12ULL, 1700000020000LL));
    EXPECT_EQ(cursor.last_delivered_sequence, 40ULL);
    EXPECT_EQ(cursor.last_sync_timestamp_ms, 1700000010000LL);

    EXPECT_TRUE(cursor.advance_monotonically(55ULL, 1700000030000LL));
    EXPECT_EQ(cursor.last_delivered_sequence, 55ULL);
    EXPECT_EQ(cursor.last_sync_timestamp_ms, 1700000030000LL);
}

TEST(OfflineSyncGatewayContractsTest, GetAndUpdateSyncCursorEnforceValidationAndMonotonicity) {
    DefaultGatewayClient gateway(ClientConfig::create_default());
    const DeviceId dev("dev-gw-1");
    const ConversationId conv("conv-gw-1");

    // Validation and default state
    EXPECT_TRUE(gateway.get_sync_cursor(DeviceId{}, conv).is_error());
    auto initial = gateway.get_sync_cursor(dev, conv);
    ASSERT_TRUE(initial.is_ok());
    EXPECT_EQ(initial.value().device_id, dev);
    EXPECT_EQ(initial.value().conversation_id, conv);
    EXPECT_EQ(initial.value().last_delivered_sequence, 0ULL);
    EXPECT_EQ(initial.value().sync_version, 1);

    // First update sets timestamp automatically if omitted (<= 0)
    auto upd1 = gateway.update_sync_cursor(SyncCursorRecord{
        .device_id = dev,
        .conversation_id = conv,
        .last_delivered_sequence = 25ULL,
        .last_sync_timestamp_ms = 0LL,
        .sync_version = 1,
    });
    ASSERT_TRUE(upd1.is_ok());
    EXPECT_EQ(upd1.value().last_delivered_sequence, 25ULL);
    EXPECT_GT(upd1.value().last_sync_timestamp_ms, 0LL);

    // Regressing sequence update does not downgrade stored cursor
    auto upd_stale = gateway.update_sync_cursor(SyncCursorRecord{
        .device_id = dev,
        .conversation_id = conv,
        .last_delivered_sequence = 10ULL,
        .last_sync_timestamp_ms = 1700000099999LL,
        .sync_version = 1,
    });
    ASSERT_TRUE(upd_stale.is_ok());
    EXPECT_EQ(upd_stale.value().last_delivered_sequence, 25ULL);

    // Higher sequence & sync_version advance monotonically (timestamps also remain monotonic)
    const int64_t next_ts = upd1.value().last_sync_timestamp_ms + 5000LL;
    auto upd2 = gateway.update_sync_cursor(SyncCursorRecord{
        .device_id = dev,
        .conversation_id = conv,
        .last_delivered_sequence = 60ULL,
        .last_sync_timestamp_ms = next_ts,
        .sync_version = 3,
    });
    ASSERT_TRUE(upd2.is_ok());
    EXPECT_EQ(upd2.value().last_delivered_sequence, 60ULL);
    EXPECT_EQ(upd2.value().last_sync_timestamp_ms, next_ts);
    EXPECT_EQ(upd2.value().sync_version, 3);

    // Test hook pre-seeds cursor cleanly
    const ConversationId conv2("conv-gw-2");
    gateway.set_simulated_sync_cursor(SyncCursorRecord{
        .device_id = dev,
        .conversation_id = conv2,
        .last_delivered_sequence = 88ULL,
        .last_sync_timestamp_ms = 1700000200000LL,
        .sync_version = 2,
    });
    auto seeded = gateway.get_sync_cursor(dev, conv2);
    ASSERT_TRUE(seeded.is_ok());
    EXPECT_EQ(seeded.value().last_delivered_sequence, 88ULL);

    // Simulated offline network failure
    gateway.set_simulated_failure(true, "Offline mode");
    EXPECT_TRUE(gateway.get_sync_cursor(dev, conv).is_error());
    EXPECT_TRUE(gateway.update_sync_cursor(upd2.value()).is_error());
}

TEST(OfflineSyncGatewayContractsTest, ListRemoteConversationsFiltersParticipantsAndHonorsLimit) {
    DefaultGatewayClient gateway(ClientConfig::create_default());
    const UserId alice("alice");
    const UserId bob("bob");
    const UserId charlie("charlie");

    EXPECT_TRUE(gateway.list_remote_conversations(UserId{}, 10).is_error());

    gateway.set_simulated_remote_conversations({
        RemoteConversationSummary{
            .conversation_id = ConversationId("c-alice-bob"),
            .type = ConversationType::Direct,
            .title = "Alice & Bob",
            .creator_user_id = alice,
            .created_at_ms = 1700000001000LL,
            .participant_user_ids = {alice, bob},
        },
        RemoteConversationSummary{
            .conversation_id = ConversationId("c-bob-charlie"),
            .type = ConversationType::Direct,
            .title = "Bob & Charlie",
            .creator_user_id = bob,
            .created_at_ms = 1700000002000LL,
            .participant_user_ids = {bob, charlie},
        },
        RemoteConversationSummary{
            .conversation_id = ConversationId("c-group-all"),
            .type = ConversationType::Group,
            .title = "Ops Channel",
            .creator_user_id = bob,
            .created_at_ms = 1700000003000LL,
            .participant_user_ids = {alice, bob, charlie},
        },
        RemoteConversationSummary{
            .conversation_id = ConversationId("c-wildcard"),
            .type = ConversationType::Group,
            .title = "Broadcast",
            .creator_user_id = charlie,
            .created_at_ms = 1700000004000LL,
            .participant_user_ids = {},
        },
    });

    auto alice_convs = gateway.list_remote_conversations(alice, 10);
    ASSERT_TRUE(alice_convs.is_ok());
    ASSERT_EQ(alice_convs.value().size(), 3U);
    EXPECT_EQ(alice_convs.value()[0].conversation_id, ConversationId("c-alice-bob"));
    EXPECT_EQ(alice_convs.value()[1].conversation_id, ConversationId("c-group-all"));
    EXPECT_EQ(alice_convs.value()[2].conversation_id, ConversationId("c-wildcard"));

    auto alice_limited = gateway.list_remote_conversations(alice, 2);
    ASSERT_TRUE(alice_limited.is_ok());
    EXPECT_EQ(alice_limited.value().size(), 2U);

    gateway.set_simulated_failure(true, "Offline");
    EXPECT_TRUE(gateway.list_remote_conversations(alice, 10).is_error());
}

TEST(OfflineSyncGatewayContractsTest, MultiPageFetchConversationMessagesSortsAndTracksNextSequenceAndCursor) {
    DefaultGatewayClient gateway(ClientConfig::create_default());
    const ConversationId cid("conv-catchup-120");
    const DeviceId did("dev-catchup-1");

    gateway.set_simulated_sync_cursor(SyncCursorRecord{
        .device_id = did,
        .conversation_id = cid,
        .last_delivered_sequence = 500ULL,
        .last_sync_timestamp_ms = 1700000500000LL,
        .sync_version = 4,
    });

    // Push 120 events in reverse order to verify deterministic ascending sorting & slicing (50 + 50 + 20)
    std::vector<RealtimeEvent> events;
    events.reserve(120U);
    for (uint64_t seq = 120ULL; seq >= 1ULL; --seq) {
        RealtimeEvent ev;
        ev.type = RealtimeEventType::InboundDirectMessage;
        ev.conversation_id = cid;
        ev.message_id = MessageId("msg-" + std::to_string(seq));
        ev.server_sequence_number = seq;
        events.push_back(std::move(ev));
    }
    gateway.set_simulated_conversation_messages(cid, std::move(events));

    auto page1 = gateway.fetch_conversation_messages(cid, did, 0ULL, 50U);
    ASSERT_TRUE(page1.is_ok());
    EXPECT_TRUE(page1.value().has_more);
    EXPECT_EQ(page1.value().events.size(), 50U);
    EXPECT_EQ(page1.value().events.front().server_sequence_number, 1ULL);
    EXPECT_EQ(page1.value().events.back().server_sequence_number, 50ULL);
    EXPECT_EQ(page1.value().next_sequence, 50ULL);
    EXPECT_EQ(page1.value().latest_sequence, 50ULL);
    ASSERT_TRUE(page1.value().cursor.has_value());
    EXPECT_EQ(page1.value().cursor->last_delivered_sequence, 500ULL);
    EXPECT_EQ(page1.value().cursor->sync_version, 4);

    auto page2 = gateway.fetch_conversation_messages(cid, did, page1.value().next_sequence, 50U);
    ASSERT_TRUE(page2.is_ok());
    EXPECT_TRUE(page2.value().has_more);
    EXPECT_EQ(page2.value().events.size(), 50U);
    EXPECT_EQ(page2.value().events.front().server_sequence_number, 51ULL);
    EXPECT_EQ(page2.value().events.back().server_sequence_number, 100ULL);
    EXPECT_EQ(page2.value().next_sequence, 100ULL);
    EXPECT_EQ(page2.value().latest_sequence, 100ULL);

    auto page3 = gateway.fetch_conversation_messages(cid, did, page2.value().next_sequence, 50U);
    ASSERT_TRUE(page3.is_ok());
    EXPECT_FALSE(page3.value().has_more);
    EXPECT_EQ(page3.value().events.size(), 20U);
    EXPECT_EQ(page3.value().events.front().server_sequence_number, 101ULL);
    EXPECT_EQ(page3.value().events.back().server_sequence_number, 120ULL);
    EXPECT_EQ(page3.value().next_sequence, 120ULL);
    EXPECT_EQ(page3.value().latest_sequence, 120ULL);

    const CatchUpSyncReport r1{
        .outbox_flushed_count = 3U,
        .outbox_remaining_count = 0U,
        .messages_merged_count = 120U,
        .duplicates_skipped_count = 2U,
        .conversations_reconciled_count = 1U,
        .contacts_reconciled_count = 4U,
        .transfers_resumed_count = 1U,
    };
    const CatchUpSyncReport r2 = r1;
    EXPECT_EQ(r1, r2);
}

} // namespace
} // namespace securecloud::client::tests
