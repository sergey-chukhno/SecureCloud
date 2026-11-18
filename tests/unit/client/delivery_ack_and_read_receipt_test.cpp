#include "application/client_config.hpp"
#include "application/managers/messaging_manager.hpp"
#include "domain/realtime_events.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"

#include <gtest/gtest.h>

namespace securecloud::client::application::managers::test {
namespace {

using namespace domain;
using namespace infrastructure::adapters;

TEST(DeliveryAckAndReadReceiptTest, InboundPersistenceDispatchesTransportDeliveryAck) {
    DefaultGatewayClient gateway(ClientConfig::create_default());
    MemoryLocalStore store;
    ASSERT_TRUE(store.open("").is_ok());
    StubCryptoProvider crypto;
    MemorySecureStorage secure_storage;
    MessagingManager mm(gateway, store, crypto, nullptr, &secure_storage);
    mm.set_local_device_id(DeviceId("alice-dev-1"));

    const UserId alice("alice");
    const UserId bob("bob");
    const DeviceId bob_dev("bob-dev-1");
    auto conv = mm.open_direct_conversation(alice, bob, "Bob").value();

    RealtimeEvent ev;
    ev.type = RealtimeEventType::InboundDirectMessage;
    ev.conversation_id = conv.conversation_id();
    ev.message_id = MessageId("msg-ack-1");
    ev.actor_user_id = bob;
    ev.actor_device_id = bob_dev;
    ev.server_sequence_number = 10;
    ev.direct_payload = crypto::PerDeviceDeliveryPayload{
        .recipient_device_id = DeviceId("alice-dev-1"),
        .ciphertext_blob = crypto.encrypt_message(bob_dev, "Ping").value(),
    };

    ASSERT_TRUE(mm.process_inbound_realtime_event(ev).is_ok());
    ASSERT_EQ(gateway.sent_delivery_acks().size(), 1u);
    EXPECT_EQ(gateway.sent_delivery_acks()[0].message_id, ev.message_id);
    EXPECT_EQ(gateway.sent_delivery_acks()[0].recipient_device_id, DeviceId("alice-dev-1"));
    EXPECT_TRUE(gateway.sent_read_receipts().empty());

    // Idempotent re-delivery re-sends ACK without duplicating the message
    ASSERT_TRUE(mm.process_inbound_realtime_event(ev).is_ok());
    EXPECT_EQ(gateway.sent_delivery_acks().size(), 2u);
    EXPECT_EQ(mm.get_conversation_messages(conv.conversation_id(), 50).value().size(), 1u);
}

TEST(DeliveryAckAndReadReceiptTest, ReadReceiptPolicyGatedAndPersistedInSecureStorage) {
    DefaultGatewayClient gateway(ClientConfig::create_default());
    MemoryLocalStore store;
    ASSERT_TRUE(store.open("").is_ok());
    StubCryptoProvider crypto;
    MemorySecureStorage secure_storage;

    const UserId alice("alice");
    const DeviceId alice_dev("alice-dev-1");
    const UserId bob("bob");
    const DeviceId bob_dev("bob-dev-1");

    ConversationId cid("conv-receipt-1");
    {
        MessagingManager mm(gateway, store, crypto, nullptr, &secure_storage);
        mm.set_local_device_id(alice_dev);
        EXPECT_TRUE(mm.read_receipts_enabled());

        auto conv = mm.open_direct_conversation(alice, bob, "Bob").value();
        cid = conv.conversation_id();

        RealtimeEvent ev;
        ev.type = RealtimeEventType::InboundDirectMessage;
        ev.conversation_id = cid;
        ev.message_id = MessageId("msg-rcpt-1");
        ev.actor_user_id = bob;
        ev.actor_device_id = bob_dev;
        ev.server_sequence_number = 1;
        ev.direct_payload = crypto::PerDeviceDeliveryPayload{
            .recipient_device_id = alice_dev,
            .ciphertext_blob = crypto.encrypt_message(bob_dev, "First").value(),
        };
        ASSERT_TRUE(mm.process_inbound_realtime_event(ev).is_ok());

        // With read receipts enabled (default), mark_conversation_read sends ReadReceipt
        ASSERT_TRUE(mm.mark_conversation_read(cid, alice, alice_dev).is_ok());
        EXPECT_EQ(mm.get_conversation(cid).value().unread_count(), 0u);
        ASSERT_EQ(gateway.sent_read_receipts().size(), 1u);
        EXPECT_EQ(gateway.sent_read_receipts()[0].message_id, MessageId("msg-rcpt-1"));

        // Disable read receipts -> persisted in ISecureStorage
        ASSERT_TRUE(mm.set_read_receipts_enabled(false).is_ok());
        EXPECT_FALSE(mm.read_receipts_enabled());
    }

    gateway.clear_sent_receipts();

    // Re-instantiate MessagingManager against same ISecureStorage -> policy remains disabled
    MessagingManager restarted_mm(gateway, store, crypto, nullptr, &secure_storage);
    restarted_mm.set_local_device_id(alice_dev);
    EXPECT_FALSE(restarted_mm.read_receipts_enabled());

    RealtimeEvent ev2;
    ev2.type = RealtimeEventType::InboundDirectMessage;
    ev2.conversation_id = cid;
    ev2.message_id = MessageId("msg-rcpt-2");
    ev2.actor_user_id = bob;
    ev2.actor_device_id = bob_dev;
    ev2.server_sequence_number = 2;
    ev2.direct_payload = crypto::PerDeviceDeliveryPayload{
        .recipient_device_id = alice_dev,
        .ciphertext_blob = crypto.encrypt_message(bob_dev, "Second").value(),
    };
    ASSERT_TRUE(restarted_mm.process_inbound_realtime_event(ev2).is_ok());
    // Transport ACK still sent even when read receipts are disabled
    EXPECT_EQ(gateway.sent_delivery_acks().size(), 1u);

    // Local unread clears to 0, but outbound ReadReceipt is suppressed
    ASSERT_TRUE(restarted_mm.mark_conversation_read(cid, alice, alice_dev).is_ok());
    EXPECT_EQ(restarted_mm.get_conversation(cid).value().unread_count(), 0u);
    EXPECT_TRUE(gateway.sent_read_receipts().empty());
}

TEST(DeliveryAckAndReadReceiptTest, InboundAckAndReadEventsAdvanceOutboundTicksMonotonically) {
    DefaultGatewayClient gateway(ClientConfig::create_default());
    MemoryLocalStore store;
    ASSERT_TRUE(store.open("").is_ok());
    StubCryptoProvider crypto;
    MessagingManager mm(gateway, store, crypto);

    const ConversationId cid("conv-ticks-1");
    const MessageId mid("msg-out-1");
    Message out(mid, cid, UserId("alice"), DeviceId("alice-dev-1"), DeliveryState::Accepted,
                std::chrono::system_clock::now(), "Hello");
    ASSERT_TRUE(store.save_message(out).is_ok());

    RealtimeEvent ack_ev;
    ack_ev.type = RealtimeEventType::DeliveryAck;
    ack_ev.conversation_id = cid;
    ack_ev.message_id = mid;
    ack_ev.server_sequence_number = 5;
    ASSERT_TRUE(mm.process_inbound_realtime_event(ack_ev).is_ok());
    EXPECT_EQ(store.get_message(cid, mid).value().delivery_state(), DeliveryState::Delivered);

    RealtimeEvent read_ev;
    read_ev.type = RealtimeEventType::ReadReceipt;
    read_ev.conversation_id = cid;
    read_ev.message_id = mid;
    read_ev.server_sequence_number = 6;
    ASSERT_TRUE(mm.process_inbound_realtime_event(read_ev).is_ok());
    EXPECT_EQ(store.get_message(cid, mid).value().delivery_state(), DeliveryState::Read);
    EXPECT_EQ(store.get_message(cid, mid).value().server_sequence_number(), 6u);

    // Late duplicate DeliveryAck must not regress Read back to Delivered
    ASSERT_TRUE(mm.process_inbound_realtime_event(ack_ev).is_ok());
    EXPECT_EQ(store.get_message(cid, mid).value().delivery_state(), DeliveryState::Read);
}

} // namespace
} // namespace securecloud::client::application::managers::test
