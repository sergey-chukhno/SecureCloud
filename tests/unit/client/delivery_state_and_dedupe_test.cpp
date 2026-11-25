#include "application/client_config.hpp"
#include "application/managers/messaging_manager.hpp"
#include "domain/delivery_state.hpp"
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

TEST(DeliveryStateAndDedupeTest, MonotonicStateRankAndTransitionsEnforced) {
    EXPECT_LT(delivery_state_rank(DeliveryState::LocalPending), delivery_state_rank(DeliveryState::Submitting));
    EXPECT_LT(delivery_state_rank(DeliveryState::Submitting), delivery_state_rank(DeliveryState::Accepted));
    EXPECT_LT(delivery_state_rank(DeliveryState::Accepted), delivery_state_rank(DeliveryState::Delivering));
    EXPECT_LT(delivery_state_rank(DeliveryState::Delivering), delivery_state_rank(DeliveryState::Delivered));
    EXPECT_LT(delivery_state_rank(DeliveryState::Delivered), delivery_state_rank(DeliveryState::Read));

    // Forward transitions allowed
    EXPECT_TRUE(can_transition_delivery_state(DeliveryState::LocalPending, DeliveryState::Accepted));
    EXPECT_TRUE(can_transition_delivery_state(DeliveryState::Accepted, DeliveryState::Delivered));
    EXPECT_TRUE(can_transition_delivery_state(DeliveryState::Delivered, DeliveryState::Read));

    // Regressions rejected
    EXPECT_FALSE(can_transition_delivery_state(DeliveryState::Read, DeliveryState::Delivered));
    EXPECT_FALSE(can_transition_delivery_state(DeliveryState::Delivered, DeliveryState::Accepted));
    EXPECT_FALSE(can_transition_delivery_state(DeliveryState::Read, DeliveryState::Failed));
    EXPECT_FALSE(can_transition_delivery_state(DeliveryState::Delivered, DeliveryState::Failed));

    // Failure from pre-delivery and recovery from Failed allowed
    EXPECT_TRUE(can_transition_delivery_state(DeliveryState::Submitting, DeliveryState::Failed));
    EXPECT_TRUE(can_transition_delivery_state(DeliveryState::Failed, DeliveryState::Submitting));
    EXPECT_FALSE(can_transition_delivery_state(DeliveryState::Failed, DeliveryState::Read));
}

TEST(DeliveryStateAndDedupeTest, MessagingManagerRejectsStaleRegressionAndAdvancesSequence) {
    DefaultGatewayClient gateway(ClientConfig::create_default());
    MemoryLocalStore store;
    ASSERT_TRUE(store.open("").is_ok());
    StubCryptoProvider crypto;
    MessagingManager mm(gateway, store, crypto);

    const ConversationId cid("conv-mono-1");
    const MessageId mid("msg-mono-1");
    Message msg(mid, cid, UserId("alice"), DeviceId("alice-dev-1"), DeliveryState::Accepted,
                std::chrono::system_clock::now(), "ciphertext");
    ASSERT_TRUE(store.save_message(msg).is_ok());

    ASSERT_TRUE(mm.update_message_delivery_state(cid, mid, DeliveryState::Read, 12).is_ok());
    auto after_read = store.get_message(cid, mid).value();
    EXPECT_EQ(after_read.delivery_state(), DeliveryState::Read);
    EXPECT_EQ(after_read.server_sequence_number(), 12u);

    // Late stale Delivered + older seq 8 must not regress Read or sequence 12
    ASSERT_TRUE(mm.update_message_delivery_state(cid, mid, DeliveryState::Delivered, 8).is_ok());
    auto after_stale = store.get_message(cid, mid).value();
    EXPECT_EQ(after_stale.delivery_state(), DeliveryState::Read);
    EXPECT_EQ(after_stale.server_sequence_number(), 12u);
}

TEST(DeliveryStateAndDedupeTest, InboundRealtimeEventDeduplicatesAtLeastOnceDeliveries) {
    DefaultGatewayClient gateway(ClientConfig::create_default());
    MemoryLocalStore store;
    ASSERT_TRUE(store.open("").is_ok());
    StubCryptoProvider crypto;
    MessagingManager mm(gateway, store, crypto);

    const UserId alice("alice");
    const UserId bob("bob");
    const DeviceId bob_dev("bob-dev-1");
    auto conv = mm.open_direct_conversation(alice, bob, "Bob").value();

    auto enc = crypto.encrypt_message(bob_dev, "Hello idempotent world").value();

    RealtimeEvent ev;
    ev.type = RealtimeEventType::InboundDirectMessage;
    ev.conversation_id = conv.conversation_id();
    ev.message_id = MessageId("msg-srv-dedupe-1");
    ev.actor_user_id = bob;
    ev.actor_device_id = bob_dev;
    ev.server_sequence_number = 77;
    ev.direct_payload = crypto::PerDeviceDeliveryPayload{
        .recipient_user_id = {},
        .recipient_device_id = DeviceId("alice-dev-1"),
        .ciphertext_blob = enc,
        .ephemeral_public_key = {},
        .iv = {},
        .auth_tag = {},
    };

    auto first = mm.process_inbound_realtime_event(ev);
    ASSERT_TRUE(first.is_ok());
    ASSERT_TRUE(first.value().has_value());
    EXPECT_EQ(first.value()->server_sequence_number(), 77u);
    EXPECT_EQ(mm.get_conversation(conv.conversation_id()).value().unread_count(), 1u);

    // Re-delivery of same message_id must deduplicate without double unread increment or duplicate row
    auto second = mm.process_inbound_realtime_event(ev);
    ASSERT_TRUE(second.is_ok());
    ASSERT_TRUE(second.value().has_value());
    EXPECT_EQ(second.value()->message_id(), ev.message_id);
    EXPECT_EQ(mm.get_conversation_messages(conv.conversation_id(), 50).value().size(), 1u);
    EXPECT_EQ(mm.get_conversation(conv.conversation_id()).value().unread_count(), 1u);
}

} // namespace
} // namespace securecloud::client::application::managers::test
