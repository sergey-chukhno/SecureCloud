#include "application/client_config.hpp"
#include "domain/realtime_events.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"

#include <gtest/gtest.h>
#include <vector>

namespace securecloud::client::tests {
namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure::adapters;

TEST(RealtimeGatewayContractsTest, AcknowledgeDeliveryAndReadReceiptRecordAndValidate) {
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const MessageId mid("msg-101");
    const ConversationId cid("conv-101");
    const DeviceId did("dev-101");

    auto ack_res = gateway.acknowledge_delivery(mid, did, 1700000001000);
    ASSERT_TRUE(ack_res.is_ok());
    EXPECT_EQ(ack_res.value(), DeliveryState::Delivered);
    ASSERT_EQ(gateway.sent_delivery_acks().size(), 1u);
    EXPECT_EQ(gateway.sent_delivery_acks()[0].message_id, mid);
    EXPECT_EQ(gateway.sent_delivery_acks()[0].recipient_device_id, did);

    auto read_res = gateway.send_read_receipt(cid, mid, did, 1700000002000);
    ASSERT_TRUE(read_res.is_ok());
    EXPECT_EQ(read_res.value(), DeliveryState::Read);
    ASSERT_EQ(gateway.sent_read_receipts().size(), 1u);
    EXPECT_EQ(gateway.sent_read_receipts()[0].conversation_id, cid);
    EXPECT_EQ(gateway.sent_read_receipts()[0].message_id, mid);

    EXPECT_TRUE(gateway.acknowledge_delivery(MessageId{}, did, 0).is_error());
    EXPECT_TRUE(gateway.send_read_receipt(ConversationId{}, mid, did, 0).is_error());

    gateway.set_simulated_failure(true, "Simulated offline");
    EXPECT_TRUE(gateway.acknowledge_delivery(mid, did, 1700000003000).is_error());
    EXPECT_TRUE(gateway.send_read_receipt(cid, mid, did, 1700000003000).is_error());
}

TEST(RealtimeGatewayContractsTest, FetchConversationMessagesRespectsSinceSequenceAndPagination) {
    DefaultGatewayClient gateway(ClientConfig::create_default());
    const ConversationId cid("conv-page-1");
    const DeviceId did("dev-reader-1");

    std::vector<RealtimeEvent> events;
    for (uint64_t seq = 1; seq <= 3; ++seq) {
        RealtimeEvent ev;
        ev.type = RealtimeEventType::InboundDirectMessage;
        ev.server_sequence_number = seq;
        ev.conversation_id = cid;
        ev.message_id = MessageId("msg-seq-" + std::to_string(seq));
        events.push_back(ev);
    }
    gateway.set_simulated_conversation_messages(cid, std::move(events));

    auto page1 = gateway.fetch_conversation_messages(cid, did, 0, 2);
    ASSERT_TRUE(page1.is_ok());
    EXPECT_TRUE(page1.value().has_more);
    EXPECT_EQ(page1.value().latest_sequence, 2u);
    ASSERT_EQ(page1.value().events.size(), 2u);
    EXPECT_EQ(page1.value().events[0].server_sequence_number, 1u);
    EXPECT_EQ(page1.value().events[1].server_sequence_number, 2u);

    auto page2 = gateway.fetch_conversation_messages(cid, did, page1.value().latest_sequence, 2);
    ASSERT_TRUE(page2.is_ok());
    EXPECT_FALSE(page2.value().has_more);
    EXPECT_EQ(page2.value().latest_sequence, 3u);
    ASSERT_EQ(page2.value().events.size(), 1u);
    EXPECT_EQ(page2.value().events[0].message_id, MessageId("msg-seq-3"));
}

TEST(RealtimeGatewayContractsTest, DeliveryStatusAndRealtimeSubscriptionLifecycle) {
    DefaultGatewayClient gateway(ClientConfig::create_default());
    const ConversationId cid("conv-rt-1");
    const MessageId mid("msg-rt-1");

    gateway.set_simulated_delivery_status(mid, MessageDeliveryStatusInfo{
                                                   .message_id = mid,
                                                   .delivery_state = DeliveryState::Read,
                                                   .server_sequence_number = 42,
                                                   .updated_at_ms = 1700000010000,
                                               });

    auto status_res = gateway.get_message_delivery_status(cid, mid);
    ASSERT_TRUE(status_res.is_ok());
    EXPECT_EQ(status_res.value().delivery_state, DeliveryState::Read);
    EXPECT_EQ(status_res.value().server_sequence_number, 42u);

    std::vector<RealtimeEvent> received;
    const uint64_t sub_id = gateway.subscribe_realtime_events([&](const RealtimeEvent& ev) { received.push_back(ev); });

    RealtimeEvent ack_ev;
    ack_ev.type = RealtimeEventType::DeliveryAck;
    ack_ev.conversation_id = cid;
    ack_ev.message_id = mid;
    ack_ev.server_sequence_number = 42;
    gateway.emit_realtime_event(ack_ev);
    ASSERT_EQ(received.size(), 1u);
    EXPECT_EQ(received[0].type, RealtimeEventType::DeliveryAck);

    gateway.unsubscribe_realtime_events(sub_id);
    gateway.emit_realtime_event(ack_ev);
    EXPECT_EQ(received.size(), 1u);
}

TEST(RealtimeGatewayContractsTest, DefaultPolicyConfigsAreValid) {
    RetryPolicyConfig retry_cfg;
    EXPECT_EQ(retry_cfg.max_attempts, 5u);
    EXPECT_EQ(retry_cfg.initial_backoff.count(), 500);
    EXPECT_EQ(retry_cfg.max_backoff.count(), 30000);
    EXPECT_DOUBLE_EQ(retry_cfg.jitter_ratio, 0.25);

    ReadReceiptPolicy receipt_policy;
    EXPECT_TRUE(receipt_policy.send_read_receipts_enabled);
    EXPECT_EQ(ReadReceiptPolicy::kStorageKey, "messaging.privacy.send_read_receipts");
}

} // namespace
} // namespace securecloud::client::tests
