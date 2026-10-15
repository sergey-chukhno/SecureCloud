#include "messaging/db/mock_scylla_session.hpp"
#include "messaging/domain/delivery_types.hpp"
#include "messaging/repository/scylla_delivery_state_repository.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::repository::test {
namespace {

using domain::ConversationId;
using domain::DeliveryState;
using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::MessageId;
using domain::MessagePriority;
using domain::RecipientDeliveryState;
using domain::UserId;

TEST(ScyllaDeliveryStateRepositoryTest, RejectsNullSession) {
    EXPECT_THROW(ScyllaDeliveryStateRepository(nullptr), std::invalid_argument);
}

TEST(ScyllaDeliveryStateRepositoryTest, SaveAndFetchPendingDeliveries) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto dev_id = DeviceId("dev-pixel-123");
    auto msg_id = MessageId::generate_v7();
    auto conv_id = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    DeviceDeliveryRecord rec;
    rec.device_id = dev_id;
    rec.delivery_bucket = "202610";
    rec.accepted_at = now;
    rec.message_id = msg_id;
    rec.conversation_id = conv_id;
    rec.message_sequence = 100;
    rec.message_priority = MessagePriority::Urgent;
    rec.delivery_state = DeliveryState::Pending;
    rec.attempt_count = 1;
    rec.next_retry_at = now + std::chrono::seconds(30);

    // 1. Save
    repo.save_pending_deliveries({rec});
    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "deliv_repo_insert_pending");

    // 2. Fetch
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    int64_t retry_ms = now_ms + 30000;

    db::ScyllaRow row({"device_id", "delivery_bucket", "accepted_at", "message_id", "conversation_id",
                       "message_sequence", "message_priority", "delivery_state", "attempt_count", "next_retry_at"},
                      {db::ScyllaValue(dev_id.str()), db::ScyllaValue("202610"), db::ScyllaValue(now_ms),
                       db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(conv_id.to_string()),
                       db::ScyllaValue(static_cast<int64_t>(100)), db::ScyllaValue("URGENT"),
                       db::ScyllaValue("PENDING"), db::ScyllaValue(1), db::ScyllaValue(retry_ms)});

    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_fetch_pending"), db::ScyllaQueryResult({row}));

    auto fetched = repo.fetch_pending_for_device(dev_id, "202610", 10);
    ASSERT_EQ(fetched.size(), 1U);
    EXPECT_EQ(fetched[0].device_id, dev_id);
    EXPECT_EQ(fetched[0].delivery_bucket, "202610");
    EXPECT_EQ(fetched[0].message_id, msg_id);
    EXPECT_EQ(fetched[0].conversation_id, conv_id);
    EXPECT_EQ(fetched[0].message_sequence, 100U);
    EXPECT_EQ(fetched[0].message_priority, MessagePriority::Urgent);
    EXPECT_EQ(fetched[0].delivery_state, DeliveryState::Pending);
    EXPECT_EQ(fetched[0].attempt_count, 1);
    ASSERT_TRUE(fetched[0].next_retry_at.has_value());
}

TEST(ScyllaDeliveryStateRepositoryTest, UpdateDeviceDeliveryStatus) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto dev_id = DeviceId("dev-1");
    auto msg_id = MessageId::generate_v7();
    auto now = std::chrono::system_clock::now();

    repo.update_device_delivery_status(dev_id, "202610", now, msg_id, DeliveryState::RetryWait, 2,
                                       now + std::chrono::seconds(60));

    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "deliv_repo_update_pending");
}

TEST(ScyllaDeliveryStateRepositoryTest, RecipientDeliveryStateLifecycle) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto msg_id = MessageId::generate_v7();
    auto dev_id = DeviceId("dev-recip-1");
    auto user_id = UserId("user-bob");
    auto now = std::chrono::system_clock::now();

    RecipientDeliveryState state;
    state.message_id = msg_id;
    state.recipient_device_id = dev_id;
    state.recipient_user_id = user_id;
    state.delivery_state = DeliveryState::Pending;

    // 1. Save recipient state
    repo.save_recipient_delivery_states({state});
    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "deliv_repo_insert_recip_state");

    // 2. Record delivery ack
    repo.record_delivery_ack(msg_id, dev_id, now);
    EXPECT_EQ(mock->get_executed_prepared().size(), 2U);
    EXPECT_EQ(mock->get_executed_prepared()[1].first.value(), "deliv_repo_delivery_ack");

    // 3. Record read ack
    repo.record_read_ack(msg_id, dev_id, now + std::chrono::seconds(5));
    EXPECT_EQ(mock->get_executed_prepared().size(), 3U);
    EXPECT_EQ(mock->get_executed_prepared()[2].first.value(), "deliv_repo_read_ack");

    // 4. Query states for message
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    db::ScyllaRow row(
        {"message_id", "recipient_device_id", "recipient_user_id", "delivery_state", "delivered_at", "read_at"},
        {db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(dev_id.str()), db::ScyllaValue(user_id.str()),
         db::ScyllaValue("READ"), db::ScyllaValue(now_ms), db::ScyllaValue(now_ms + 5000)});

    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_get_msg_states"), db::ScyllaQueryResult({row}));

    auto states = repo.get_delivery_states_for_message(msg_id);
    ASSERT_EQ(states.size(), 1U);
    EXPECT_EQ(states[0].message_id, msg_id);
    EXPECT_EQ(states[0].recipient_device_id, dev_id);
    EXPECT_EQ(states[0].recipient_user_id, user_id);
    EXPECT_EQ(states[0].delivery_state, DeliveryState::Read);
    ASSERT_TRUE(states[0].delivered_at.has_value());
    ASSERT_TRUE(states[0].read_at.has_value());
}

} // namespace
} // namespace securecloud::messaging::repository::test
