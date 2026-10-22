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

TEST(ScyllaDeliveryStateRepositoryTest, UpdateDeliveryStateMonotonic_ValidForwardTransition) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto msg_id = MessageId::generate_v7();
    auto dev_id = DeviceId("dev-phone-1");
    auto user_id = UserId("user-alice");
    auto now = std::chrono::system_clock::now();

    // Device is currently in DELIVERING state
    db::ScyllaRow row(
        {"message_id", "recipient_device_id", "recipient_user_id", "delivery_state", "delivered_at", "read_at"},
        {db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(dev_id.str()), db::ScyllaValue(user_id.str()),
         db::ScyllaValue("DELIVERING"), db::ScyllaValue(), db::ScyllaValue()});

    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_get_single_state"), db::ScyllaQueryResult({row}));

    // Forward transition: DELIVERING -> DELIVERED
    bool updated = repo.update_delivery_state_monotonic(msg_id, dev_id, DeliveryState::Delivered, now);
    EXPECT_TRUE(updated);

    const auto& executed = mock->get_executed_prepared();
    ASSERT_GE(executed.size(), 2U);
    EXPECT_EQ(executed[0].first.value(), "deliv_repo_get_single_state");
    EXPECT_EQ(executed[1].first.value(), "deliv_repo_update_state");
}

TEST(ScyllaDeliveryStateRepositoryTest, UpdateDeliveryStateMonotonic_RejectsRegression) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto msg_id = MessageId::generate_v7();
    auto dev_id = DeviceId("dev-phone-1");
    auto user_id = UserId("user-alice");
    auto now = std::chrono::system_clock::now();
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    // Device is already DELIVERED
    db::ScyllaRow row(
        {"message_id", "recipient_device_id", "recipient_user_id", "delivery_state", "delivered_at", "read_at"},
        {db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(dev_id.str()), db::ScyllaValue(user_id.str()),
         db::ScyllaValue("DELIVERED"), db::ScyllaValue(now_ms), db::ScyllaValue()});

    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_get_single_state"), db::ScyllaQueryResult({row}));

    // Regression 1: DELIVERED -> RETRY_WAIT must be rejected
    bool reg1 = repo.update_delivery_state_monotonic(msg_id, dev_id, DeliveryState::RetryWait, now);
    EXPECT_FALSE(reg1);

    // Regression 2: DELIVERED -> QUEUED must be rejected
    bool reg2 = repo.update_delivery_state_monotonic(msg_id, dev_id, DeliveryState::Queued, now);
    EXPECT_FALSE(reg2);

    // Regression 3: DELIVERED -> DELIVERING must be rejected
    bool reg3 = repo.update_delivery_state_monotonic(msg_id, dev_id, DeliveryState::Delivering, now);
    EXPECT_FALSE(reg3);

    // Verify deliv_repo_update_state was NEVER invoked
    for (const auto& exec : mock->get_executed_prepared()) {
        EXPECT_NE(exec.first.value(), "deliv_repo_update_state");
    }
}

TEST(ScyllaDeliveryStateRepositoryTest, UpdateDeliveryStateMonotonic_TerminalExpired) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto msg_id = MessageId::generate_v7();
    auto dev_id = DeviceId("dev-phone-1");
    auto user_id = UserId("user-alice");
    auto now = std::chrono::system_clock::now();

    // Device is EXPIRED
    db::ScyllaRow row(
        {"message_id", "recipient_device_id", "recipient_user_id", "delivery_state", "delivered_at", "read_at"},
        {db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(dev_id.str()), db::ScyllaValue(user_id.str()),
         db::ScyllaValue("EXPIRED"), db::ScyllaValue(), db::ScyllaValue()});

    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_get_single_state"), db::ScyllaQueryResult({row}));

    // Cannot transition from EXPIRED to DELIVERED
    bool res1 = repo.update_delivery_state_monotonic(msg_id, dev_id, DeliveryState::Delivered, now);
    EXPECT_FALSE(res1);

    // Cannot transition from EXPIRED to DELIVERING
    bool res2 = repo.update_delivery_state_monotonic(msg_id, dev_id, DeliveryState::Delivering, now);
    EXPECT_FALSE(res2);

    // Idempotent re-application of EXPIRED returns true
    bool res3 = repo.update_delivery_state_monotonic(msg_id, dev_id, DeliveryState::Expired, now);
    EXPECT_TRUE(res3);
}

TEST(ScyllaDeliveryStateRepositoryTest, UpdateDeliveryStateMonotonic_Idempotency) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto msg_id = MessageId::generate_v7();
    auto dev_id = DeviceId("dev-phone-1");
    auto user_id = UserId("user-alice");
    auto now = std::chrono::system_clock::now();
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    // Already DELIVERED
    db::ScyllaRow row(
        {"message_id", "recipient_device_id", "recipient_user_id", "delivery_state", "delivered_at", "read_at"},
        {db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(dev_id.str()), db::ScyllaValue(user_id.str()),
         db::ScyllaValue("DELIVERED"), db::ScyllaValue(now_ms), db::ScyllaValue()});

    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_get_single_state"), db::ScyllaQueryResult({row}));

    // Idempotent update: DELIVERED -> DELIVERED
    bool updated = repo.update_delivery_state_monotonic(msg_id, dev_id, DeliveryState::Delivered, now);
    EXPECT_TRUE(updated);

    // Should only have read single state, never run update_state
    const auto& executed = mock->get_executed_prepared();
    ASSERT_EQ(executed.size(), 1U);
    EXPECT_EQ(executed[0].first.value(), "deliv_repo_get_single_state");
}

TEST(ScyllaDeliveryStateRepositoryTest, UpdateDeliveryStateMonotonic_RowNotFound) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto msg_id = MessageId::generate_v7();
    auto dev_id = DeviceId("dev-nonexistent");
    auto now = std::chrono::system_clock::now();

    // Empty result
    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_get_single_state"),
                              db::ScyllaQueryResult(std::vector<db::ScyllaRow>{}));

    bool updated = repo.update_delivery_state_monotonic(msg_id, dev_id, DeliveryState::Delivered, now);
    EXPECT_FALSE(updated);
}

TEST(ScyllaDeliveryStateRepositoryTest, GetMessageDeliverySummary_EmptyReturnsNullopt) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto msg_id = MessageId::generate_v7();
    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_get_msg_states"),
                              db::ScyllaQueryResult(std::vector<db::ScyllaRow>{}));

    auto summary = repo.get_message_delivery_summary(msg_id);
    EXPECT_FALSE(summary.has_value());
}

TEST(ScyllaDeliveryStateRepositoryTest, GetMessageDeliverySummary_MultiDeviceUserReadOnPhoneNotWeb) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto msg_id = MessageId::generate_v7();
    auto user_bob = UserId("user-bob");
    auto dev_phone = DeviceId("dev-bob-phone");
    auto dev_laptop = DeviceId("dev-bob-laptop");

    auto now = std::chrono::system_clock::now();
    int64_t delivered_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    int64_t read_ms = delivered_ms + 2000;

    // Bob has 2 devices:
    // Phone: DELIVERED, read_at set
    // Laptop: QUEUED, no delivered_at, no read_at
    db::ScyllaRow row_phone(
        {"message_id", "recipient_device_id", "recipient_user_id", "delivery_state", "delivered_at", "read_at"},
        {db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(dev_phone.str()), db::ScyllaValue(user_bob.str()),
         db::ScyllaValue("DELIVERED"), db::ScyllaValue(delivered_ms), db::ScyllaValue(read_ms)});

    db::ScyllaRow row_laptop(
        {"message_id", "recipient_device_id", "recipient_user_id", "delivery_state", "delivered_at", "read_at"},
        {db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(dev_laptop.str()), db::ScyllaValue(user_bob.str()),
         db::ScyllaValue("QUEUED"), db::ScyllaValue(), db::ScyllaValue()});

    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_get_msg_states"),
                              db::ScyllaQueryResult({row_phone, row_laptop}));

    auto summary_opt = repo.get_message_delivery_summary(msg_id);
    ASSERT_TRUE(summary_opt.has_value());

    const auto& summary = *summary_opt;
    EXPECT_EQ(summary.message_id, msg_id);
    EXPECT_EQ(summary.total_targets, 2U);
    EXPECT_EQ(summary.delivered_targets, 1U);
    EXPECT_EQ(summary.pending_targets, 1U);
    EXPECT_EQ(summary.expired_targets, 0U);

    ASSERT_EQ(summary.device_statuses.size(), 2U);
    EXPECT_EQ(summary.device_statuses[0].device_id, dev_phone);
    EXPECT_EQ(summary.device_statuses[0].delivery_state, DeliveryState::Delivered);
    EXPECT_EQ(summary.device_statuses[1].device_id, dev_laptop);
    EXPECT_EQ(summary.device_statuses[1].delivery_state, DeliveryState::Queued);

    // Logical recipient read status: exactly 1 user (Bob)
    ASSERT_EQ(summary.recipient_read_statuses.size(), 1U);
    EXPECT_EQ(summary.recipient_read_statuses[0].user_id, user_bob);
    EXPECT_EQ(summary.recipient_read_statuses[0].read_state, domain::ReadState::Read);
    ASSERT_TRUE(summary.recipient_read_statuses[0].read_at.has_value());
    EXPECT_EQ(summary.recipient_read_statuses[0].reader_device_id, dev_phone);
}

TEST(ScyllaDeliveryStateRepositoryTest, GetMessageDeliverySummary_GroupChatPartialRead) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto msg_id = MessageId::generate_v7();
    auto user_bob = UserId("user-bob");
    auto user_charlie = UserId("user-charlie");
    auto user_dave = UserId("user-dave");

    auto dev_bob = DeviceId("dev-bob-1");
    auto dev_charlie = DeviceId("dev-charlie-1");
    auto dev_dave = DeviceId("dev-dave-1");

    auto now = std::chrono::system_clock::now();
    int64_t t_now = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    // Bob: DELIVERED, READ
    db::ScyllaRow row_bob(
        {"message_id", "recipient_device_id", "recipient_user_id", "delivery_state", "delivered_at", "read_at"},
        {db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(dev_bob.str()), db::ScyllaValue(user_bob.str()),
         db::ScyllaValue("DELIVERED"), db::ScyllaValue(t_now), db::ScyllaValue(t_now + 1000)});

    // Charlie: DELIVERED, UNREAD
    db::ScyllaRow row_charlie(
        {"message_id", "recipient_device_id", "recipient_user_id", "delivery_state", "delivered_at", "read_at"},
        {db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(dev_charlie.str()), db::ScyllaValue(user_charlie.str()),
         db::ScyllaValue("DELIVERED"), db::ScyllaValue(t_now), db::ScyllaValue()});

    // Dave: EXPIRED, UNREAD
    db::ScyllaRow row_dave(
        {"message_id", "recipient_device_id", "recipient_user_id", "delivery_state", "delivered_at", "read_at"},
        {db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(dev_dave.str()), db::ScyllaValue(user_dave.str()),
         db::ScyllaValue("EXPIRED"), db::ScyllaValue(), db::ScyllaValue()});

    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_get_msg_states"),
                              db::ScyllaQueryResult({row_bob, row_charlie, row_dave}));

    auto summary_opt = repo.get_message_delivery_summary(msg_id);
    ASSERT_TRUE(summary_opt.has_value());

    const auto& summary = *summary_opt;
    EXPECT_EQ(summary.total_targets, 3U);
    EXPECT_EQ(summary.delivered_targets, 2U);
    EXPECT_EQ(summary.pending_targets, 0U);
    EXPECT_EQ(summary.expired_targets, 1U);

    ASSERT_EQ(summary.recipient_read_statuses.size(), 3U);

    // Verify per-user read states
    std::map<domain::UserId, domain::LogicalRecipientReadStatus> status_map;
    for (const auto& s : summary.recipient_read_statuses) {
        status_map[s.user_id] = s;
    }

    EXPECT_EQ(status_map[user_bob].read_state, domain::ReadState::Read);
    EXPECT_EQ(status_map[user_bob].reader_device_id, dev_bob);
    EXPECT_TRUE(status_map[user_bob].read_at.has_value());

    EXPECT_EQ(status_map[user_charlie].read_state, domain::ReadState::Unread);
    EXPECT_FALSE(status_map[user_charlie].read_at.has_value());

    EXPECT_EQ(status_map[user_dave].read_state, domain::ReadState::Unread);
    EXPECT_FALSE(status_map[user_dave].read_at.has_value());
}

} // namespace
} // namespace securecloud::messaging::repository::test
