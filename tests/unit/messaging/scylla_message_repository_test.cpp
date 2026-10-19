#include "messaging/db/mock_scylla_session.hpp"
#include "messaging/domain/message_bucket.hpp"
#include "messaging/domain/message_entity.hpp"
#include "messaging/domain/outbox_event.hpp"
#include "messaging/repository/scylla_message_repository.hpp"
#include "messaging/repository/scylla_outbox_repository.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::repository::test {
namespace {

using domain::CiphertextEnvelope;
using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationOutboxEventType;
using domain::DeviceId;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::MessagePriority;
using domain::UserId;

// ============================================================================
// 1. ScyllaMessageRepository Tests
// ============================================================================

TEST(ScyllaMessageRepositoryTest, RejectsNullSession) {
    EXPECT_THROW(ScyllaMessageRepository(nullptr), std::invalid_argument);
}

TEST(ScyllaMessageRepositoryTest, SaveAndFindMessageById) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaMessageRepository repo(mock);

    auto conv_id = ConversationId::generate_v7();
    auto bucket = MessageBucket::from_year_month(2026, 10);
    auto msg_id = MessageId::generate_v7();
    auto user_id = UserId("user-alice-123");
    auto device_id = DeviceId("dev-phone-456");
    auto now = std::chrono::system_clock::now();

    MessageEntity msg;
    msg.conversation_id = conv_id;
    msg.message_bucket = bucket;
    msg.message_sequence = 42;
    msg.message_id = msg_id;
    msg.sender_user_id = user_id;
    msg.sender_device_id = device_id;
    msg.priority = MessagePriority::Urgent;
    msg.accepted_at = now;
    msg.envelope.ciphertext = "ciphertext-data-base64";
    msg.envelope.envelope_version = 1;
    msg.file_reference_ids = {"file-ref-1", "file-ref-2"};

    // 1. Save message
    repo.save_message(msg);
    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "msg_repo_save_message");

    // 2. Configure mock response for find_by_id
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    db::ScyllaRow row({"conversation_id", "message_bucket", "message_sequence", "message_id", "sender_user_id",
                       "sender_device_id", "message_priority", "accepted_at", "ciphertext_envelope", "envelope_version",
                       "file_reference_ids"},
                      {db::ScyllaValue(conv_id.to_string()), db::ScyllaValue(bucket.value()),
                       db::ScyllaValue(static_cast<int64_t>(42)), db::ScyllaValue(msg_id.to_string()),
                       db::ScyllaValue(user_id.str()), db::ScyllaValue(device_id.str()), db::ScyllaValue("URGENT"),
                       db::ScyllaValue(now_ms), db::ScyllaValue("ciphertext-data-base64"), db::ScyllaValue(1),
                       db::ScyllaValue(std::vector<std::string>{"file-ref-1", "file-ref-2"})});

    mock->set_prepared_result(db::PreparedStatementId("msg_repo_find_by_id"), db::ScyllaQueryResult({row}));

    auto found = repo.find_by_id(conv_id, bucket, msg_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->conversation_id, conv_id);
    EXPECT_EQ(found->message_bucket, bucket);
    EXPECT_EQ(found->message_sequence, 42U);
    EXPECT_EQ(found->message_id, msg_id);
    EXPECT_EQ(found->sender_user_id, user_id);
    EXPECT_EQ(found->sender_device_id, device_id);
    EXPECT_EQ(found->priority, MessagePriority::Urgent);
    EXPECT_EQ(found->envelope.ciphertext, "ciphertext-data-base64");
    EXPECT_EQ(found->envelope.envelope_version, 1);
    ASSERT_EQ(found->file_reference_ids.size(), 2U);
    EXPECT_EQ(found->file_reference_ids[0], "file-ref-1");

    // 3. Not found returns nullopt
    mock->set_prepared_result(db::PreparedStatementId("msg_repo_find_by_id"), db::ScyllaQueryResult{});
    auto not_found = repo.find_by_id(conv_id, bucket, MessageId::generate_v7());
    EXPECT_FALSE(not_found.has_value());
}

TEST(ScyllaMessageRepositoryTest, ListMessagesBySequenceRange) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaMessageRepository repo(mock);

    auto conv_id = ConversationId::generate_v7();
    auto bucket = MessageBucket::from_year_month(2026, 10);
    auto msg1_id = MessageId::generate_v7();
    auto msg2_id = MessageId::generate_v7();
    int64_t now_ms = 1792065600000;

    db::ScyllaRow r1(
        {"conversation_id", "message_bucket", "message_sequence", "message_id", "sender_user_id", "sender_device_id",
         "message_priority", "accepted_at", "ciphertext_envelope", "envelope_version", "file_reference_ids"},
        {db::ScyllaValue(conv_id.to_string()), db::ScyllaValue(bucket.value()),
         db::ScyllaValue(static_cast<int64_t>(10)), db::ScyllaValue(msg1_id.to_string()), db::ScyllaValue("user-1"),
         db::ScyllaValue("dev-1"), db::ScyllaValue("NORMAL"), db::ScyllaValue(now_ms), db::ScyllaValue("msg1"),
         db::ScyllaValue(1), db::ScyllaValue(std::vector<std::string>{})});

    db::ScyllaRow r2(
        {"conversation_id", "message_bucket", "message_sequence", "message_id", "sender_user_id", "sender_device_id",
         "message_priority", "accepted_at", "ciphertext_envelope", "envelope_version", "file_reference_ids"},
        {db::ScyllaValue(conv_id.to_string()), db::ScyllaValue(bucket.value()),
         db::ScyllaValue(static_cast<int64_t>(11)), db::ScyllaValue(msg2_id.to_string()), db::ScyllaValue("user-2"),
         db::ScyllaValue("dev-2"), db::ScyllaValue("NORMAL"), db::ScyllaValue(now_ms + 1000), db::ScyllaValue("msg2"),
         db::ScyllaValue(1), db::ScyllaValue(std::vector<std::string>{})});

    mock->set_prepared_result(db::PreparedStatementId("msg_repo_list_range"), db::ScyllaQueryResult({r1, r2}));

    auto list = repo.list_messages_by_sequence_range(conv_id, bucket, 10, 20, 50);
    ASSERT_EQ(list.size(), 2U);
    EXPECT_EQ(list[0].message_sequence, 10U);
    EXPECT_EQ(list[1].message_sequence, 11U);
}

TEST(ScyllaMessageRepositoryTest, GetLastSequence) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaMessageRepository repo(mock);

    auto conv_id = ConversationId::generate_v7();
    auto bucket = MessageBucket::from_year_month(2026, 10);

    // Empty partition returns 0
    mock->set_prepared_result(db::PreparedStatementId("msg_repo_get_last_seq"), db::ScyllaQueryResult{});
    EXPECT_EQ(repo.get_last_sequence(conv_id, bucket), 0U);

    // With rows returns highest sequence
    db::ScyllaRow row({"message_sequence"}, {db::ScyllaValue(static_cast<int64_t>(105))});
    mock->set_prepared_result(db::PreparedStatementId("msg_repo_get_last_seq"), db::ScyllaQueryResult({row}));
    EXPECT_EQ(repo.get_last_sequence(conv_id, bucket), 105U);
}

// ============================================================================
// 2. ScyllaOutboxRepository Tests
// ============================================================================

TEST(ScyllaOutboxRepositoryTest, RejectsNullSession) {
    EXPECT_THROW(ScyllaOutboxRepository(nullptr), std::invalid_argument);
}

TEST(ScyllaOutboxRepositoryTest, EnqueueAndFetchPendingEvents) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaOutboxRepository repo(mock);

    auto conv_id = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    ConversationOutboxEvent event;
    event.event_id = "evt-12345";
    event.conversation_id = conv_id;
    event.event_type = ConversationOutboxEventType::MessageSent;
    event.payload_json = R"({"msg":"hello"})";
    event.created_at = now;

    // Enqueue
    repo.enqueue_event(event);
    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "outbox_repo_enqueue");

    // Fetch pending
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::string bucket = outbox_bucket_from_time_point(now);

    db::ScyllaRow r_pending({"outbox_bucket", "created_at", "event_id", "conversation_id", "event_type", "payload_json",
                             "published_at", "publish_status"},
                            {db::ScyllaValue(bucket), db::ScyllaValue(now_ms), db::ScyllaValue("evt-12345"),
                             db::ScyllaValue(conv_id.to_string()), db::ScyllaValue("MessageSent"),
                             db::ScyllaValue(R"({"msg":"hello"})"), db::ScyllaValue::null(),
                             db::ScyllaValue("PENDING")});

    db::ScyllaRow r_published({"outbox_bucket", "created_at", "event_id", "conversation_id", "event_type",
                               "payload_json", "published_at", "publish_status"},
                              {db::ScyllaValue(bucket), db::ScyllaValue(now_ms - 100), db::ScyllaValue("evt-old"),
                               db::ScyllaValue(conv_id.to_string()), db::ScyllaValue("ConversationCreated"),
                               db::ScyllaValue("{}"), db::ScyllaValue(now_ms), db::ScyllaValue("PUBLISHED")});

    mock->set_prepared_result(db::PreparedStatementId("outbox_repo_fetch"),
                              db::ScyllaQueryResult({r_published, r_pending}));

    auto pending = repo.fetch_pending_events(bucket, 10);
    ASSERT_EQ(pending.size(), 1U);
    EXPECT_EQ(pending[0].event_id, "evt-12345");
    EXPECT_EQ(pending[0].event_type, "MessageSent");
    EXPECT_EQ(pending[0].publish_status, OutboxPublishStatus::Pending);
}

TEST(ScyllaOutboxRepositoryTest, MarkEventPublished) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaOutboxRepository repo(mock);

    auto now = std::chrono::system_clock::now();
    std::string bucket = "2026101512";

    repo.mark_event_published(bucket, now, "evt-12345", now);
    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "outbox_repo_mark_published");
}

} // namespace
} // namespace securecloud::messaging::repository::test
