#include "messaging/db/mock_scylla_session.hpp"
#include "messaging/domain/idempotency_types.hpp"
#include "messaging/repository/scylla_idempotency_repository.hpp"

#include <gtest/gtest.h>
#include <memory>

namespace securecloud::messaging::repository::test {
namespace {

using domain::ConversationId;
using domain::DeviceId;
using domain::IdempotencyRecord;
using domain::MessageId;
using domain::SubmissionStatus;

TEST(ScyllaIdempotencyRepositoryTest, RejectsNullSession) {
    EXPECT_THROW(ScyllaIdempotencyRepository(nullptr), std::invalid_argument);
}

TEST(ScyllaIdempotencyRepositoryTest, SaveAndFindSubmission) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaIdempotencyRepository repo(mock);

    auto dev_id = DeviceId("dev-sender-1");
    auto msg_id = MessageId::generate_v7();
    auto conv_id = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    IdempotencyRecord record;
    record.sender_device_id = dev_id;
    record.idempotency_key = "idem-key-abc-123";
    record.message_id = msg_id;
    record.conversation_id = conv_id;
    record.message_sequence = 77;
    record.submission_status = SubmissionStatus::Committed;
    record.created_at = now;

    // 1. Save submission
    repo.save_submission(record);
    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "idem_repo_save_submission");

    // 2. Configure mock response for find_submission
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    db::ScyllaRow row({"sender_device_id", "idempotency_key", "message_id", "conversation_id", "message_sequence",
                       "submission_status", "created_at"},
                      {db::ScyllaValue(dev_id.str()), db::ScyllaValue("idem-key-abc-123"),
                       db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(conv_id.to_string()),
                       db::ScyllaValue(static_cast<int64_t>(77)), db::ScyllaValue("COMMITTED"),
                       db::ScyllaValue(now_ms)});

    mock->set_prepared_result(db::PreparedStatementId("idem_repo_find_submission"), db::ScyllaQueryResult({row}));

    auto found = repo.find_submission(dev_id, "idem-key-abc-123");
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->sender_device_id, dev_id);
    EXPECT_EQ(found->idempotency_key, "idem-key-abc-123");
    EXPECT_EQ(found->message_id, msg_id);
    EXPECT_EQ(found->conversation_id, conv_id);
    EXPECT_EQ(found->message_sequence, 77U);
    EXPECT_EQ(found->submission_status, SubmissionStatus::Committed);

    // 3. Not found returns nullopt
    mock->set_prepared_result(db::PreparedStatementId("idem_repo_find_submission"), db::ScyllaQueryResult{});
    auto not_found = repo.find_submission(dev_id, "non-existent-key");
    EXPECT_FALSE(not_found.has_value());
}

} // namespace
} // namespace securecloud::messaging::repository::test
