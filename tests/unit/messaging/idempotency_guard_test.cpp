#include "messaging/domain/idempotency_types.hpp"
#include "messaging/domain/submission_fingerprint.hpp"
#include "messaging/domain/submission_types.hpp"
#include "messaging/repository/idempotency_repository_interface.hpp"
#include "messaging/service/idempotency_guard.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <unordered_map>

namespace securecloud::messaging::service::test {
namespace {

using domain::ConversationId;
using domain::DeviceDeliveryTarget;
using domain::DeviceId;
using domain::IdempotencyRecord;
using domain::MessageId;
using domain::MessagePriority;
using domain::MessageSubmissionCommand;
using domain::SubmissionStatus;
using domain::UserId;

class MockIdempotencyRepository : public repository::IIdempotencyRepository {
  public:
    std::optional<IdempotencyRecord> find_submission(const DeviceId& sender_device_id,
                                                     const std::string& idempotency_key) override {
        ++find_calls;
        const auto key = sender_device_id.str() + ":" + idempotency_key;
        auto it = records_.find(key);
        if (it != records_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void save_submission(const IdempotencyRecord& record) override {
        ++save_calls;
        const auto key = record.sender_device_id.str() + ":" + record.idempotency_key;
        records_[key] = record;
    }

    int find_calls{0};
    int save_calls{0};
    std::unordered_map<std::string, IdempotencyRecord> records_;
};

MessageSubmissionCommand make_sample_command(const std::string& token = "client-token-12345") {
    MessageSubmissionCommand cmd;
    cmd.caller_user_id = UserId("018d0000-0000-7000-8000-000000000001");
    cmd.sender_device_id = DeviceId("dev-sender-phone");
    cmd.conversation_id = *ConversationId::from_string("018d0000-0000-7000-8000-000000000010");
    cmd.client_idempotency_token = token;
    cmd.priority = MessagePriority::Normal;

    DeviceDeliveryTarget target;
    target.recipient_user_id = UserId("018d0000-0000-7000-8000-000000000002");
    target.recipient_device_id = DeviceId("dev-recipient-tablet");
    target.ciphertext_blob = "sample_ciphertext";
    target.ephemeral_public_key = std::vector<uint8_t>(32, 0xAA);
    target.iv = std::vector<uint8_t>(24, 0xBB);
    target.auth_tag = std::vector<uint8_t>(16, 0xCC);
    target.algorithm = "XChaCha20-Poly1305";
    cmd.delivery_targets.push_back(target);

    return cmd;
}

TEST(IdempotencyGuardTest, RejectsNullRepository) {
    EXPECT_THROW(MessageSubmissionIdempotencyGuard(nullptr), std::invalid_argument);
}

TEST(IdempotencyGuardTest, FreshSubmissionReturnsProceedNew) {
    auto repo = std::make_shared<MockIdempotencyRepository>();
    MessageSubmissionIdempotencyGuard guard(repo);

    auto cmd = make_sample_command();
    std::string fingerprint = domain::calculate_submission_fingerprint(cmd);

    auto eval = guard.evaluate_submission(cmd, fingerprint);
    EXPECT_EQ(eval.action, IdempotencyAction::ProceedNew);
    EXPECT_FALSE(eval.cached_record.has_value());
    EXPECT_TRUE(eval.error_message.empty());
    EXPECT_EQ(repo->find_calls, 1);
}

TEST(IdempotencyGuardTest, IdenticalReplayReturnsReturnCached) {
    auto repo = std::make_shared<MockIdempotencyRepository>();
    MessageSubmissionIdempotencyGuard guard(repo);

    auto cmd = make_sample_command();
    std::string fingerprint = domain::calculate_submission_fingerprint(cmd);
    auto msg_id = MessageId::generate_v7();

    // Mark as committed in repository
    guard.mark_committed(cmd, fingerprint, msg_id, 42);

    // Replay identical submission
    auto eval = guard.evaluate_submission(cmd, fingerprint);
    EXPECT_EQ(eval.action, IdempotencyAction::ReturnCached);
    ASSERT_TRUE(eval.cached_record.has_value());
    EXPECT_EQ(eval.cached_record->message_id, msg_id);
    EXPECT_EQ(eval.cached_record->message_sequence, 42U);
    EXPECT_EQ(eval.cached_record->submission_status, SubmissionStatus::Committed);
    EXPECT_EQ(eval.cached_record->request_fingerprint, fingerprint);
}

TEST(IdempotencyGuardTest, ConflictingConversationRejected) {
    auto repo = std::make_shared<MockIdempotencyRepository>();
    MessageSubmissionIdempotencyGuard guard(repo);

    auto cmd1 = make_sample_command("token-conflict-1");
    std::string fingerprint1 = domain::calculate_submission_fingerprint(cmd1);
    auto msg_id = MessageId::generate_v7();
    guard.mark_committed(cmd1, fingerprint1, msg_id, 10);

    // Same token used with a different conversation ID
    auto cmd2 = cmd1;
    cmd2.conversation_id = *ConversationId::from_string("018d0000-0000-7000-8000-000000000099");
    std::string fingerprint2 = domain::calculate_submission_fingerprint(cmd2);

    auto eval = guard.evaluate_submission(cmd2, fingerprint2);
    EXPECT_EQ(eval.action, IdempotencyAction::RejectConflict);
    EXPECT_EQ(eval.error_code, v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT);
    EXPECT_FALSE(eval.error_message.empty());
}

TEST(IdempotencyGuardTest, ConflictingFingerprintRejected) {
    auto repo = std::make_shared<MockIdempotencyRepository>();
    MessageSubmissionIdempotencyGuard guard(repo);

    auto cmd1 = make_sample_command("token-conflict-2");
    std::string fingerprint1 = domain::calculate_submission_fingerprint(cmd1);
    auto msg_id = MessageId::generate_v7();
    guard.mark_committed(cmd1, fingerprint1, msg_id, 10);

    // Same token and conversation, but altered message content/ciphertext
    auto cmd2 = cmd1;
    cmd2.delivery_targets[0].ciphertext_blob = "altered_tampered_ciphertext";
    std::string fingerprint2 = domain::calculate_submission_fingerprint(cmd2);

    auto eval = guard.evaluate_submission(cmd2, fingerprint2);
    EXPECT_EQ(eval.action, IdempotencyAction::RejectConflict);
    EXPECT_EQ(eval.error_code, v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT);
    EXPECT_FALSE(eval.error_message.empty());
}

TEST(IdempotencyGuardTest, InFlightSubmissionReturnsRetryWait) {
    auto repo = std::make_shared<MockIdempotencyRepository>();
    MessageSubmissionIdempotencyGuard guard(repo);

    auto cmd = make_sample_command("token-inflight");
    std::string fingerprint = domain::calculate_submission_fingerprint(cmd);
    auto msg_id = MessageId::generate_v7();

    // Mark as in-flight PROCESSING
    guard.mark_processing(cmd, fingerprint, msg_id);

    // Another worker/thread receives duplicate request while first is still PROCESSING
    auto eval = guard.evaluate_submission(cmd, fingerprint);
    EXPECT_EQ(eval.action, IdempotencyAction::RetryWait);
    EXPECT_FALSE(eval.error_message.empty());
}

TEST(IdempotencyGuardTest, FailedSubmissionAllowsRetryProceedNew) {
    auto repo = std::make_shared<MockIdempotencyRepository>();
    MessageSubmissionIdempotencyGuard guard(repo);

    auto cmd = make_sample_command("token-failed");
    std::string fingerprint = domain::calculate_submission_fingerprint(cmd);
    auto msg_id = MessageId::generate_v7();

    guard.mark_processing(cmd, fingerprint, msg_id);
    guard.mark_failed(cmd.sender_device_id, cmd.client_idempotency_token);

    // Subsequent submission should be allowed to proceed as new
    auto eval = guard.evaluate_submission(cmd, fingerprint);
    EXPECT_EQ(eval.action, IdempotencyAction::ProceedNew);
}

TEST(IdempotencyGuardTest, LifecycleTransitionsAndQueries) {
    auto repo = std::make_shared<MockIdempotencyRepository>();
    MessageSubmissionIdempotencyGuard guard(repo);

    auto cmd = make_sample_command("lifecycle-token");
    std::string fingerprint = domain::calculate_submission_fingerprint(cmd);
    auto msg_id = MessageId::generate_v7();

    // 1. Initial lookup is empty
    EXPECT_FALSE(guard.find_submission(cmd.sender_device_id, cmd.client_idempotency_token).has_value());

    // 2. Mark processing
    guard.mark_processing(cmd, fingerprint, msg_id);
    auto proc = guard.find_submission(cmd.sender_device_id, cmd.client_idempotency_token);
    ASSERT_TRUE(proc.has_value());
    EXPECT_EQ(proc->submission_status, SubmissionStatus::Processing);
    EXPECT_EQ(proc->message_id, msg_id);

    // 3. Mark committed
    guard.mark_committed(cmd, fingerprint, msg_id, 99);
    auto comm = guard.find_submission(cmd.sender_device_id, cmd.client_idempotency_token);
    ASSERT_TRUE(comm.has_value());
    EXPECT_EQ(comm->submission_status, SubmissionStatus::Committed);
    EXPECT_EQ(comm->message_sequence, 99U);

    // 4. Mark failed
    guard.mark_failed(cmd.sender_device_id, cmd.client_idempotency_token);
    auto fail = guard.find_submission(cmd.sender_device_id, cmd.client_idempotency_token);
    ASSERT_TRUE(fail.has_value());
    EXPECT_EQ(fail->submission_status, SubmissionStatus::Failed);
}

} // namespace
} // namespace securecloud::messaging::service::test
