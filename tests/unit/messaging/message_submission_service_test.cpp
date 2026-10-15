#include "messaging/domain/conversation_entity.hpp"
#include "messaging/domain/conversation_participant_entity.hpp"
#include "messaging/domain/submission_fingerprint.hpp"
#include "messaging/domain/submission_types.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/service/conversation_authorization_service.hpp"
#include "messaging/service/idempotency_guard.hpp"
#include "messaging/service/in_memory_sequence_allocator.hpp"
#include "messaging/service/message_submission_service.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::service::test {
namespace {

using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeviceDeliveryRecord;
using domain::DeviceDeliveryTarget;
using domain::DeviceId;
using domain::IdempotencyRecord;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::MessagePriority;
using domain::MessageSubmissionCommand;
using domain::ParticipantRole;
using domain::RecipientDeliveryState;
using domain::SubmissionStatus;
using domain::UserId;

// ============================================================================
// Mock Repositories
// ============================================================================

class MockMessageRepository : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override {
        if (throw_on_save) {
            throw std::runtime_error("Simulated ScyllaDB message write failure");
        }
        saved_messages.push_back(msg);
    }

    std::optional<MessageEntity> find_by_id(const ConversationId&, const MessageBucket&, const MessageId&) override {
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId&, const MessageBucket&, uint64_t,
                                                               uint64_t, size_t) override {
        return {};
    }

    uint64_t get_last_sequence(const ConversationId&, const MessageBucket&) override { return 0; }

    bool throw_on_save{false};
    std::vector<MessageEntity> saved_messages;
};

class MockDeliveryStateRepository : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        saved_pending.insert(saved_pending.end(), records.begin(), records.end());
    }

    std::vector<DeviceDeliveryRecord> fetch_pending_for_device(const DeviceId&, const std::string&, size_t) override {
        return {};
    }

    void update_device_delivery_status(const DeviceId&, const std::string&,
                                       const std::chrono::system_clock::time_point&, const MessageId&,
                                       domain::DeliveryState, int32_t,
                                       std::optional<std::chrono::system_clock::time_point>) override {}

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        saved_recipient_states.insert(saved_recipient_states.end(), states.begin(), states.end());
    }

    void record_delivery_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {
    }

    void record_read_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {}

    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId&) override { return {}; }

    std::vector<DeviceDeliveryRecord> saved_pending;
    std::vector<RecipientDeliveryState> saved_recipient_states;
};

class MockOutboxRepository : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string&) override {
        enqueued_events.push_back(event);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }

    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

    std::vector<ConversationOutboxEvent> enqueued_events;
};

class MockIdempotencyRepository : public repository::IIdempotencyRepository {
  public:
    std::optional<IdempotencyRecord> find_submission(const DeviceId& sender_device_id,
                                                     const std::string& idempotency_key) override {
        const auto key = sender_device_id.str() + ":" + idempotency_key;
        auto it = records_.find(key);
        if (it != records_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void save_submission(const IdempotencyRecord& record) override {
        const auto key = record.sender_device_id.str() + ":" + record.idempotency_key;
        records_[key] = record;
    }

    std::unordered_map<std::string, IdempotencyRecord> records_;
};

// ============================================================================
// Test Fixture
// ============================================================================

class MessageSubmissionServiceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        memb_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *memb_repo_);
        sequence_allocator_ = std::make_shared<InMemorySequenceAllocator>();
        idempotency_repo_ = std::make_shared<MockIdempotencyRepository>();
        idempotency_guard_ = std::make_shared<MessageSubmissionIdempotencyGuard>(idempotency_repo_);
        message_repo_ = std::make_shared<MockMessageRepository>();
        delivery_repo_ = std::make_shared<MockDeliveryStateRepository>();
        outbox_repo_ = std::make_shared<MockOutboxRepository>();

        service_ = std::make_unique<MessageSubmissionService>(auth_service_, sequence_allocator_, idempotency_guard_,
                                                              message_repo_, delivery_repo_, outbox_repo_);

        // Set up active test conversation
        test_conv_id_ = ConversationId::generate_v7();
        test_alice_ = UserId("018d0000-0000-7000-8000-000000000001");
        test_bob_ = UserId("018d0000-0000-7000-8000-000000000002");
        alice_device_ = DeviceId("alice-device-phone");
        bob_device_ = DeviceId("bob-device-tablet");

        ConversationEntity conv(test_conv_id_, ConversationType::Direct, test_alice_);
        conv_repo_->save_conversation(conv);

        auto now = std::chrono::system_clock::now();
        ConversationParticipantEntity p_alice{test_conv_id_, test_alice_, ParticipantRole::Member,
                                              MembershipStatus::Active, now};
        ConversationParticipantEntity p_bob{test_conv_id_, test_bob_, ParticipantRole::Member, MembershipStatus::Active,
                                            now};
        memb_repo_->add_participant(p_alice);
        memb_repo_->add_participant(p_bob);
    }

    MessageSubmissionCommand make_valid_command(const std::string& token = "tok-12345") {
        MessageSubmissionCommand cmd;
        cmd.caller_user_id = test_alice_;
        cmd.sender_device_id = alice_device_;
        cmd.conversation_id = test_conv_id_;
        cmd.client_idempotency_token = token;
        cmd.priority = MessagePriority::Normal;

        DeviceDeliveryTarget target;
        target.recipient_user_id = test_bob_;
        target.recipient_device_id = bob_device_;
        target.ciphertext_blob = "encrypted_secret_data";
        target.ephemeral_public_key = std::vector<uint8_t>(32, 0xAA);
        target.iv = std::vector<uint8_t>(24, 0xBB);
        target.auth_tag = std::vector<uint8_t>(16, 0xCC);
        target.algorithm = "XChaCha20-Poly1305";
        cmd.delivery_targets.push_back(target);

        return cmd;
    }

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> memb_repo_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<InMemorySequenceAllocator> sequence_allocator_;
    std::shared_ptr<MockIdempotencyRepository> idempotency_repo_;
    std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard_;
    std::shared_ptr<MockMessageRepository> message_repo_;
    std::shared_ptr<MockDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<MockOutboxRepository> outbox_repo_;

    std::unique_ptr<MessageSubmissionService> service_;

    ConversationId test_conv_id_;
    UserId test_alice_;
    UserId test_bob_;
    DeviceId alice_device_;
    DeviceId bob_device_;
};

// ============================================================================
// Tests
// ============================================================================

TEST_F(MessageSubmissionServiceTest, RejectsNullDependencies) {
    EXPECT_THROW(MessageSubmissionService(nullptr, sequence_allocator_, idempotency_guard_, message_repo_,
                                          delivery_repo_, outbox_repo_),
                 std::invalid_argument);
    EXPECT_THROW(MessageSubmissionService(auth_service_, nullptr, idempotency_guard_, message_repo_, delivery_repo_,
                                          outbox_repo_),
                 std::invalid_argument);
    EXPECT_THROW(MessageSubmissionService(auth_service_, sequence_allocator_, nullptr, message_repo_, delivery_repo_,
                                          outbox_repo_),
                 std::invalid_argument);
    EXPECT_THROW(MessageSubmissionService(auth_service_, sequence_allocator_, idempotency_guard_, nullptr,
                                          delivery_repo_, outbox_repo_),
                 std::invalid_argument);
    EXPECT_THROW(MessageSubmissionService(auth_service_, sequence_allocator_, idempotency_guard_, message_repo_,
                                          nullptr, outbox_repo_),
                 std::invalid_argument);
    EXPECT_THROW(MessageSubmissionService(auth_service_, sequence_allocator_, idempotency_guard_, message_repo_,
                                          delivery_repo_, nullptr),
                 std::invalid_argument);
}

TEST_F(MessageSubmissionServiceTest, EndToEndSuccessfulSubmission) {
    auto cmd = make_valid_command();
    auto result = service_->submit_message(cmd);

    ASSERT_TRUE(result.success);
    EXPECT_FALSE(result.value.is_replay);
    EXPECT_EQ(result.value.conversation_id, test_conv_id_);
    EXPECT_EQ(result.value.message_sequence, 1U);
    EXPECT_FALSE(result.value.message_id.is_nil());
    EXPECT_EQ(result.value.initial_state, v1::DELIVERY_STATE_QUEUED);

    // 1. Verify MessageEntity persisted
    ASSERT_EQ(message_repo_->saved_messages.size(), 1U);
    const auto& saved_msg = message_repo_->saved_messages.front();
    EXPECT_EQ(saved_msg.message_id, result.value.message_id);
    EXPECT_EQ(saved_msg.conversation_id, test_conv_id_);
    EXPECT_EQ(saved_msg.message_sequence, 1U);
    EXPECT_EQ(saved_msg.sender_user_id, test_alice_);
    EXPECT_EQ(saved_msg.sender_device_id, alice_device_);
    EXPECT_EQ(saved_msg.envelope.ciphertext, "encrypted_secret_data");

    // 2. Verify Delivery Records persisted
    ASSERT_EQ(delivery_repo_->saved_pending.size(), 1U);
    EXPECT_EQ(delivery_repo_->saved_pending.front().device_id, bob_device_);
    EXPECT_EQ(delivery_repo_->saved_pending.front().message_id, result.value.message_id);

    ASSERT_EQ(delivery_repo_->saved_recipient_states.size(), 1U);
    EXPECT_EQ(delivery_repo_->saved_recipient_states.front().recipient_device_id, bob_device_);
    EXPECT_EQ(delivery_repo_->saved_recipient_states.front().recipient_user_id, test_bob_);

    // 3. Verify Transactional Outbox Event enqueued
    ASSERT_EQ(outbox_repo_->enqueued_events.size(), 1U);
    EXPECT_EQ(outbox_repo_->enqueued_events.front().event_type, domain::ConversationOutboxEventType::MessageSent);
    EXPECT_EQ(outbox_repo_->enqueued_events.front().conversation_id, test_conv_id_);
    EXPECT_NE(outbox_repo_->enqueued_events.front().payload_json.find(result.value.message_id.to_string()),
              std::string::npos);

    // 4. Verify Idempotency Record COMMITTED
    auto idem_rec = idempotency_guard_->find_submission(alice_device_, cmd.client_idempotency_token);
    ASSERT_TRUE(idem_rec.has_value());
    EXPECT_EQ(idem_rec->submission_status, SubmissionStatus::Committed);
    EXPECT_EQ(idem_rec->message_id, result.value.message_id);
    EXPECT_EQ(idem_rec->message_sequence, 1U);
}

TEST_F(MessageSubmissionServiceTest, ImmediateIdenticalReplayReturnsCachedWithoutDuplicateWrites) {
    auto cmd = make_valid_command();

    // First submission
    auto res1 = service_->submit_message(cmd);
    ASSERT_TRUE(res1.success);
    EXPECT_FALSE(res1.value.is_replay);

    // Save baseline repository counts
    const size_t msg_count = message_repo_->saved_messages.size();
    const size_t delivery_count = delivery_repo_->saved_pending.size();
    const size_t outbox_count = outbox_repo_->enqueued_events.size();

    // Second identical submission (mobile client retry)
    auto res2 = service_->submit_message(cmd);
    ASSERT_TRUE(res2.success);
    EXPECT_TRUE(res2.value.is_replay);
    EXPECT_EQ(res2.value.message_id, res1.value.message_id);
    EXPECT_EQ(res2.value.message_sequence, res1.value.message_sequence);
    EXPECT_EQ(res2.value.conversation_id, res1.value.conversation_id);

    // Zero secondary writes rule (ADR-007)
    EXPECT_EQ(message_repo_->saved_messages.size(), msg_count);
    EXPECT_EQ(delivery_repo_->saved_pending.size(), delivery_count);
    EXPECT_EQ(outbox_repo_->enqueued_events.size(), outbox_count);
}

TEST_F(MessageSubmissionServiceTest, ValidationFailureFailsFastBeforePersistence) {
    auto cmd = make_valid_command();
    cmd.conversation_id = ConversationId{}; // nil UUID

    auto res = service_->submit_message(cmd);
    EXPECT_FALSE(res.success);
    EXPECT_NE(res.error_message.find("Conversation ID"), std::string::npos);

    EXPECT_TRUE(message_repo_->saved_messages.empty());
    EXPECT_TRUE(delivery_repo_->saved_pending.empty());
    EXPECT_TRUE(outbox_repo_->enqueued_events.empty());
}

TEST_F(MessageSubmissionServiceTest, UnauthorizedUserRejected) {
    auto cmd = make_valid_command();
    // Non-member caller
    cmd.caller_user_id = UserId("018d0000-0000-7000-8000-000000000099");

    auto res = service_->submit_message(cmd);
    EXPECT_FALSE(res.success);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);

    EXPECT_TRUE(message_repo_->saved_messages.empty());
    EXPECT_TRUE(delivery_repo_->saved_pending.empty());
    EXPECT_TRUE(outbox_repo_->enqueued_events.empty());
}

TEST_F(MessageSubmissionServiceTest, ConflictingIdempotencyTokenRejected) {
    auto cmd1 = make_valid_command("shared-token-key");
    auto res1 = service_->submit_message(cmd1);
    ASSERT_TRUE(res1.success);

    // Reusing same token with tampered ciphertext
    auto cmd2 = cmd1;
    cmd2.delivery_targets[0].ciphertext_blob = "tampered_ciphertext_data";

    auto res2 = service_->submit_message(cmd2);
    EXPECT_FALSE(res2.success);
    EXPECT_EQ(res2.error_code, v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT);
}

TEST_F(MessageSubmissionServiceTest, PersistenceFailureMarksIdempotencyFailedForRetry) {
    auto cmd = make_valid_command();
    message_repo_->throw_on_save = true;

    auto res = service_->submit_message(cmd);
    EXPECT_FALSE(res.success);
    EXPECT_NE(res.error_message.find("Message persistence failed"), std::string::npos);

    // Check idempotency record was marked FAILED so subsequent retry can proceed
    auto idem_rec = idempotency_guard_->find_submission(alice_device_, cmd.client_idempotency_token);
    ASSERT_TRUE(idem_rec.has_value());
    EXPECT_EQ(idem_rec->submission_status, SubmissionStatus::Failed);

    // Allow database to succeed on retry
    message_repo_->throw_on_save = false;
    auto retry_res = service_->submit_message(cmd);
    EXPECT_TRUE(retry_res.success);
    EXPECT_FALSE(retry_res.value.is_replay);
    EXPECT_EQ(retry_res.value.message_sequence, 2U);
}

} // namespace
} // namespace securecloud::messaging::service::test
