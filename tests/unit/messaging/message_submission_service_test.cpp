#include "messaging/domain/audit_event.hpp"
#include "messaging/domain/audit_event_id.hpp"
#include "messaging/domain/conversation_entity.hpp"
#include "messaging/domain/conversation_participant_entity.hpp"
#include "messaging/domain/submission_fingerprint.hpp"
#include "messaging/domain/submission_types.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/in_memory_messaging_audit_outbox_repository.hpp"
#include "messaging/repository/messaging_audit_outbox_repository_interface.hpp"
#include "messaging/service/conversation_authorization_service.hpp"
#include "messaging/service/e2e_envelope_validator.hpp"
#include "messaging/service/idempotency_guard.hpp"
#include "messaging/service/in_memory_sequence_allocator.hpp"
#include "messaging/service/message_submission_service.hpp"
#include "messaging/service/recipient_device_resolution_service.hpp"
#include "securecloud/audit/v1/audit.pb.h"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
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
// Thread-Safe Mock Repositories
// ============================================================================

class ThreadSafeMessageRepo final : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (throw_on_save_) {
            throw std::runtime_error("Simulated ScyllaDB message write failure");
        }
        saved_messages_.push_back(msg);
        messages_[msg.conversation_id.to_string()].push_back(msg);
    }

    std::optional<MessageEntity> find_by_id(const ConversationId& conv, const MessageBucket&,
                                            const MessageId& id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = messages_.find(conv.to_string());
        if (it != messages_.end()) {
            for (const auto& m : it->second) {
                if (m.message_id == id)
                    return m;
            }
        }
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId&, const MessageBucket&, uint64_t,
                                                               uint64_t, size_t) override {
        return {};
    }

    uint64_t get_last_sequence(const ConversationId& conv, const MessageBucket&) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = messages_.find(conv.to_string());
        if (it == messages_.end() || it->second.empty())
            return 0;
        uint64_t max_seq = 0;
        for (const auto& m : it->second) {
            max_seq = std::max(max_seq, m.message_sequence);
        }
        return max_seq;
    }

    void set_throw_on_save(bool val) {
        std::lock_guard<std::mutex> lock(mutex_);
        throw_on_save_ = val;
    }

    std::vector<MessageEntity> get_all_saved() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return saved_messages_;
    }

  private:
    mutable std::mutex mutex_;
    bool throw_on_save_{false};
    std::vector<MessageEntity> saved_messages_;
    std::unordered_map<std::string, std::vector<MessageEntity>> messages_;
};

class ThreadSafeDeliveryStateRepo final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mutex_);
        saved_pending_.insert(saved_pending_.end(), records.begin(), records.end());
    }

    std::vector<DeviceDeliveryRecord> fetch_pending_for_device(const DeviceId&, const std::string&, size_t) override {
        return {};
    }

    void update_device_delivery_status(const DeviceId&, const std::string&,
                                       const std::chrono::system_clock::time_point&, const MessageId&,
                                       domain::DeliveryState, int32_t,
                                       std::optional<std::chrono::system_clock::time_point>) override {}

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mutex_);
        saved_recipient_states_.insert(saved_recipient_states_.end(), states.begin(), states.end());
    }

    void record_delivery_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {
    }
    void record_read_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {}
    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId&) override { return {}; }

    std::vector<DeviceDeliveryRecord> get_saved_pending() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return saved_pending_;
    }

    std::vector<RecipientDeliveryState> get_saved_recipient_states() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return saved_recipient_states_;
    }

  private:
    mutable std::mutex mutex_;
    std::vector<DeviceDeliveryRecord> saved_pending_;
    std::vector<RecipientDeliveryState> saved_recipient_states_;
};

class ThreadSafeOutboxRepo final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string&) override {
        std::lock_guard<std::mutex> lock(mutex_);
        enqueued_events_.push_back(event);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }

    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

    std::vector<ConversationOutboxEvent> get_enqueued_events() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return enqueued_events_;
    }

  private:
    mutable std::mutex mutex_;
    std::vector<ConversationOutboxEvent> enqueued_events_;
};

class ThreadSafeIdempotencyRepo final : public repository::IIdempotencyRepository {
  public:
    std::optional<IdempotencyRecord> find_submission(const DeviceId& sender_device_id,
                                                     const std::string& idempotency_key) override {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto key = sender_device_id.str() + ":" + idempotency_key;
        auto it = records_.find(key);
        if (it != records_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void save_submission(const IdempotencyRecord& record) override {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto key = record.sender_device_id.str() + ":" + record.idempotency_key;
        records_[key] = record;
    }

  private:
    mutable std::mutex mutex_;
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
        idempotency_repo_ = std::make_shared<ThreadSafeIdempotencyRepo>();
        idempotency_guard_ = std::make_shared<MessageSubmissionIdempotencyGuard>(idempotency_repo_);
        message_repo_ = std::make_shared<ThreadSafeMessageRepo>();
        delivery_repo_ = std::make_shared<ThreadSafeDeliveryStateRepo>();
        outbox_repo_ = std::make_shared<ThreadSafeOutboxRepo>();
        audit_repo_ = std::make_shared<repository::InMemoryMessagingAuditOutboxRepository>();

        service_ = std::make_unique<MessageSubmissionService>(auth_service_, sequence_allocator_, idempotency_guard_,
                                                              message_repo_, delivery_repo_, outbox_repo_, audit_repo_,
                                                              nullptr, nullptr);

        // Set up active test conversation
        test_conv_id_ = ConversationId::generate_v7();
        test_alice_ = UserId("018d0000-0000-7000-8000-000000000001");
        test_bob_ = UserId("018d0000-0000-7000-8000-000000000002");
        alice_device_ = DeviceId("alice-device-phone");
        bob_device_ = DeviceId("bob-device-tablet");

        ConversationEntity conv{test_conv_id_, ConversationType::Direct, test_alice_};
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
    std::shared_ptr<ThreadSafeIdempotencyRepo> idempotency_repo_;
    std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard_;
    std::shared_ptr<ThreadSafeMessageRepo> message_repo_;
    std::shared_ptr<ThreadSafeDeliveryStateRepo> delivery_repo_;
    std::shared_ptr<ThreadSafeOutboxRepo> outbox_repo_;
    std::shared_ptr<repository::InMemoryMessagingAuditOutboxRepository> audit_repo_;

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
                                          delivery_repo_, outbox_repo_, audit_repo_, nullptr, nullptr),
                 std::invalid_argument);
    EXPECT_THROW(MessageSubmissionService(auth_service_, nullptr, idempotency_guard_, message_repo_, delivery_repo_,
                                          outbox_repo_, audit_repo_, nullptr, nullptr),
                 std::invalid_argument);
    EXPECT_THROW(MessageSubmissionService(auth_service_, sequence_allocator_, nullptr, message_repo_, delivery_repo_,
                                          outbox_repo_, audit_repo_, nullptr, nullptr),
                 std::invalid_argument);
    EXPECT_THROW(MessageSubmissionService(auth_service_, sequence_allocator_, idempotency_guard_, nullptr,
                                          delivery_repo_, outbox_repo_, audit_repo_, nullptr, nullptr),
                 std::invalid_argument);
    EXPECT_THROW(MessageSubmissionService(auth_service_, sequence_allocator_, idempotency_guard_, message_repo_,
                                          nullptr, outbox_repo_, audit_repo_, nullptr, nullptr),
                 std::invalid_argument);
    EXPECT_THROW(MessageSubmissionService(auth_service_, sequence_allocator_, idempotency_guard_, message_repo_,
                                          delivery_repo_, nullptr, audit_repo_, nullptr, nullptr),
                 std::invalid_argument);
    EXPECT_THROW(MessageSubmissionService(auth_service_, sequence_allocator_, idempotency_guard_, message_repo_,
                                          delivery_repo_, outbox_repo_, nullptr, nullptr, nullptr),
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

    auto saved_msgs = message_repo_->get_all_saved();
    ASSERT_EQ(saved_msgs.size(), 1U);
    EXPECT_EQ(saved_msgs.front().message_id, result.value.message_id);
    EXPECT_EQ(saved_msgs.front().conversation_id, test_conv_id_);

    auto saved_pending = delivery_repo_->get_saved_pending();
    ASSERT_EQ(saved_pending.size(), 1U);
    EXPECT_EQ(saved_pending.front().device_id, bob_device_);
    EXPECT_EQ(saved_pending.front().message_id, result.value.message_id);

    auto saved_recipient_states = delivery_repo_->get_saved_recipient_states();
    ASSERT_EQ(saved_recipient_states.size(), 1U);
    EXPECT_EQ(saved_recipient_states.front().recipient_device_id, bob_device_);

    auto enqueued_events = outbox_repo_->get_enqueued_events();
    ASSERT_EQ(enqueued_events.size(), 1U);
    EXPECT_EQ(enqueued_events.front().event_type, domain::ConversationOutboxEventType::MessageSent);

    auto idem_rec = idempotency_guard_->find_submission(alice_device_, cmd.client_idempotency_token);
    ASSERT_TRUE(idem_rec.has_value());
    EXPECT_EQ(idem_rec->submission_status, SubmissionStatus::Committed);
}

TEST_F(MessageSubmissionServiceTest, ImmediateIdenticalReplayReturnsCachedWithoutDuplicateWrites) {
    auto cmd = make_valid_command();

    auto res1 = service_->submit_message(cmd);
    ASSERT_TRUE(res1.success);
    EXPECT_FALSE(res1.value.is_replay);

    const size_t msg_count = message_repo_->get_all_saved().size();
    const size_t delivery_count = delivery_repo_->get_saved_pending().size();
    const size_t outbox_count = outbox_repo_->get_enqueued_events().size();

    auto res2 = service_->submit_message(cmd);
    ASSERT_TRUE(res2.success);
    EXPECT_TRUE(res2.value.is_replay);
    EXPECT_EQ(res2.value.message_id, res1.value.message_id);

    EXPECT_EQ(message_repo_->get_all_saved().size(), msg_count);
    EXPECT_EQ(delivery_repo_->get_saved_pending().size(), delivery_count);
    EXPECT_EQ(outbox_repo_->get_enqueued_events().size(), outbox_count);
}

TEST_F(MessageSubmissionServiceTest, ValidationFailureFailsFastBeforePersistence) {
    auto cmd = make_valid_command();
    cmd.conversation_id = ConversationId{}; // nil UUID

    auto res = service_->submit_message(cmd);
    EXPECT_FALSE(res.success);
    EXPECT_NE(res.error_message.find("Conversation ID"), std::string::npos);

    EXPECT_TRUE(message_repo_->get_all_saved().empty());
}

TEST_F(MessageSubmissionServiceTest, UnauthorizedUserRejected) {
    auto cmd = make_valid_command();
    cmd.caller_user_id = UserId("018d0000-0000-7000-8000-000000000099");

    auto res = service_->submit_message(cmd);
    EXPECT_FALSE(res.success);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);

    EXPECT_TRUE(message_repo_->get_all_saved().empty());

    const auto audit_records = audit_repo_->all_records();
    ASSERT_EQ(audit_records.size(), 1U);
    const auto& rec = audit_records[0];
    EXPECT_EQ(rec.event_type, "security.authorization.denied");
    EXPECT_EQ(rec.severity, "SECURITY");
    EXPECT_TRUE(domain::is_valid_audit_uuid_v7(rec.event_id));
    EXPECT_EQ(rec.outbox_bucket, domain::compute_outbox_bucket_utc(rec.created_at));
    EXPECT_EQ(rec.shard_id, domain::compute_outbox_shard_id(test_conv_id_.to_string()));
    ASSERT_FALSE(rec.payload_proto_bin.empty());
    securecloud::audit::v1::AuditEventProto proto;
    ASSERT_TRUE(proto.ParseFromArray(rec.payload_proto_bin.data(), static_cast<int>(rec.payload_proto_bin.size())));
    EXPECT_EQ(proto.event_type(), "security.authorization.denied");
    EXPECT_EQ(proto.severity(), securecloud::audit::v1::SEVERITY_SECURITY);
    EXPECT_EQ(proto.producer_service(), securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING);
}

TEST_F(MessageSubmissionServiceTest, ConflictingIdempotencyTokenRejected) {
    auto cmd1 = make_valid_command("shared-token-key");
    auto res1 = service_->submit_message(cmd1);
    ASSERT_TRUE(res1.success);

    auto cmd2 = cmd1;
    cmd2.delivery_targets[0].ciphertext_blob = "tampered_ciphertext_data";

    auto res2 = service_->submit_message(cmd2);
    EXPECT_FALSE(res2.success);
    EXPECT_EQ(res2.error_code, v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT);
}

TEST_F(MessageSubmissionServiceTest, PersistenceFailureMarksIdempotencyFailedForRetry) {
    auto cmd = make_valid_command();
    message_repo_->set_throw_on_save(true);

    auto res = service_->submit_message(cmd);
    EXPECT_FALSE(res.success);
    EXPECT_NE(res.error_message.find("Message persistence failed"), std::string::npos);

    auto idem_rec = idempotency_guard_->find_submission(alice_device_, cmd.client_idempotency_token);
    ASSERT_TRUE(idem_rec.has_value());
    EXPECT_EQ(idem_rec->submission_status, SubmissionStatus::Failed);

    message_repo_->set_throw_on_save(false);
    auto retry_res = service_->submit_message(cmd);
    EXPECT_TRUE(retry_res.success);
    EXPECT_FALSE(retry_res.value.is_replay);
    EXPECT_EQ(retry_res.value.message_sequence, 2U);
}

TEST_F(MessageSubmissionServiceTest, EmergencyMessageSubmissionStagesCanonicalAuditRecordsAndCriticalEvent) {
    auto cmd = make_valid_command("tok-emergency-001");
    cmd.priority = MessagePriority::Emergency;

    auto res = service_->submit_message(cmd);
    ASSERT_TRUE(res.success);

    const auto audit_records = audit_repo_->all_records();
    ASSERT_EQ(audit_records.size(), 2U);

    bool saw_submitted = false;
    bool saw_emergency = false;
    for (const auto& rec : audit_records) {
        EXPECT_TRUE(domain::is_valid_audit_uuid_v7(rec.event_id));
        EXPECT_EQ(rec.outbox_bucket, domain::compute_outbox_bucket_utc(rec.created_at));
        EXPECT_EQ(rec.shard_id, domain::compute_outbox_shard_id(test_conv_id_.to_string()));
        ASSERT_FALSE(rec.payload_proto_bin.empty());

        securecloud::audit::v1::AuditEventProto proto;
        ASSERT_TRUE(proto.ParseFromArray(rec.payload_proto_bin.data(), static_cast<int>(rec.payload_proto_bin.size())));
        EXPECT_EQ(proto.event_id(), rec.event_id);
        EXPECT_EQ(proto.producer_service(), securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING);

        if (rec.event_type == "message.submitted") {
            saw_submitted = true;
            EXPECT_EQ(rec.event_id, domain::generate_message_audit_event_id(
                                        res.value.message_id, domain::MessagingAuditEventType::MessageSubmitted));
            EXPECT_EQ(rec.severity, "INFO");
            EXPECT_EQ(proto.severity(), securecloud::audit::v1::SEVERITY_INFO);
        } else if (rec.event_type == "emergency.activated") {
            saw_emergency = true;
            EXPECT_EQ(rec.event_id, domain::generate_message_audit_event_id(
                                        res.value.message_id, domain::MessagingAuditEventType::EmergencyActivated));
            EXPECT_EQ(rec.severity, "CRITICAL");
            EXPECT_EQ(proto.severity(), securecloud::audit::v1::SEVERITY_CRITICAL);
        }
    }
    EXPECT_TRUE(saw_submitted);
    EXPECT_TRUE(saw_emergency);
}

TEST_F(MessageSubmissionServiceTest, IdempotentReplayDoesNotDowngradePublishedAuditEvent) {
    auto cmd = make_valid_command("tok-published-preserve-001");
    auto res1 = service_->submit_message(cmd);
    ASSERT_TRUE(res1.success);

    const auto initial_records = audit_repo_->all_records();
    ASSERT_EQ(initial_records.size(), 1U);
    const auto& rec = initial_records[0];
    EXPECT_EQ(rec.publish_status, "PENDING");

    audit_repo_->mark_published(rec.outbox_bucket, rec.shard_id, rec.created_at, rec.event_id);
    const auto published_before =
        audit_repo_->find_record(rec.outbox_bucket, rec.shard_id, rec.created_at, rec.event_id);
    ASSERT_TRUE(published_before.has_value());
    EXPECT_EQ(published_before->publish_status, "PUBLISHED");

    auto res2 = service_->submit_message(cmd);
    ASSERT_TRUE(res2.success);
    EXPECT_TRUE(res2.value.is_replay);
    EXPECT_EQ(audit_repo_->total_records(), 1U);

    const auto published_after =
        audit_repo_->find_record(rec.outbox_bucket, rec.shard_id, rec.created_at, rec.event_id);
    ASSERT_TRUE(published_after.has_value());
    EXPECT_EQ(published_after->publish_status, "PUBLISHED");
}

TEST_F(MessageSubmissionServiceTest, IdempotentReplayForwardRecoversMissingAuditEvent) {
    auto cmd = make_valid_command("tok-forward-recover-001");
    auto res1 = service_->submit_message(cmd);
    ASSERT_TRUE(res1.success);

    auto fresh_audit_repo = std::make_shared<repository::InMemoryMessagingAuditOutboxRepository>();
    MessageSubmissionService recovery_service(auth_service_, sequence_allocator_, idempotency_guard_, message_repo_,
                                              delivery_repo_, outbox_repo_, fresh_audit_repo, nullptr, nullptr);

    auto res2 = recovery_service.submit_message(cmd);
    ASSERT_TRUE(res2.success);
    EXPECT_TRUE(res2.value.is_replay);
    EXPECT_EQ(res2.value.message_id, res1.value.message_id);

    const auto recovered = fresh_audit_repo->all_records();
    ASSERT_EQ(recovered.size(), 1U);
    EXPECT_EQ(recovered[0].event_id, domain::generate_message_audit_event_id(
                                         res1.value.message_id, domain::MessagingAuditEventType::MessageSubmitted));

    securecloud::audit::v1::AuditEventProto proto;
    ASSERT_TRUE(proto.ParseFromArray(recovered[0].payload_proto_bin.data(),
                                     static_cast<int>(recovered[0].payload_proto_bin.size())));
    ASSERT_TRUE(proto.metadata().contains("forward_recovered"));
    EXPECT_EQ(proto.metadata().at("forward_recovered"), "true");
}

} // namespace
} // namespace securecloud::messaging::service::test
