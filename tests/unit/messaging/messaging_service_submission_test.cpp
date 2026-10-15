#include "concurrency/bounded_worker_pool.hpp"
#include "domain/conversation_types.hpp"
#include "domain/message_entity.hpp"
#include "domain/submission_types.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/idempotency_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "securecloud/grpc/caller_context.hpp"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "service/conversation_authorization_service.hpp"
#include "service/idempotency_guard.hpp"
#include "service/in_memory_sequence_allocator.hpp"
#include "service/message_submission_service.hpp"
#include "service/messaging_caller_context.hpp"
#include "service/messaging_error_mapper.hpp"
#include "service/messaging_service_impl.hpp"

#include <chrono>
#include <deque>
#include <future>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace grpc::testing {

class ServerContextTestSpouse {
  public:
    explicit ServerContextTestSpouse(::grpc::ServerContext* ctx) : ctx_(ctx) {}

    void add_client_metadata(const std::string& key, const std::string& val) {
        stored_strings_.push_back(key);
        stored_strings_.push_back(val);
        const auto& k = stored_strings_[stored_strings_.size() - 2];
        const auto& v = stored_strings_.back();
        ctx_->client_metadata_.map()->insert(
            std::make_pair(::grpc::string_ref(k.data(), k.size()), ::grpc::string_ref(v.data(), v.size())));
    }

  private:
    ::grpc::ServerContext* ctx_;
    std::deque<std::string> stored_strings_;
};

} // namespace grpc::testing

namespace securecloud::messaging::service {
namespace {

using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::IdempotencyRecord;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::ParticipantRole;
using domain::RecipientDeliveryState;
using domain::SubmissionStatus;
using domain::UserId;

// ============================================================================
// Test Mock Repositories
// ============================================================================

class MockMessageRepo : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override { saved_messages.push_back(msg); }
    std::optional<MessageEntity> find_by_id(const ConversationId&, const MessageBucket&, const MessageId&) override {
        return std::nullopt;
    }
    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId&, const MessageBucket&, uint64_t,
                                                               uint64_t, size_t) override {
        return {};
    }
    uint64_t get_last_sequence(const ConversationId&, const MessageBucket&) override { return 0; }

    std::vector<MessageEntity> saved_messages;
};

class MockDeliveryStateRepo : public repository::IDeliveryStateRepository {
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

class MockOutboxRepo : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string&) override {
        enqueued_events.push_back(event);
    }
    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }
    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

    std::vector<ConversationOutboxEvent> enqueued_events;
};

class MockIdempotencyRepo : public repository::IIdempotencyRepository {
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

class MessagingServiceSubmissionTest : public ::testing::Test {
  protected:
    void SetUp() override {
        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        memb_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *memb_repo_);
        sequence_allocator_ = std::make_shared<InMemorySequenceAllocator>();
        idempotency_repo_ = std::make_shared<MockIdempotencyRepo>();
        idempotency_guard_ = std::make_shared<MessageSubmissionIdempotencyGuard>(idempotency_repo_);
        message_repo_ = std::make_shared<MockMessageRepo>();
        delivery_repo_ = std::make_shared<MockDeliveryStateRepo>();
        outbox_repo_ = std::make_shared<MockOutboxRepo>();

        submission_service_ = std::make_shared<MessageSubmissionService>(
            auth_service_, sequence_allocator_, idempotency_guard_, message_repo_, delivery_repo_, outbox_repo_);

        service_impl_ = std::make_unique<MessagingServiceImpl>(nullptr, nullptr, nullptr, nullptr, submission_service_);

        test_conv_id_ = ConversationId::generate_v7();
        test_alice_ = UserId("018d0000-0000-7000-8000-000000000001");
        test_bob_ = UserId("018d0000-0000-7000-8000-000000000002");
        alice_device_ = DeviceId("018d0000-0000-7000-8000-000000000011");
        bob_device_ = DeviceId("018d0000-0000-7000-8000-000000000022");

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

    v1::SendMessageRequest make_valid_request(const std::string& token = "tok-1234567890abcdef") {
        v1::SendMessageRequest req;
        req.set_conversation_id(test_conv_id_.to_string());
        req.set_sender_device_id(alice_device_.str());
        req.set_priority(v1::MESSAGE_PRIORITY_NORMAL);
        req.set_client_idempotency_token(token);

        auto* target = req.add_delivery_targets();
        target->set_recipient_user_id(test_bob_.str());
        target->set_recipient_device_id(bob_device_.str());

        auto* payload = target->mutable_encrypted_payload();
        payload->set_ciphertext_blob("encrypted-ciphertext-bytes");
        payload->set_ephemeral_public_key(std::string(32, '\xAA'));
        payload->set_initialization_vector(std::string(24, '\xBB'));
        payload->set_auth_tag(std::string(16, '\xCC'));
        payload->set_algorithm("XChaCha20-Poly1305");

        return req;
    }

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> memb_repo_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<InMemorySequenceAllocator> sequence_allocator_;
    std::shared_ptr<MockIdempotencyRepo> idempotency_repo_;
    std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard_;
    std::shared_ptr<MockMessageRepo> message_repo_;
    std::shared_ptr<MockDeliveryStateRepo> delivery_repo_;
    std::shared_ptr<MockOutboxRepo> outbox_repo_;
    std::shared_ptr<MessageSubmissionService> submission_service_;
    std::unique_ptr<MessagingServiceImpl> service_impl_;

    ConversationId test_conv_id_;
    UserId test_alice_;
    UserId test_bob_;
    DeviceId alice_device_;
    DeviceId bob_device_;
};

// ============================================================================
// Unit Tests
// ============================================================================

TEST_F(MessagingServiceSubmissionTest, NullSubmissionServiceReturnsUnimplemented) {
    MessagingServiceImpl unimpl_service(nullptr, nullptr, nullptr, nullptr, nullptr);
    ::grpc::ServerContext context;
    v1::SendMessageRequest req = make_valid_request();
    v1::SendMessageResponse resp;

    auto status = unimpl_service.SendMessage(&context, &req, &resp);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

TEST_F(MessagingServiceSubmissionTest, NullRequestOrResponseReturnsInvalidArgument) {
    ::grpc::ServerContext context;
    v1::SendMessageResponse resp;

    auto status1 = service_impl_->SendMessage(&context, nullptr, &resp);
    EXPECT_EQ(status1.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);

    v1::SendMessageRequest req = make_valid_request();
    auto status2 = service_impl_->SendMessage(&context, &req, nullptr);
    EXPECT_EQ(status2.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(MessagingServiceSubmissionTest, UnauthenticatedCallerRejected) {
    ::grpc::ServerContext context; // No x-user-id metadata
    v1::SendMessageRequest req = make_valid_request();
    v1::SendMessageResponse resp;

    auto status = service_impl_->SendMessage(&context, &req, &resp);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::UNAUTHENTICATED);
}

TEST_F(MessagingServiceSubmissionTest, MissingDeviceIdRejected) {
    ::grpc::ServerContext context;
    ::grpc::testing::ServerContextTestSpouse spouse(&context);
    spouse.add_client_metadata("x-user-id", test_alice_.str());

    v1::SendMessageRequest req = make_valid_request();
    req.clear_sender_device_id(); // Clear device ID in request as well
    v1::SendMessageResponse resp;

    auto status = service_impl_->SendMessage(&context, &req, &resp);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(MessagingServiceSubmissionTest, InvalidConversationIdFormatRejected) {
    ::grpc::ServerContext context;
    ::grpc::testing::ServerContextTestSpouse spouse(&context);
    spouse.add_client_metadata("x-user-id", test_alice_.str());
    spouse.add_client_metadata("x-device-id", alice_device_.str());

    v1::SendMessageRequest req = make_valid_request();
    req.set_conversation_id("invalid-not-a-uuid");
    v1::SendMessageResponse resp;

    auto status = service_impl_->SendMessage(&context, &req, &resp);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::NOT_FOUND);
}

TEST_F(MessagingServiceSubmissionTest, HappyPathSubmissionSuccess) {
    ::grpc::ServerContext context;
    ::grpc::testing::ServerContextTestSpouse spouse(&context);
    spouse.add_client_metadata("x-user-id", test_alice_.str());
    spouse.add_client_metadata("x-device-id", alice_device_.str());
    spouse.add_client_metadata("x-correlation-id", "018d0000-0000-7000-8000-000000000099");

    v1::SendMessageRequest req = make_valid_request("tok-valid-token-12345");
    v1::SendMessageResponse resp;

    auto status = service_impl_->SendMessage(&context, &req, &resp);
    ASSERT_TRUE(status.ok()) << "Error: " << status.error_message();

    EXPECT_FALSE(resp.message_id().empty());
    EXPECT_EQ(resp.conversation_id(), test_conv_id_.to_string());
    EXPECT_GT(resp.accepted_at_unix_ms(), 0);
    EXPECT_EQ(resp.initial_state(), v1::DELIVERY_STATE_QUEUED);
    EXPECT_EQ(resp.target_count(), 1u);

    // Verify persistence
    EXPECT_EQ(message_repo_->saved_messages.size(), 1u);
    EXPECT_EQ(delivery_repo_->saved_pending.size(), 1u);
    EXPECT_EQ(outbox_repo_->enqueued_events.size(), 1u);
}

TEST_F(MessagingServiceSubmissionTest, DuplicateReplayReturnsCachedResponse) {
    ::grpc::ServerContext context1;
    ::grpc::testing::ServerContextTestSpouse spouse1(&context1);
    spouse1.add_client_metadata("x-user-id", test_alice_.str());
    spouse1.add_client_metadata("x-device-id", alice_device_.str());

    v1::SendMessageRequest req = make_valid_request("tok-replay-test-12345");
    v1::SendMessageResponse resp1;
    auto status1 = service_impl_->SendMessage(&context1, &req, &resp1);
    ASSERT_TRUE(status1.ok());

    // Resend exact same request
    ::grpc::ServerContext context2;
    ::grpc::testing::ServerContextTestSpouse spouse2(&context2);
    spouse2.add_client_metadata("x-user-id", test_alice_.str());
    spouse2.add_client_metadata("x-device-id", alice_device_.str());

    v1::SendMessageResponse resp2;
    auto status2 = service_impl_->SendMessage(&context2, &req, &resp2);
    ASSERT_TRUE(status2.ok());

    EXPECT_EQ(resp1.message_id(), resp2.message_id());
    EXPECT_EQ(resp1.conversation_id(), resp2.conversation_id());
    EXPECT_NEAR(resp1.accepted_at_unix_ms(), resp2.accepted_at_unix_ms(), 100);

    // 0 duplicate secondary writes
    EXPECT_EQ(message_repo_->saved_messages.size(), 1u);
    EXPECT_EQ(delivery_repo_->saved_pending.size(), 1u);
    EXPECT_EQ(outbox_repo_->enqueued_events.size(), 1u);
}

TEST_F(MessagingServiceSubmissionTest, ConflictingIdempotencyKeyRejection) {
    ::grpc::ServerContext context1;
    ::grpc::testing::ServerContextTestSpouse spouse1(&context1);
    spouse1.add_client_metadata("x-user-id", test_alice_.str());
    spouse1.add_client_metadata("x-device-id", alice_device_.str());

    v1::SendMessageRequest req1 = make_valid_request("tok-conflict-test-123");
    v1::SendMessageResponse resp1;
    auto status1 = service_impl_->SendMessage(&context1, &req1, &resp1);
    ASSERT_TRUE(status1.ok());

    // Send differing payload with the same idempotency token
    ::grpc::ServerContext context2;
    ::grpc::testing::ServerContextTestSpouse spouse2(&context2);
    spouse2.add_client_metadata("x-user-id", test_alice_.str());
    spouse2.add_client_metadata("x-device-id", alice_device_.str());

    v1::SendMessageRequest req2 = make_valid_request("tok-conflict-test-123");
    req2.mutable_delivery_targets(0)->mutable_encrypted_payload()->set_ciphertext_blob("different-ciphertext");
    v1::SendMessageResponse resp2;

    auto status2 = service_impl_->SendMessage(&context2, &req2, &resp2);
    EXPECT_EQ(status2.error_code(), ::grpc::StatusCode::ALREADY_EXISTS);
}

TEST_F(MessagingServiceSubmissionTest, NonParticipantRejectedWithPermissionDenied) {
    UserId charlie("018d0000-0000-7000-8000-000000000003");
    DeviceId charlie_device("018d0000-0000-7000-8000-000000000033");

    ::grpc::ServerContext context;
    ::grpc::testing::ServerContextTestSpouse spouse(&context);
    spouse.add_client_metadata("x-user-id", charlie.str());
    spouse.add_client_metadata("x-device-id", charlie_device.str());

    v1::SendMessageRequest req = make_valid_request("tok-unauth-member-123");
    req.set_sender_device_id(charlie_device.str());
    v1::SendMessageResponse resp;

    auto status = service_impl_->SendMessage(&context, &req, &resp);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(MessagingServiceSubmissionTest, WorkerPoolCapacityExceededRejection) {
    // Pool with 1 worker and 1 queued task capacity
    auto pool = std::make_shared<concurrency::BoundedWorkerPool>(1, 1, "test-sub-pool");

    auto busy_service = std::make_unique<MessagingServiceImpl>(pool, nullptr, nullptr, nullptr, submission_service_);

    std::atomic<bool> worker_blocked{true};
    std::promise<void> worker_running;
    auto worker_started = worker_running.get_future();

    // 1. Occupy the single worker thread
    ASSERT_TRUE(pool->try_submit([&]() {
        worker_running.set_value();
        while (worker_blocked.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }));

    worker_started.wait();

    // 2. Fill the single available queue slot
    ASSERT_TRUE(pool->try_submit([]() {}));

    // 3. With worker busy and queue saturated, subsequent submission must fail fast with RESOURCE_EXHAUSTED
    ::grpc::ServerContext context;
    ::grpc::testing::ServerContextTestSpouse spouse(&context);
    spouse.add_client_metadata("x-user-id", test_alice_.str());
    spouse.add_client_metadata("x-device-id", alice_device_.str());
    v1::SendMessageRequest req = make_valid_request("tok-queue-full-12345");
    v1::SendMessageResponse resp;

    auto status = busy_service->SendMessage(&context, &req, &resp);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::RESOURCE_EXHAUSTED);

    // Unblock worker and clean up
    worker_blocked.store(false);
    pool->drain_and_stop();
}

} // namespace
} // namespace securecloud::messaging::service
