#include "concurrency/bounded_worker_pool.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/message_entity.hpp"
#include "domain/outbox_event.hpp"
#include "domain/read_receipt_types.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "repository/message_repository_interface.hpp"
#include "repository/sync_cursor_repository_interface.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/delivery_service.hpp"
#include "service/message_sync_service.hpp"
#include "service/messaging_service_impl.hpp"
#include "service/read_receipt_commands.hpp"
#include "service/read_receipt_service.hpp"
#include "service/sync_cursor_manager.hpp"

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"

#include <chrono>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <vector>

namespace securecloud::messaging::service {
namespace {

using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryState;
using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::DeviceSyncCursor;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::ParticipantRole;
using domain::RecipientDeliveryState;
using domain::UserId;

// ============================================================================
// Mocks
// ============================================================================

class MockDeliveryStateRepo final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<domain::DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.insert(pending_.end(), records.begin(), records.end());
    }

    std::vector<domain::DeviceDeliveryRecord>
    fetch_pending_for_device(const DeviceId& device_id, const std::string& delivery_bucket, size_t) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<domain::DeviceDeliveryRecord> result;
        for (const auto& rec : pending_) {
            if (rec.device_id == device_id && rec.delivery_bucket == delivery_bucket) {
                result.push_back(rec);
            }
        }
        return result;
    }

    void update_device_delivery_status(const DeviceId& device_id, const std::string& delivery_bucket,
                                       const std::chrono::system_clock::time_point& accepted_at,
                                       const MessageId& message_id, DeliveryState state, int32_t attempt_count,
                                       std::optional<std::chrono::system_clock::time_point> next_retry) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& rec : pending_) {
            if (rec.device_id == device_id && rec.delivery_bucket == delivery_bucket &&
                rec.accepted_at == accepted_at && rec.message_id == message_id) {
                rec.delivery_state = state;
                rec.attempt_count = attempt_count;
                rec.next_retry_at = next_retry;
                break;
            }
        }
    }

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mutex_);
        recipient_states_.insert(recipient_states_.end(), states.begin(), states.end());
    }

    void record_delivery_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point& delivered_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        recorded_acks_.push_back({message_id, recipient_device_id, delivered_at});
        for (auto& s : recipient_states_) {
            if (s.message_id == message_id && s.recipient_device_id == recipient_device_id) {
                s.delivery_state = domain::DeliveryState::Delivered;
                s.delivered_at = delivered_at;
                break;
            }
        }
    }

    void record_read_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                         const std::chrono::system_clock::time_point& read_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& s : recipient_states_) {
            if (s.message_id == message_id && s.recipient_device_id == recipient_device_id) {
                s.delivery_state = domain::DeliveryState::Read;
                s.read_at = read_at;
                break;
            }
        }
    }

    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<RecipientDeliveryState> result;
        for (const auto& s : recipient_states_) {
            if (s.message_id == message_id) {
                result.push_back(s);
            }
        }
        return result;
    }

    struct AckEntry {
        MessageId message_id;
        DeviceId device_id;
        std::chrono::system_clock::time_point delivered_at;
    };

    std::mutex mutex_;
    std::vector<domain::DeviceDeliveryRecord> pending_;
    std::vector<RecipientDeliveryState> recipient_states_;
    std::vector<AckEntry> recorded_acks_;
};

class MockOutboxRepo final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const domain::ConversationOutboxEvent& event, const std::string&) override {
        std::lock_guard<std::mutex> lock(mutex_);
        enqueued_events_.push_back(event);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }

    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

    std::mutex mutex_;
    std::vector<domain::ConversationOutboxEvent> enqueued_events_;
};

class MockSyncCursorRepo final : public repository::ISyncCursorRepository {
  public:
    std::optional<DeviceSyncCursor> get_sync_cursor(const DeviceId& device_id,
                                                    const ConversationId& conversation_id) override {
        auto key = std::make_pair(device_id.str(), conversation_id.to_string());
        auto it = store_.find(key);
        if (it != store_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::vector<DeviceSyncCursor> list_sync_cursors_by_device(const DeviceId& device_id) override {
        std::vector<DeviceSyncCursor> results;
        for (const auto& [key, cursor] : store_) {
            if (key.first == device_id.str()) {
                results.push_back(cursor);
            }
        }
        return results;
    }

    void upsert_sync_cursor(const DeviceSyncCursor& cursor) override {
        auto key = std::make_pair(cursor.device_id.str(), cursor.conversation_id.to_string());
        store_[key] = cursor;
    }

  private:
    std::map<std::pair<std::string, std::string>, DeviceSyncCursor> store_;
};

class MockMessageRepo final : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override {
        messages_[msg.conversation_id.to_string()].push_back(msg);
        auto& msgs = messages_[msg.conversation_id.to_string()];
        std::sort(msgs.begin(), msgs.end(), [](const MessageEntity& a, const MessageEntity& b) {
            return a.message_sequence < b.message_sequence;
        });
    }

    std::optional<MessageEntity> find_by_id(const ConversationId& conv, const MessageBucket& /*bucket*/,
                                            const MessageId& id) override {
        auto it = messages_.find(conv.to_string());
        if (it == messages_.end()) {
            return std::nullopt;
        }
        for (const auto& msg : it->second) {
            if (msg.message_id == id) {
                return msg;
            }
        }
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId& conv,
                                                               const MessageBucket& /*bucket*/, uint64_t from,
                                                               uint64_t to, size_t limit) override {
        std::vector<MessageEntity> results;
        auto it = messages_.find(conv.to_string());
        if (it == messages_.end()) {
            return results;
        }

        for (const auto& msg : it->second) {
            if (msg.message_sequence >= from && msg.message_sequence <= to) {
                results.push_back(msg);
                if (results.size() >= limit) {
                    break;
                }
            }
        }
        return results;
    }

    uint64_t get_last_sequence(const ConversationId& conversation_id, const MessageBucket& /*bucket*/) override {
        auto it = messages_.find(conversation_id.to_string());
        if (it == messages_.end() || it->second.empty()) {
            return 0;
        }
        return it->second.back().message_sequence;
    }

  private:
    std::map<std::string, std::vector<MessageEntity>> messages_;
};

// ============================================================================
// Unit Tests for Anti-Impersonation
// ============================================================================

class DeviceAntiImpersonationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        alice_user_ = UserId("018f2d52-0000-7000-8000-000000000001");
        alice_phone_ = DeviceId("018f2d52-0000-7000-8000-00000000000a");
        alice_laptop_ = DeviceId("018f2d52-0000-7000-8000-00000000000b");
        conv_id_ = ConversationId::generate_v7();
        msg_id_ = MessageId::generate_v7();

        delivery_repo_ = std::make_shared<MockDeliveryStateRepo>();
        outbox_repo_ = std::make_shared<MockOutboxRepo>();
        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        member_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        message_repo_ = std::make_shared<MockMessageRepo>();
        cursor_repo_ = std::make_shared<MockSyncCursorRepo>();

        delivery_service_ = std::make_shared<DeliveryService>(delivery_repo_, outbox_repo_);
        read_receipt_service_ = std::make_shared<ReadReceiptService>(delivery_repo_, member_repo_, outbox_repo_,
                                                                     [](const DeviceId&) { return true; });

        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *member_repo_);
        cursor_manager_ = std::make_shared<SyncCursorManager>(cursor_repo_, message_repo_);
        sync_service_ = std::make_shared<MessageSyncService>(message_repo_, cursor_manager_, auth_service_);

        worker_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(2, 10, "test_worker_pool");

        // Seed conversation & membership
        auto now = std::chrono::system_clock::now();
        ConversationEntity conv{
            .conversation_id = conv_id_,
            .type = ConversationType::Direct,
            .created_by_user_id = alice_user_,
            .created_at = now,
        };
        conv_repo_->save_conversation(conv);

        ConversationParticipantEntity p_alice{
            .conversation_id = conv_id_,
            .user_id = alice_user_,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = now,
        };
        member_repo_->add_participant(p_alice);

        // Seed delivery states for Alice's Laptop
        RecipientDeliveryState s_laptop{
            .message_id = msg_id_,
            .recipient_device_id = alice_laptop_,
            .recipient_user_id = alice_user_,
            .delivery_state = DeliveryState::Queued,
            .delivered_at = std::nullopt,
            .read_at = std::nullopt,
        };
        delivery_repo_->save_recipient_delivery_states({s_laptop});

        // Seed a message for sync
        MessageEntity msg{
            .conversation_id = conv_id_,
            .message_bucket = MessageBucket::from_time_point(now),
            .message_sequence = 1,
            .message_id = msg_id_,
            .sender_user_id = alice_user_,
            .sender_device_id = alice_phone_,
            .priority = domain::MessagePriority::Normal,
            .accepted_at = now,
            .envelope = domain::CiphertextEnvelope{.ciphertext = "cipher-1", .envelope_version = 1},
            .file_reference_ids = {},
        };
        message_repo_->save_message(msg);

        // Build gRPC service and in-process server
        service_impl_ = std::make_unique<MessagingServiceImpl>(worker_pool_, worker_pool_, worker_pool_, nullptr,
                                                               nullptr, delivery_service_, read_receipt_service_,
                                                               sync_service_, cursor_manager_);

        grpc::ServerBuilder builder;
        builder.RegisterService(service_impl_.get());
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);

        channel_ = server_->InProcessChannel(grpc::ChannelArguments{});
        ASSERT_NE(channel_, nullptr);
        stub_ = v1::MessagingService::NewStub(channel_);
        ASSERT_NE(stub_, nullptr);
    }

    void TearDown() override {
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    UserId alice_user_;
    DeviceId alice_phone_;
    DeviceId alice_laptop_;
    ConversationId conv_id_;
    MessageId msg_id_;

    std::shared_ptr<MockDeliveryStateRepo> delivery_repo_;
    std::shared_ptr<MockOutboxRepo> outbox_repo_;
    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> member_repo_;
    std::shared_ptr<MockMessageRepo> message_repo_;
    std::shared_ptr<MockSyncCursorRepo> cursor_repo_;

    std::shared_ptr<DeliveryService> delivery_service_;
    std::shared_ptr<ReadReceiptService> read_receipt_service_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<SyncCursorManager> cursor_manager_;
    std::shared_ptr<MessageSyncService> sync_service_;
    std::shared_ptr<concurrency::BoundedWorkerPool> worker_pool_;

    std::unique_ptr<MessagingServiceImpl> service_impl_;
    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::MessagingService::Stub> stub_;
};

// ============================================================================
// 1. DeliveryService Domain Anti-Impersonation
// ============================================================================

TEST_F(DeviceAntiImpersonationTest, DeliveryService_RejectsCrossDeviceDeliveryAckWithinSameUser) {
    // Alice Phone attempts to acknowledge delivery for Alice Laptop
    DeliveryAckCommand cmd;
    cmd.message_id = msg_id_;
    cmd.recipient_device_id = alice_laptop_;
    cmd.caller_user_id = alice_user_;
    cmd.caller_device_id = alice_phone_; // Cross-device impersonation!
    cmd.delivered_at = std::chrono::system_clock::now();

    auto res = delivery_service_->acknowledge_delivery(cmd);
    EXPECT_FALSE(res.success);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
    EXPECT_NE(res.error_message.find("Caller device cannot acknowledge delivery on behalf of a different device"),
              std::string::npos);
}

TEST_F(DeviceAntiImpersonationTest, DeliveryService_AllowsMatchingDeviceDeliveryAck) {
    // Alice Laptop acknowledges delivery for Alice Laptop
    DeliveryAckCommand cmd;
    cmd.message_id = msg_id_;
    cmd.recipient_device_id = alice_laptop_;
    cmd.caller_user_id = alice_user_;
    cmd.caller_device_id = alice_laptop_; // Legitimate matching device
    cmd.delivered_at = std::chrono::system_clock::now();

    auto res = delivery_service_->acknowledge_delivery(cmd);
    EXPECT_TRUE(res.success);
    EXPECT_EQ(res.value.state, v1::DELIVERY_STATE_DELIVERED);
}

// ============================================================================
// 2. ReadReceiptService Domain Anti-Impersonation
// ============================================================================

TEST_F(DeviceAntiImpersonationTest, ReadReceiptService_RejectsCrossDeviceReadReceiptWithinSameUser) {
    // Alice Phone attempts to submit read receipt on behalf of Alice Laptop
    ReadReceiptCommand cmd;
    cmd.message_id = msg_id_;
    cmd.conversation_id = conv_id_;
    cmd.caller_user_id = alice_user_;
    cmd.reader_device_id = alice_laptop_;
    cmd.caller_device_id = alice_phone_; // Cross-device impersonation!
    cmd.read_at = std::chrono::system_clock::now();

    auto res = read_receipt_service_->record_read_receipt(cmd);
    EXPECT_FALSE(res.success);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
    EXPECT_NE(res.error_message.find("Caller device cannot submit read receipts on behalf of a different device"),
              std::string::npos);
}

TEST_F(DeviceAntiImpersonationTest, ReadReceiptService_AllowsMatchingDeviceReadReceipt) {
    // Alice Laptop submits read receipt for Alice Laptop
    ReadReceiptCommand cmd;
    cmd.message_id = msg_id_;
    cmd.conversation_id = conv_id_;
    cmd.caller_user_id = alice_user_;
    cmd.reader_device_id = alice_laptop_;
    cmd.caller_device_id = alice_laptop_; // Matching device
    cmd.read_at = std::chrono::system_clock::now();

    auto res = read_receipt_service_->record_read_receipt(cmd);
    EXPECT_TRUE(res.success);
    EXPECT_EQ(res.value.state, v1::DELIVERY_STATE_READ);
}

// ============================================================================
// 3. MessagingServiceImpl RPC Perimeter Anti-Impersonation
// ============================================================================

TEST_F(DeviceAntiImpersonationTest, AcknowledgeDelivery_RejectsCrossDeviceImpersonationAtPerimeter) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_phone_.str()); // Authenticated caller is Phone
    context.AddMetadata("x-correlation-id", "corr-anti-ack-1");

    v1::AcknowledgeDeliveryRequest request;
    request.set_message_id(msg_id_.to_string());
    request.set_recipient_device_id(alice_laptop_.str()); // Request targets Laptop!

    v1::AcknowledgeDeliveryResponse response;
    auto status = stub_->AcknowledgeDelivery(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_NE(status.error_message().find("Caller device cannot acknowledge delivery on behalf of a different device"),
              std::string::npos);
}

TEST_F(DeviceAntiImpersonationTest, SendReadReceipt_RejectsCrossDeviceImpersonationAtPerimeter) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_phone_.str()); // Authenticated caller is Phone
    context.AddMetadata("x-correlation-id", "corr-anti-read-1");

    v1::SendReadReceiptRequest request;
    request.set_message_id(msg_id_.to_string());
    request.set_conversation_id(conv_id_.to_string());
    request.set_reader_device_id(alice_laptop_.str()); // Request targets Laptop!

    v1::SendReadReceiptResponse response;
    auto status = stub_->SendReadReceipt(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_NE(status.error_message().find("Caller device cannot submit read receipts on behalf of a different device"),
              std::string::npos);
}

TEST_F(DeviceAntiImpersonationTest, GetMessages_RejectsCrossDeviceImpersonationAtPerimeter) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_phone_.str()); // Authenticated caller is Phone
    context.AddMetadata("x-correlation-id", "corr-anti-get-1");

    v1::GetMessagesRequest request;
    request.set_conversation_id(conv_id_.to_string());
    request.set_recipient_device_id(alice_laptop_.str()); // Request targets Laptop!

    v1::GetMessagesResponse response;
    auto status = stub_->GetMessages(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_NE(status.error_message().find("Caller device cannot query messages on behalf of a different device"),
              std::string::npos);
}

TEST_F(DeviceAntiImpersonationTest, SyncDeviceMessages_RejectsCrossDeviceImpersonationAtPerimeter) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_phone_.str()); // Authenticated caller is Phone
    context.AddMetadata("x-correlation-id", "corr-anti-sync-1");

    v1::SyncDeviceMessagesRequest request;
    request.set_conversation_id(conv_id_.to_string());
    request.set_device_id(alice_laptop_.str()); // Request targets Laptop!

    v1::SyncDeviceMessagesResponse response;
    auto status = stub_->SyncDeviceMessages(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_NE(status.error_message().find("Caller device cannot sync messages on behalf of a different device"),
              std::string::npos);
}

} // namespace
} // namespace securecloud::messaging::service
