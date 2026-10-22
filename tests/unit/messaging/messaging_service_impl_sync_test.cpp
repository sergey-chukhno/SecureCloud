#include "concurrency/bounded_worker_pool.hpp"
#include "domain/conversation_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/message_entity.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "repository/message_repository_interface.hpp"
#include "repository/sync_cursor_repository_interface.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/message_sync_service.hpp"
#include "service/messaging_service_impl.hpp"
#include "service/sync_cursor_manager.hpp"

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"

#include <algorithm>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace securecloud::messaging::service {
namespace {

using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeviceId;
using domain::DeviceSyncCursor;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::ParticipantRole;
using domain::UserId;

/// In-memory mock for ISyncCursorRepository
class MockSyncCursorRepo : public repository::ISyncCursorRepository {
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

/// In-memory mock for IMessageRepository supporting chronological range queries
class MockMessageRepo : public repository::IMessageRepository {
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

class MessagingServiceImplSyncTest : public ::testing::Test {
  protected:
    void SetUp() override {
        alice_user_ = UserId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        alice_device_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
        eve_user_ = UserId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
        conv_id_ = ConversationId::generate_v7();

        cursor_repo_ = std::make_shared<MockSyncCursorRepo>();
        message_repo_ = std::make_shared<MockMessageRepo>();
        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        member_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();

        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *member_repo_);
        cursor_manager_ = std::make_shared<SyncCursorManager>(cursor_repo_, message_repo_);
        sync_service_ = std::make_shared<MessageSyncService>(message_repo_, cursor_manager_, auth_service_);

        sync_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(2, 10, "test_sync_pool");

        // Setup active conversation membership for Alice
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

        // Pre-populate 3 messages in the conversation
        for (uint64_t seq = 1; seq <= 3; ++seq) {
            MessageEntity msg{
                .conversation_id = conv_id_,
                .message_bucket = MessageBucket::from_time_point(now),
                .message_sequence = seq,
                .message_id = MessageId::generate_v7(),
                .sender_user_id = alice_user_,
                .sender_device_id = alice_device_,
                .priority = domain::MessagePriority::Normal,
                .accepted_at = now,
                .envelope =
                    domain::CiphertextEnvelope{.ciphertext = "cipher-" + std::to_string(seq), .envelope_version = 1},
                .file_reference_ids = {},
            };
            message_repo_->save_message(msg);
        }

        service_impl_ = std::make_unique<MessagingServiceImpl>(nullptr, nullptr, sync_pool_, nullptr, nullptr, nullptr,
                                                               nullptr, sync_service_, cursor_manager_);

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
    DeviceId alice_device_;
    UserId eve_user_;
    ConversationId conv_id_;

    std::shared_ptr<MockSyncCursorRepo> cursor_repo_;
    std::shared_ptr<MockMessageRepo> message_repo_;
    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> member_repo_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<SyncCursorManager> cursor_manager_;
    std::shared_ptr<MessageSyncService> sync_service_;
    std::shared_ptr<concurrency::BoundedWorkerPool> sync_pool_;

    std::unique_ptr<MessagingServiceImpl> service_impl_;
    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::MessagingService::Stub> stub_;
};

// ============================================================================
// SyncDeviceMessages Tests
// ============================================================================

TEST_F(MessagingServiceImplSyncTest, SyncDeviceMessagesSuccess) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_device_.str());
    context.AddMetadata("x-correlation-id", "corr-sync-001");

    v1::SyncDeviceMessagesRequest request;
    request.set_device_id(alice_device_.str());
    request.set_conversation_id(conv_id_.to_string());
    request.set_since_sequence(0);
    request.set_max_messages(10);

    v1::SyncDeviceMessagesResponse response;
    auto status = stub_->SyncDeviceMessages(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "Error: " << status.error_message();
    EXPECT_EQ(response.device_id(), alice_device_.str());
    EXPECT_EQ(response.messages_size(), 3);
    EXPECT_FALSE(response.has_more());
    EXPECT_EQ(response.latest_sequence(), 3);
    EXPECT_EQ(response.next_sequence(), 4);
    EXPECT_EQ(response.messages(0).conversation_id(), conv_id_.to_string());
}

TEST_F(MessagingServiceImplSyncTest, SyncDeviceMessagesPagination) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_device_.str());

    v1::SyncDeviceMessagesRequest request;
    request.set_device_id(alice_device_.str());
    request.set_conversation_id(conv_id_.to_string());
    request.set_since_sequence(0);
    request.set_max_messages(2); // Only request 2 out of 3

    v1::SyncDeviceMessagesResponse response;
    auto status = stub_->SyncDeviceMessages(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "Error: " << status.error_message();
    EXPECT_EQ(response.messages_size(), 2);
    EXPECT_TRUE(response.has_more());
    EXPECT_EQ(response.next_sequence(), 3);
}

TEST_F(MessagingServiceImplSyncTest, SyncDeviceMessagesUnauthenticatedReturnsError) {
    grpc::ClientContext context; // Missing x-user-id

    v1::SyncDeviceMessagesRequest request;
    request.set_device_id(alice_device_.str());
    request.set_conversation_id(conv_id_.to_string());

    v1::SyncDeviceMessagesResponse response;
    auto status = stub_->SyncDeviceMessages(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

TEST_F(MessagingServiceImplSyncTest, SyncDeviceMessagesNonParticipantReturnsPermissionDenied) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", eve_user_.str()); // Eve is not in conversation
    context.AddMetadata("x-device-id", "device-eve-001");

    v1::SyncDeviceMessagesRequest request;
    request.set_device_id("device-eve-001");
    request.set_conversation_id(conv_id_.to_string());

    v1::SyncDeviceMessagesResponse response;
    auto status = stub_->SyncDeviceMessages(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(MessagingServiceImplSyncTest, SyncDeviceMessagesUnwiredReturnsUnimplemented) {
    // Unwired service implementation
    MessagingServiceImpl unwired_service;
    grpc::ServerContext context;
    v1::SyncDeviceMessagesRequest req;
    v1::SyncDeviceMessagesResponse resp;

    auto status = unwired_service.SyncDeviceMessages(&context, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
}

TEST_F(MessagingServiceImplSyncTest, SyncDeviceMessagesQueueCapacityExceeded) {
    // Configure worker pool and shut it down to induce immediate capacity rejection
    auto exhausted_pool = std::make_shared<concurrency::BoundedWorkerPool>(1, 1, "exhausted_pool");
    exhausted_pool->shutdown();

    MessagingServiceImpl rejecting_service(nullptr, nullptr, exhausted_pool, nullptr, nullptr, nullptr, nullptr,
                                           sync_service_, cursor_manager_);

    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_device_.str());

    grpc::ServerBuilder builder;
    builder.RegisterService(&rejecting_service);
    auto local_server = builder.BuildAndStart();
    auto local_channel = local_server->InProcessChannel(grpc::ChannelArguments{});
    auto local_stub = v1::MessagingService::NewStub(local_channel);

    v1::SyncDeviceMessagesRequest request;
    request.set_device_id(alice_device_.str());
    request.set_conversation_id(conv_id_.to_string());

    v1::SyncDeviceMessagesResponse response;
    auto status = local_stub->SyncDeviceMessages(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);

    local_server->Shutdown();
    local_server->Wait();
}

// ============================================================================
// GetMessages Tests
// ============================================================================

TEST_F(MessagingServiceImplSyncTest, GetMessagesSuccess) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_device_.str());

    v1::GetMessagesRequest request;
    request.set_conversation_id(conv_id_.to_string());
    request.set_recipient_device_id(alice_device_.str());
    request.set_since_sequence(0);
    request.set_max_results(5);

    v1::GetMessagesResponse response;
    auto status = stub_->GetMessages(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "Error: " << status.error_message();
    EXPECT_EQ(response.messages_size(), 3);
    EXPECT_FALSE(response.has_more());
    EXPECT_EQ(response.latest_sequence(), 3);
}

// ============================================================================
// GetSyncCursor Tests
// ============================================================================

TEST_F(MessagingServiceImplSyncTest, GetSyncCursorSuccess) {
    // Pre-seed cursor
    DeviceSyncCursor stored_cursor{
        .device_id = alice_device_,
        .conversation_id = conv_id_,
        .last_synced_sequence = 2,
        .last_sync_at = std::chrono::system_clock::now(),
        .sync_version = 1,
    };
    cursor_repo_->upsert_sync_cursor(stored_cursor);

    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_device_.str());

    v1::GetSyncCursorRequest request;
    request.set_device_id(alice_device_.str());
    request.set_conversation_id(conv_id_.to_string());

    v1::GetSyncCursorResponse response;
    auto status = stub_->GetSyncCursor(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "Error: " << status.error_message();
    EXPECT_EQ(response.cursor().device_id(), alice_device_.str());
    EXPECT_EQ(response.cursor().conversation_id(), conv_id_.to_string());
    EXPECT_EQ(response.cursor().last_delivered_sequence(), 2);
}

TEST_F(MessagingServiceImplSyncTest, GetSyncCursorUnwiredReturnsUnimplemented) {
    MessagingServiceImpl unwired_service;
    grpc::ServerContext context;
    v1::GetSyncCursorRequest req;
    v1::GetSyncCursorResponse resp;

    auto status = unwired_service.GetSyncCursor(&context, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
}

// ============================================================================
// UpdateSyncCursor Tests
// ============================================================================

TEST_F(MessagingServiceImplSyncTest, UpdateSyncCursorSuccess) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_device_.str());

    v1::UpdateSyncCursorRequest request;
    auto* cursor = request.mutable_cursor();
    cursor->set_device_id(alice_device_.str());
    cursor->set_conversation_id(conv_id_.to_string());
    cursor->set_last_delivered_sequence(2); // Sequence 2 <= ceiling 3

    v1::UpdateSyncCursorResponse response;
    auto status = stub_->UpdateSyncCursor(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "Error: " << status.error_message();
    EXPECT_TRUE(response.success());
    EXPECT_EQ(response.cursor().last_delivered_sequence(), 2);

    // Verify stored in repository
    auto persisted = cursor_repo_->get_sync_cursor(alice_device_, conv_id_);
    ASSERT_TRUE(persisted.has_value());
    EXPECT_EQ(persisted->last_synced_sequence, 2);
}

TEST_F(MessagingServiceImplSyncTest, UpdateSyncCursorRegressionRejected) {
    // Pre-seed cursor at 2
    DeviceSyncCursor stored_cursor{
        .device_id = alice_device_,
        .conversation_id = conv_id_,
        .last_synced_sequence = 2,
        .last_sync_at = std::chrono::system_clock::now(),
        .sync_version = 1,
    };
    cursor_repo_->upsert_sync_cursor(stored_cursor);

    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_device_.str());

    v1::UpdateSyncCursorRequest request;
    auto* cursor = request.mutable_cursor();
    cursor->set_device_id(alice_device_.str());
    cursor->set_conversation_id(conv_id_.to_string());
    cursor->set_last_delivered_sequence(1); // Regression 1 < 2

    v1::UpdateSyncCursorResponse response;
    auto status = stub_->UpdateSyncCursor(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::OUT_OF_RANGE);
}

TEST_F(MessagingServiceImplSyncTest, UpdateSyncCursorOutOfBoundsRejected) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_device_.str());

    v1::UpdateSyncCursorRequest request;
    auto* cursor = request.mutable_cursor();
    cursor->set_device_id(alice_device_.str());
    cursor->set_conversation_id(conv_id_.to_string());
    cursor->set_last_delivered_sequence(999); // Ceiling is 3

    v1::UpdateSyncCursorResponse response;
    auto status = stub_->UpdateSyncCursor(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::OUT_OF_RANGE);
}

TEST_F(MessagingServiceImplSyncTest, UpdateSyncCursorUnwiredReturnsUnimplemented) {
    MessagingServiceImpl unwired_service;
    grpc::ServerContext context;
    v1::UpdateSyncCursorRequest req;
    v1::UpdateSyncCursorResponse resp;

    auto status = unwired_service.UpdateSyncCursor(&context, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
}

} // namespace
} // namespace securecloud::messaging::service
