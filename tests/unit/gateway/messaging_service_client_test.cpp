#include "grpc/client_call_context.hpp"
#include "grpc/messaging_service_client.hpp"

#include <chrono>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>

namespace securecloud::gateway::grpc {
namespace {

constexpr int64_t k_test_timestamp_ms = 1750000000000LL;
constexpr int64_t k_test_sequence = 42;
constexpr uint32_t k_test_target_count = 3;
constexpr uint32_t k_test_max_results = 10;
constexpr uint32_t k_test_list_limit = 20;
constexpr uint32_t k_test_sync_limit = 50;
constexpr std::chrono::milliseconds k_test_timeout_ms{2000};

class FakeMessagingService final : public securecloud::messaging::v1::MessagingService::Service {
  public:
    ::grpc::StatusCode return_code{::grpc::StatusCode::OK};
    std::string return_message{"Success"};

    ::grpc::Status SendMessage(::grpc::ServerContext* /*context*/,
                               const securecloud::messaging::v1::SendMessageRequest* request,
                               securecloud::messaging::v1::SendMessageResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        response->set_message_id("msg-0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
        response->set_conversation_id(request->conversation_id());
        response->set_accepted_at_unix_ms(k_test_timestamp_ms);
        response->set_initial_state(securecloud::messaging::v1::DeliveryState::DELIVERY_STATE_QUEUED);
        response->set_target_count(k_test_target_count);
        return ::grpc::Status::OK;
    }

    ::grpc::Status GetMessages(::grpc::ServerContext* /*context*/,
                               const securecloud::messaging::v1::GetMessagesRequest* request,
                               securecloud::messaging::v1::GetMessagesResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        auto* msg = response->add_messages();
        msg->set_message_id("msg-0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        msg->set_conversation_id(request->conversation_id());
        response->set_has_more(false);
        response->set_latest_sequence(k_test_sequence);
        return ::grpc::Status::OK;
    }

    ::grpc::Status AcknowledgeDelivery(::grpc::ServerContext* /*context*/,
                                       const securecloud::messaging::v1::AcknowledgeDeliveryRequest* request,
                                       securecloud::messaging::v1::AcknowledgeDeliveryResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        response->set_message_id(request->message_id());
        response->set_state(securecloud::messaging::v1::DeliveryState::DELIVERY_STATE_DELIVERED);
        response->set_recorded_at_unix_ms(k_test_timestamp_ms);
        return ::grpc::Status::OK;
    }

    ::grpc::Status SendReadReceipt(::grpc::ServerContext* /*context*/,
                                   const securecloud::messaging::v1::SendReadReceiptRequest* request,
                                   securecloud::messaging::v1::SendReadReceiptResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        response->set_message_id(request->message_id());
        response->set_state(securecloud::messaging::v1::DeliveryState::DELIVERY_STATE_READ);
        response->set_recorded_at_unix_ms(k_test_timestamp_ms);
        return ::grpc::Status::OK;
    }

    ::grpc::Status CreateConversation(::grpc::ServerContext* /*context*/,
                                      const securecloud::messaging::v1::CreateConversationRequest* request,
                                      securecloud::messaging::v1::CreateConversationResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        auto* conv = response->mutable_conversation();
        conv->set_conversation_id("conv-0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
        conv->set_type(request->type());
        conv->set_title(request->title());
        return ::grpc::Status::OK;
    }

    ::grpc::Status GetConversation(::grpc::ServerContext* /*context*/,
                                   const securecloud::messaging::v1::GetConversationRequest* request,
                                   securecloud::messaging::v1::GetConversationResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        auto* conv = response->mutable_conversation();
        conv->set_conversation_id(request->conversation_id());
        conv->set_title("Test Conversation");
        return ::grpc::Status::OK;
    }

    ::grpc::Status ListConversations(::grpc::ServerContext* /*context*/,
                                     const securecloud::messaging::v1::ListConversationsRequest* /*request*/,
                                     securecloud::messaging::v1::ListConversationsResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        auto* item = response->add_conversations();
        item->set_conversation_id("conv-0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
        item->set_title("Listed Conversation");
        return ::grpc::Status::OK;
    }

    ::grpc::Status AddParticipant(::grpc::ServerContext* /*context*/,
                                  const securecloud::messaging::v1::AddParticipantRequest* request,
                                  securecloud::messaging::v1::AddParticipantResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        response->set_conversation_id(request->conversation_id());
        response->set_participant_user_id(request->participant_user_id());
        response->set_total_participants(k_test_target_count);
        return ::grpc::Status::OK;
    }

    ::grpc::Status RemoveParticipant(::grpc::ServerContext* /*context*/,
                                     const securecloud::messaging::v1::RemoveParticipantRequest* request,
                                     securecloud::messaging::v1::RemoveParticipantResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        response->set_conversation_id(request->conversation_id());
        response->set_participant_user_id(request->participant_user_id());
        response->set_total_participants(k_test_target_count - 1);
        return ::grpc::Status::OK;
    }

    ::grpc::Status LeaveConversation(::grpc::ServerContext* /*context*/,
                                     const securecloud::messaging::v1::LeaveConversationRequest* request,
                                     securecloud::messaging::v1::LeaveConversationResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        response->set_conversation_id(request->conversation_id());
        response->set_success(true);
        return ::grpc::Status::OK;
    }

    ::grpc::Status
    UpdateConversationMetadata(::grpc::ServerContext* /*context*/,
                               const securecloud::messaging::v1::UpdateConversationMetadataRequest* request,
                               securecloud::messaging::v1::UpdateConversationMetadataResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        auto* conv = response->mutable_conversation();
        conv->set_conversation_id(request->conversation_id());
        conv->set_title(request->title());
        return ::grpc::Status::OK;
    }

    ::grpc::Status SyncDeviceMessages(::grpc::ServerContext* /*context*/,
                                      const securecloud::messaging::v1::SyncDeviceMessagesRequest* request,
                                      securecloud::messaging::v1::SyncDeviceMessagesResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        response->set_device_id(request->device_id());
        response->set_has_more(false);
        response->set_next_sequence(k_test_sequence);
        return ::grpc::Status::OK;
    }

    ::grpc::Status GetSyncCursor(::grpc::ServerContext* /*context*/,
                                 const securecloud::messaging::v1::GetSyncCursorRequest* request,
                                 securecloud::messaging::v1::GetSyncCursorResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        auto* cursor = response->mutable_cursor();
        cursor->set_device_id(request->device_id());
        cursor->set_last_delivered_sequence(k_test_sequence);
        return ::grpc::Status::OK;
    }

    ::grpc::Status UpdateSyncCursor(::grpc::ServerContext* /*context*/,
                                    const securecloud::messaging::v1::UpdateSyncCursorRequest* request,
                                    securecloud::messaging::v1::UpdateSyncCursorResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        *response->mutable_cursor() = request->cursor();
        response->set_success(true);
        return ::grpc::Status::OK;
    }

    ::grpc::Status UpdatePresence(::grpc::ServerContext* /*context*/,
                                  const securecloud::messaging::v1::UpdatePresenceRequest* request,
                                  securecloud::messaging::v1::UpdatePresenceResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        auto* pres = response->mutable_presence();
        pres->set_user_id("user-0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
        pres->set_status(request->status());
        pres->set_custom_status_message(request->custom_status_message());
        pres->set_last_active_unix_ms(k_test_timestamp_ms);
        return ::grpc::Status::OK;
    }

    ::grpc::Status GetPresence(::grpc::ServerContext* /*context*/,
                               const securecloud::messaging::v1::GetPresenceRequest* request,
                               securecloud::messaging::v1::GetPresenceResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        auto* pres = response->mutable_presence();
        pres->set_user_id(request->user_id());
        pres->set_status(securecloud::messaging::v1::PresenceStatus::PRESENCE_STATUS_ONLINE);
        pres->set_last_active_unix_ms(k_test_timestamp_ms);
        return ::grpc::Status::OK;
    }

    ::grpc::Status BatchGetPresence(::grpc::ServerContext* /*context*/,
                                    const securecloud::messaging::v1::BatchGetPresenceRequest* request,
                                    securecloud::messaging::v1::BatchGetPresenceResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return {return_code, return_message};
        }
        for (const auto& uid : request->user_ids()) {
            auto* pres = response->add_presences();
            pres->set_user_id(uid);
            pres->set_status(securecloud::messaging::v1::PresenceStatus::PRESENCE_STATUS_ONLINE);
        }
        return ::grpc::Status::OK;
    }
};

class MessagingServiceClientTest : public ::testing::Test {
  protected:
    void SetUp() override {
        fake_service_ = std::make_unique<FakeMessagingService>();

        ::grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", ::grpc::InsecureServerCredentials(), &bound_port_);
        builder.RegisterService(fake_service_.get());
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);
        ASSERT_GT(bound_port_, 0);

        server_address_ = "127.0.0.1:" + std::to_string(bound_port_);
        channel_ = ::grpc::CreateChannel(server_address_, ::grpc::InsecureChannelCredentials());
        client_ = std::make_unique<MessagingServiceClient>(channel_);
    }

    void TearDown() override {
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    std::unique_ptr<FakeMessagingService> fake_service_;
    std::unique_ptr<::grpc::Server> server_;
    int bound_port_{0};
    std::string server_address_;
    std::shared_ptr<::grpc::Channel> channel_;
    std::unique_ptr<MessagingServiceClient> client_;
};

// ============================================================================
// Message Submission & Delivery Tests
// ============================================================================

TEST_F(MessagingServiceClientTest, SendMessageSuccess) {
    securecloud::messaging::v1::SendMessageRequest req;
    req.set_conversation_id("conv-1");
    req.set_sender_device_id("dev-1");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->send_message(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().message_id(), "msg-0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    EXPECT_EQ(result.value().conversation_id(), "conv-1");
    EXPECT_EQ(result.value().accepted_at_unix_ms(), k_test_timestamp_ms);
    EXPECT_EQ(result.value().target_count(), k_test_target_count);
}

TEST_F(MessagingServiceClientTest, GetMessagesSuccess) {
    securecloud::messaging::v1::GetMessagesRequest req;
    req.set_conversation_id("conv-1");
    req.set_max_results(k_test_max_results);

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->get_messages(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().messages_size(), 1);
    EXPECT_EQ(result.value().messages(0).conversation_id(), "conv-1");
    EXPECT_EQ(result.value().latest_sequence(), k_test_sequence);
}

TEST_F(MessagingServiceClientTest, AcknowledgeDeliverySuccess) {
    securecloud::messaging::v1::AcknowledgeDeliveryRequest req;
    req.set_message_id("msg-1");
    req.set_recipient_device_id("dev-1");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->acknowledge_delivery(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().message_id(), "msg-1");
    EXPECT_EQ(result.value().state(), securecloud::messaging::v1::DeliveryState::DELIVERY_STATE_DELIVERED);
}

TEST_F(MessagingServiceClientTest, SendReadReceiptSuccess) {
    securecloud::messaging::v1::SendReadReceiptRequest req;
    req.set_message_id("msg-1");
    req.set_conversation_id("conv-1");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->send_read_receipt(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().message_id(), "msg-1");
    EXPECT_EQ(result.value().state(), securecloud::messaging::v1::DeliveryState::DELIVERY_STATE_READ);
}

// ============================================================================
// Conversation Topology & Membership Tests
// ============================================================================

TEST_F(MessagingServiceClientTest, CreateConversationSuccess) {
    securecloud::messaging::v1::CreateConversationRequest req;
    req.set_type(securecloud::messaging::v1::ConversationType::CONVERSATION_TYPE_DIRECT);
    req.set_title("Direct Chat");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->create_conversation(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().conversation().title(), "Direct Chat");
}

TEST_F(MessagingServiceClientTest, GetConversationSuccess) {
    securecloud::messaging::v1::GetConversationRequest req;
    req.set_conversation_id("conv-1");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->get_conversation(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().conversation().conversation_id(), "conv-1");
}

TEST_F(MessagingServiceClientTest, ListConversationsSuccess) {
    securecloud::messaging::v1::ListConversationsRequest req;
    req.set_user_id("user-1");
    req.set_max_results(k_test_list_limit);

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->list_conversations(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().conversations_size(), 1);
}

TEST_F(MessagingServiceClientTest, AddParticipantSuccess) {
    securecloud::messaging::v1::AddParticipantRequest req;
    req.set_conversation_id("conv-1");
    req.set_participant_user_id("user-2");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->add_participant(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().total_participants(), k_test_target_count);
}

TEST_F(MessagingServiceClientTest, RemoveParticipantSuccess) {
    securecloud::messaging::v1::RemoveParticipantRequest req;
    req.set_conversation_id("conv-1");
    req.set_participant_user_id("user-2");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->remove_participant(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().total_participants(), k_test_target_count - 1);
}

TEST_F(MessagingServiceClientTest, LeaveConversationSuccess) {
    securecloud::messaging::v1::LeaveConversationRequest req;
    req.set_conversation_id("conv-1");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->leave_conversation(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value().success());
}

TEST_F(MessagingServiceClientTest, UpdateConversationMetadataSuccess) {
    securecloud::messaging::v1::UpdateConversationMetadataRequest req;
    req.set_conversation_id("conv-1");
    req.set_title("New Title");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->update_conversation_metadata(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().conversation().title(), "New Title");
}

// ============================================================================
// Device Stream Synchronization Tests
// ============================================================================

TEST_F(MessagingServiceClientTest, SyncDeviceMessagesSuccess) {
    securecloud::messaging::v1::SyncDeviceMessagesRequest req;
    req.set_device_id("dev-1");
    req.set_since_sequence(0);
    req.set_max_messages(k_test_sync_limit);

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->sync_device_messages(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().device_id(), "dev-1");
    EXPECT_EQ(result.value().next_sequence(), k_test_sequence);
}

TEST_F(MessagingServiceClientTest, GetSyncCursorSuccess) {
    securecloud::messaging::v1::GetSyncCursorRequest req;
    req.set_device_id("dev-1");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->get_sync_cursor(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().cursor().device_id(), "dev-1");
}

TEST_F(MessagingServiceClientTest, UpdateSyncCursorSuccess) {
    securecloud::messaging::v1::UpdateSyncCursorRequest req;
    req.mutable_cursor()->set_device_id("dev-1");
    req.mutable_cursor()->set_last_delivered_sequence(k_test_sequence);

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->update_sync_cursor(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value().success());
    EXPECT_EQ(result.value().cursor().device_id(), "dev-1");
}

// ============================================================================
// Presence Protocol Tests
// ============================================================================

TEST_F(MessagingServiceClientTest, UpdatePresenceSuccess) {
    securecloud::messaging::v1::UpdatePresenceRequest req;
    req.set_status(securecloud::messaging::v1::PresenceStatus::PRESENCE_STATUS_AWAY);
    req.set_custom_status_message("In a meeting");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->update_presence(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().presence().status(), securecloud::messaging::v1::PresenceStatus::PRESENCE_STATUS_AWAY);
    EXPECT_EQ(result.value().presence().custom_status_message(), "In a meeting");
}

TEST_F(MessagingServiceClientTest, GetPresenceSuccess) {
    securecloud::messaging::v1::GetPresenceRequest req;
    req.set_user_id("user-1");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->get_presence(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().presence().user_id(), "user-1");
    EXPECT_EQ(result.value().presence().status(), securecloud::messaging::v1::PresenceStatus::PRESENCE_STATUS_ONLINE);
}

TEST_F(MessagingServiceClientTest, BatchGetPresenceSuccess) {
    securecloud::messaging::v1::BatchGetPresenceRequest req;
    req.add_user_ids("user-1");
    req.add_user_ids("user-2");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->batch_get_presence(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().presences_size(), 2);
}

// ============================================================================
// Error Handling & Null Stub Tests
// ============================================================================

TEST_F(MessagingServiceClientTest, MapsNotFoundStatusToDependencyError) {
    fake_service_->return_code = ::grpc::StatusCode::NOT_FOUND;
    fake_service_->return_message = "Conversation not found";

    securecloud::messaging::v1::GetConversationRequest req;
    req.set_conversation_id("conv-unknown");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->get_conversation(req, ctx);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, DependencyErrorKind::NotFound);
    EXPECT_EQ(result.error().grpc_code, ::grpc::StatusCode::NOT_FOUND);
    EXPECT_EQ(result.error().message, "Conversation not found");
}

TEST_F(MessagingServiceClientTest, MapsPermissionDeniedToDependencyError) {
    fake_service_->return_code = ::grpc::StatusCode::PERMISSION_DENIED;
    fake_service_->return_message = "Not a participant";

    securecloud::messaging::v1::SendMessageRequest req;
    req.set_conversation_id("conv-secret");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->send_message(req, ctx);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, DependencyErrorKind::PermissionDenied);
    EXPECT_EQ(result.error().grpc_code, ::grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(MessagingServiceClientTest, MapsDeadlineExceededToTimeout) {
    fake_service_->return_code = ::grpc::StatusCode::DEADLINE_EXCEEDED;
    fake_service_->return_message = "Deadline expired";

    securecloud::messaging::v1::SyncDeviceMessagesRequest req;
    req.set_device_id("dev-1");

    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client_->sync_device_messages(req, ctx);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, DependencyErrorKind::Timeout);
    EXPECT_EQ(result.error().grpc_code, ::grpc::StatusCode::DEADLINE_EXCEEDED);
}

TEST_F(MessagingServiceClientTest, NullStubReturnsServiceUnavailable) {
    std::shared_ptr<securecloud::messaging::v1::MessagingService::StubInterface> null_stub;
    MessagingServiceClient client(null_stub);

    securecloud::messaging::v1::SendMessageRequest req;
    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client.send_message(req, ctx);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, DependencyErrorKind::ServiceUnavailable);
    EXPECT_EQ(result.error().grpc_code, ::grpc::StatusCode::UNAVAILABLE);
}

TEST_F(MessagingServiceClientTest, NullChannelReturnsServiceUnavailable) {
    std::shared_ptr<::grpc::Channel> null_channel;
    MessagingServiceClient client(null_channel);

    securecloud::messaging::v1::GetPresenceRequest req;
    ClientCallContext ctx(k_test_timeout_ms);
    auto result = client.get_presence(req, ctx);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, DependencyErrorKind::ServiceUnavailable);
    EXPECT_EQ(result.error().grpc_code, ::grpc::StatusCode::UNAVAILABLE);
}

} // namespace
} // namespace securecloud::gateway::grpc
