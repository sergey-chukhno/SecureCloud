#include "grpc/messaging_client_interface.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/auth/request_context.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/proxy/messaging_proxy_handler.hpp"
#include "http/routing/gateway_route_registrar.hpp"
#include "http/routing/router.hpp"
#include "securecloud/health/health_status_manager.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

namespace securecloud::gateway::http {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

class MockMessagingClient : public grpc::IMessagingClient {
  public:
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::SendMessageResponse>, send_message,
                (const securecloud::messaging::v1::SendMessageRequest& req, grpc::ClientCallContext& ctx), (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::GetMessagesResponse>, get_messages,
                (const securecloud::messaging::v1::GetMessagesRequest& req, grpc::ClientCallContext& ctx), (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::AcknowledgeDeliveryResponse>, acknowledge_delivery,
                (const securecloud::messaging::v1::AcknowledgeDeliveryRequest& req, grpc::ClientCallContext& ctx),
                (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::SendReadReceiptResponse>, send_read_receipt,
                (const securecloud::messaging::v1::SendReadReceiptRequest& req, grpc::ClientCallContext& ctx),
                (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::GetMessageDeliveryStatusResponse>, get_message_delivery_status,
                (const securecloud::messaging::v1::GetMessageDeliveryStatusRequest& req, grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::CreateConversationResponse>, create_conversation,
                (const securecloud::messaging::v1::CreateConversationRequest& req, grpc::ClientCallContext& ctx),
                (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::GetConversationResponse>, get_conversation,
                (const securecloud::messaging::v1::GetConversationRequest& req, grpc::ClientCallContext& ctx),
                (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::ListConversationsResponse>, list_conversations,
                (const securecloud::messaging::v1::ListConversationsRequest& req, grpc::ClientCallContext& ctx),
                (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::AddParticipantResponse>, add_participant,
                (const securecloud::messaging::v1::AddParticipantRequest& req, grpc::ClientCallContext& ctx),
                (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::RemoveParticipantResponse>, remove_participant,
                (const securecloud::messaging::v1::RemoveParticipantRequest& req, grpc::ClientCallContext& ctx),
                (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::LeaveConversationResponse>, leave_conversation,
                (const securecloud::messaging::v1::LeaveConversationRequest& req, grpc::ClientCallContext& ctx),
                (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::UpdateConversationMetadataResponse>,
                update_conversation_metadata,
                (const securecloud::messaging::v1::UpdateConversationMetadataRequest& req,
                 grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::SyncDeviceMessagesResponse>, sync_device_messages,
                (const securecloud::messaging::v1::SyncDeviceMessagesRequest& req, grpc::ClientCallContext& ctx),
                (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::GetSyncCursorResponse>, get_sync_cursor,
                (const securecloud::messaging::v1::GetSyncCursorRequest& req, grpc::ClientCallContext& ctx),
                (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::UpdateSyncCursorResponse>, update_sync_cursor,
                (const securecloud::messaging::v1::UpdateSyncCursorRequest& req, grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::UpdatePresenceResponse>, update_presence,
                (const securecloud::messaging::v1::UpdatePresenceRequest& req, grpc::ClientCallContext& ctx),
                (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::GetPresenceResponse>, get_presence,
                (const securecloud::messaging::v1::GetPresenceRequest& req, grpc::ClientCallContext& ctx), (override));
    MOCK_METHOD(grpc::Result<securecloud::messaging::v1::BatchGetPresenceResponse>, batch_get_presence,
                (const securecloud::messaging::v1::BatchGetPresenceRequest& req, grpc::ClientCallContext& ctx),
                (override));
};

AuthenticatedContext make_test_context(const std::string& user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
                                       const std::string& device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099") {
    return AuthenticatedContext(user_id, device_id, "session-test-1",
                                securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                {"messaging:read", "messaging:write"}, 1750000000000LL);
}

class GatewayConversationRoutingTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_client_ = std::make_shared<MockMessagingClient>();
        bulkhead_manager_ = std::make_shared<BulkheadManager>(GatewayBulkheadConfig{
            .auth_max_concurrent = 10,
            .messaging_max_concurrent = 10,
            .files_max_concurrent = 5,
            .emergency_reserved_slots = 1,
        });
        deadline_manager_ = std::make_shared<DeadlineManager>(GatewayServiceDeadlinesConfig{
            .messaging_timeout_ms = 2000,
        });
        retry_policy_ = std::make_shared<RetryPolicy>();
        circuit_breaker_ = std::make_shared<CircuitBreaker>("messaging", GatewayCircuitBreakerConfig{
                                                                             .enabled = true,
                                                                             .failure_threshold = 2,
                                                                             .recovery_timeout_ms = 1000,
                                                                             .half_open_probe_count = 1,
                                                                         });

        handler_ = std::make_shared<MessagingProxyHandler>(mock_client_, deadline_manager_, retry_policy_,
                                                           bulkhead_manager_, circuit_breaker_);
        handler_->register_routes(router_);
    }

    std::shared_ptr<MockMessagingClient> mock_client_;
    std::shared_ptr<BulkheadManager> bulkhead_manager_;
    std::shared_ptr<DeadlineManager> deadline_manager_;
    std::shared_ptr<RetryPolicy> retry_policy_;
    std::shared_ptr<CircuitBreaker> circuit_breaker_;
    std::shared_ptr<MessagingProxyHandler> handler_;
    Router router_;
};

// ============================================================================
// 1. Create Conversation
// ============================================================================

TEST_F(GatewayConversationRoutingTest, CreateDirectConversationSuccess) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/conversations";
    req.body = R"({"type": "direct", "recipient_user_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002"})";
    req.set_header("Content-Type", "application/json");
    req.set_header("X-Request-ID", "req-create-123");
    req.set_header("X-Idempotency-Token", "token-idemp-456");

    securecloud::messaging::v1::CreateConversationResponse grpc_resp;
    auto* conv = grpc_resp.mutable_conversation();
    conv->set_conversation_id("conv-111");
    conv->set_type(securecloud::messaging::v1::CONVERSATION_TYPE_DIRECT);
    conv->set_creator_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    conv->add_participant_user_ids("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    conv->add_participant_user_ids("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");

    EXPECT_CALL(*mock_client_, create_conversation(_, _)).WillOnce([&](const auto& r, auto&) {
        EXPECT_EQ(r.type(), securecloud::messaging::v1::CONVERSATION_TYPE_DIRECT);
        EXPECT_EQ(r.participant_user_ids_size(), 1);
        EXPECT_EQ(r.participant_user_ids(0), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
        return grpc_resp;
    });

    httplib::Response res;
    auto ctx = make_test_context();
    handler_->handle_create_conversation(req, res, ctx);

    EXPECT_EQ(res.status, 201);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["conversation"]["conversation_id"], "conv-111");
    EXPECT_EQ(body["conversation"]["type"], "direct");
}

TEST_F(GatewayConversationRoutingTest, CreateGroupConversationSuccess) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/conversations";
    req.body =
        R"({"type": "group", "title": "Platform Core", "participant_user_ids": ["0191ec4d-91b4-7b4d-b6a9-8e41e3d36002"]})";
    req.set_header("Content-Type", "application/json");

    securecloud::messaging::v1::CreateConversationResponse grpc_resp;
    auto* conv = grpc_resp.mutable_conversation();
    conv->set_conversation_id("conv-group-222");
    conv->set_type(securecloud::messaging::v1::CONVERSATION_TYPE_GROUP);
    conv->set_title("Platform Core");

    EXPECT_CALL(*mock_client_, create_conversation(_, _)).WillOnce([&](const auto& r, auto&) {
        EXPECT_EQ(r.type(), securecloud::messaging::v1::CONVERSATION_TYPE_GROUP);
        EXPECT_EQ(r.title(), "Platform Core");
        return grpc_resp;
    });

    httplib::Response res;
    handler_->handle_create_conversation(req, res, make_test_context());

    EXPECT_EQ(res.status, 201);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["conversation"]["conversation_id"], "conv-group-222");
    EXPECT_EQ(body["conversation"]["title"], "Platform Core");
}

// ============================================================================
// 2. Get Conversation
// ============================================================================

TEST_F(GatewayConversationRoutingTest, GetConversationSuccess) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/conversations/conv-111";
    req.path_params["id"] = "conv-111";

    securecloud::messaging::v1::GetConversationResponse grpc_resp;
    auto* conv = grpc_resp.mutable_conversation();
    conv->set_conversation_id("conv-111");
    conv->set_type(securecloud::messaging::v1::CONVERSATION_TYPE_DIRECT);

    EXPECT_CALL(*mock_client_, get_conversation(_, _)).WillOnce([&](const auto& r, auto&) {
        EXPECT_EQ(r.conversation_id(), "conv-111");
        return grpc_resp;
    });

    httplib::Response res;
    handler_->handle_get_conversation(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["conversation"]["conversation_id"], "conv-111");
}

TEST_F(GatewayConversationRoutingTest, GetConversationNotFound) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/conversations/conv-404";
    req.path_params["id"] = "conv-404";

    EXPECT_CALL(*mock_client_, get_conversation(_, _))
        .WillOnce(Return(grpc::DependencyError{
            .kind = grpc::DependencyErrorKind::NotFound,
            .message = "Conversation not found",
            .grpc_code = ::grpc::StatusCode::NOT_FOUND,
        }));

    httplib::Response res;
    handler_->handle_get_conversation(req, res, make_test_context());

    EXPECT_EQ(res.status, 404);
}

// ============================================================================
// 3. List Conversations
// ============================================================================

TEST_F(GatewayConversationRoutingTest, ListConversationsSuccess) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/conversations";
    req.params.emplace("limit", "10");

    securecloud::messaging::v1::ListConversationsResponse grpc_resp;
    auto* item = grpc_resp.add_conversations();
    item->set_conversation_id("conv-111");
    item->set_type(securecloud::messaging::v1::CONVERSATION_TYPE_DIRECT);

    EXPECT_CALL(*mock_client_, list_conversations(_, _)).WillOnce(Return(grpc_resp));

    httplib::Response res;
    handler_->handle_list_conversations(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["conversations"].size(), 1);
    EXPECT_EQ(body["conversations"][0]["conversation_id"], "conv-111");
}

// ============================================================================
// 4. Participant Management
// ============================================================================

TEST_F(GatewayConversationRoutingTest, AddParticipantSuccess) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/conversations/conv-group/participants";
    req.path_params["id"] = "conv-group";
    req.body = R"({"participant_user_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003"})";

    securecloud::messaging::v1::AddParticipantResponse grpc_resp;
    grpc_resp.set_conversation_id("conv-group");
    grpc_resp.set_participant_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    grpc_resp.set_total_participants(3);

    EXPECT_CALL(*mock_client_, add_participant(_, _)).WillOnce(Return(grpc_resp));

    httplib::Response res;
    handler_->handle_add_participant(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["total_participants"], 3);
}

TEST_F(GatewayConversationRoutingTest, RemoveParticipantSuccess) {
    httplib::Request req;
    req.method = "DELETE";
    req.path = "/api/v1/conversations/conv-group/participants/user-charlie";
    req.path_params["id"] = "conv-group";
    req.path_params["userId"] = "user-charlie";

    securecloud::messaging::v1::RemoveParticipantResponse grpc_resp;
    grpc_resp.set_conversation_id("conv-group");
    grpc_resp.set_participant_user_id("user-charlie");
    grpc_resp.set_total_participants(2);

    EXPECT_CALL(*mock_client_, remove_participant(_, _)).WillOnce(Return(grpc_resp));

    httplib::Response res;
    handler_->handle_remove_participant(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["total_participants"], 2);
}

TEST_F(GatewayConversationRoutingTest, LeaveConversationSuccess) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/conversations/conv-group/leave";
    req.path_params["id"] = "conv-group";

    securecloud::messaging::v1::LeaveConversationResponse grpc_resp;
    grpc_resp.set_conversation_id("conv-group");
    grpc_resp.set_success(true);

    EXPECT_CALL(*mock_client_, leave_conversation(_, _)).WillOnce(Return(grpc_resp));

    httplib::Response res;
    handler_->handle_leave_conversation(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_TRUE(body["success"]);
}

TEST_F(GatewayConversationRoutingTest, UpdateMetadataSuccess) {
    httplib::Request req;
    req.method = "PATCH";
    req.path = "/api/v1/conversations/conv-group/metadata";
    req.path_params["id"] = "conv-group";
    req.body = R"({"title": "Renamed Team"})";

    securecloud::messaging::v1::UpdateConversationMetadataResponse grpc_resp;
    auto* conv = grpc_resp.mutable_conversation();
    conv->set_conversation_id("conv-group");
    conv->set_title("Renamed Team");

    EXPECT_CALL(*mock_client_, update_conversation_metadata(_, _)).WillOnce(Return(grpc_resp));

    httplib::Response res;
    handler_->handle_update_metadata(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["conversation"]["title"], "Renamed Team");
}

} // namespace
} // namespace securecloud::gateway::http
