#include "grpc/messaging_client_interface.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/auth/request_context.hpp"
#include "http/proxy/messaging_proxy_handler.hpp"
#include "http/routing/router.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

namespace securecloud::gateway::http {
namespace {

using ::testing::_;
using ::testing::Return;

class MockMessagingClient final : public grpc::IMessagingClient {
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

AuthenticatedContext make_test_auth_context(const std::string& user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
                                            const std::string& device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099") {
    return AuthenticatedContext(user_id, device_id, "session-test-1",
                                securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                {"messaging:read", "messaging:write"}, 1750000000000LL);
}

class MessagingProxyAckTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_client_ = std::make_shared<MockMessagingClient>();
        deadline_manager_ = std::make_shared<DeadlineManager>();
        retry_policy_ = std::make_shared<RetryPolicy>();
        bulkhead_manager_ = std::make_shared<BulkheadManager>(GatewayBulkheadConfig{
            .auth_max_concurrent = 10,
            .messaging_max_concurrent = 10,
            .files_max_concurrent = 10,
            .emergency_reserved_slots = 0,
        });
        circuit_breaker_ = std::make_shared<CircuitBreaker>("messaging", GatewayCircuitBreakerConfig{
                                                                             .enabled = true,
                                                                             .failure_threshold = 2,
                                                                             .recovery_timeout_ms = 1000,
                                                                             .half_open_probe_count = 1,
                                                                         });

        handler_ = std::make_unique<MessagingProxyHandler>(mock_client_, deadline_manager_, retry_policy_,
                                                           bulkhead_manager_, circuit_breaker_);
        handler_->register_routes(router_);
    }

    std::shared_ptr<MockMessagingClient> mock_client_;
    std::shared_ptr<DeadlineManager> deadline_manager_;
    std::shared_ptr<RetryPolicy> retry_policy_;
    std::shared_ptr<BulkheadManager> bulkhead_manager_;
    std::shared_ptr<CircuitBreaker> circuit_breaker_;
    std::unique_ptr<MessagingProxyHandler> handler_;
    Router router_;
};

TEST_F(MessagingProxyAckTest, AcknowledgeDeliverySuccess) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/0191ec4d-91b4-7b4d-b6a9-8e41e3d36000/ack";
    req.path_params["id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000";
    req.body = R"({"delivered_at_unix_ms": 1760000000000})";

    securecloud::messaging::v1::AcknowledgeDeliveryResponse grpc_resp;
    grpc_resp.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    grpc_resp.set_state(securecloud::messaging::v1::DELIVERY_STATE_DELIVERED);
    grpc_resp.set_recorded_at_unix_ms(1760000000000);

    EXPECT_CALL(*mock_client_, acknowledge_delivery(_, _))
        .WillOnce([&](const securecloud::messaging::v1::AcknowledgeDeliveryRequest& request, grpc::ClientCallContext&) {
            EXPECT_EQ(request.message_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
            EXPECT_EQ(request.recipient_device_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
            EXPECT_EQ(request.delivered_at_unix_ms(), 1760000000000);
            return grpc::Result<securecloud::messaging::v1::AcknowledgeDeliveryResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_acknowledge_delivery(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["message_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    EXPECT_EQ(body["state"], "DELIVERED");
    EXPECT_EQ(body["recorded_at_unix_ms"], 1760000000000);
}

TEST_F(MessagingProxyAckTest, AcknowledgeDeliveryExplicitDeviceInBody) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/0191ec4d-91b4-7b4d-b6a9-8e41e3d36000/ack";
    req.path_params["id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000";
    req.body = R"({"recipient_device_id": "device-custom-999", "delivered_at_unix_ms": 1760000000000})";

    securecloud::messaging::v1::AcknowledgeDeliveryResponse grpc_resp;
    grpc_resp.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    grpc_resp.set_state(securecloud::messaging::v1::DELIVERY_STATE_DELIVERED);
    grpc_resp.set_recorded_at_unix_ms(1760000000000);

    EXPECT_CALL(*mock_client_, acknowledge_delivery(_, _))
        .WillOnce([&](const securecloud::messaging::v1::AcknowledgeDeliveryRequest& request, grpc::ClientCallContext&) {
            EXPECT_EQ(request.recipient_device_id(), "device-custom-999");
            return grpc::Result<securecloud::messaging::v1::AcknowledgeDeliveryResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_acknowledge_delivery(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 200);
}

TEST_F(MessagingProxyAckTest, AcknowledgeDeliveryMissingMessageIdReturns400) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages//ack";
    req.path_params.clear(); // Missing "id" parameter

    httplib::Response res;
    handler_->handle_acknowledge_delivery(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "INVALID_ARGUMENT");
}

TEST_F(MessagingProxyAckTest, AcknowledgeDeliveryInvalidJsonReturns400) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/0191ec4d-91b4-7b4d-b6a9-8e41e3d36000/ack";
    req.path_params["id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000";
    req.body = "{not-json}";

    httplib::Response res;
    handler_->handle_acknowledge_delivery(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "INVALID_ARGUMENT");
}

TEST_F(MessagingProxyAckTest, AcknowledgeDeliveryDownstreamNotFoundReturns404) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/0191ec4d-91b4-7b4d-b6a9-8e41e3d36000/ack";
    req.path_params["id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000";

    grpc::DependencyError not_found_err{
        .kind = grpc::DependencyErrorKind::NotFound,
        .message = "Delivery state record not found for message and device",
        .grpc_code = ::grpc::StatusCode::NOT_FOUND,
    };

    EXPECT_CALL(*mock_client_, acknowledge_delivery(_, _))
        .WillOnce(Return(grpc::Result<securecloud::messaging::v1::AcknowledgeDeliveryResponse>(not_found_err)));

    httplib::Response res;
    handler_->handle_acknowledge_delivery(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 404);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "NOT_FOUND");
}

TEST_F(MessagingProxyAckTest, AcknowledgeDeliveryDownstreamPermissionDeniedReturns403) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/0191ec4d-91b4-7b4d-b6a9-8e41e3d36000/ack";
    req.path_params["id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000";

    grpc::DependencyError perm_err{
        .kind = grpc::DependencyErrorKind::PermissionDenied,
        .message = "Caller is not authorized to acknowledge delivery",
        .grpc_code = ::grpc::StatusCode::PERMISSION_DENIED,
    };

    EXPECT_CALL(*mock_client_, acknowledge_delivery(_, _))
        .WillOnce(Return(grpc::Result<securecloud::messaging::v1::AcknowledgeDeliveryResponse>(perm_err)));

    httplib::Response res;
    handler_->handle_acknowledge_delivery(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "PERMISSION_DENIED");
}

TEST_F(MessagingProxyAckTest, AcknowledgeDeliveryBulkheadRejectionReturns503) {
    auto full_bulkhead = std::make_shared<BulkheadManager>(GatewayBulkheadConfig{
        .auth_max_concurrent = 0,
        .messaging_max_concurrent = 0,
        .files_max_concurrent = 0,
        .emergency_reserved_slots = 0,
    });

    MessagingProxyHandler rejecting_handler(mock_client_, deadline_manager_, retry_policy_, full_bulkhead,
                                            circuit_breaker_);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/0191ec4d-91b4-7b4d-b6a9-8e41e3d36000/ack";
    req.path_params["id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000";

    httplib::Response res;
    rejecting_handler.handle_acknowledge_delivery(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 503);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");
}

} // namespace
} // namespace securecloud::gateway::http
