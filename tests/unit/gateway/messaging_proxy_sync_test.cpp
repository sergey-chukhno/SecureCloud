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

class MessagingProxySyncTest : public ::testing::Test {
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

// ============================================================================
// SyncDeviceMessages Route Tests
// ============================================================================

TEST_F(MessagingProxySyncTest, SyncMessagesSuccess) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/conversations/0191ec4d-91b4-7b4d-b6a9-8e41e3d36000/messages";
    req.path_params["id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000";
    req.params.emplace("since_sequence", "10");
    req.params.emplace("limit", "25");

    securecloud::messaging::v1::SyncDeviceMessagesResponse grpc_resp;
    grpc_resp.set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    grpc_resp.set_has_more(true);
    grpc_resp.set_next_sequence(36);
    grpc_resp.set_latest_sequence(50);

    auto* msg = grpc_resp.add_messages();
    msg->set_message_id("msg-001");
    msg->set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    msg->set_sender_user_id("user-sender-1");
    msg->set_sender_device_id("device-sender-1");
    msg->set_priority(securecloud::messaging::v1::MESSAGE_PRIORITY_URGENT);
    msg->set_created_at_unix_ms(1760000001000);

    auto* target = msg->add_delivery_targets();
    target->set_recipient_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    target->set_recipient_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    target->set_state(securecloud::messaging::v1::DELIVERY_STATE_DELIVERED);
    auto* ep = target->mutable_encrypted_payload();
    ep->set_ciphertext_blob("encrypted-bytes-opaque");
    ep->set_algorithm("XChaCha20-Poly1305");

    auto* cursor = grpc_resp.mutable_cursor();
    cursor->set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    cursor->set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    cursor->set_last_delivered_sequence(35);
    cursor->set_last_sync_timestamp_unix_ms(1760000002000);

    EXPECT_CALL(*mock_client_, sync_device_messages(_, _))
        .WillOnce([&](const securecloud::messaging::v1::SyncDeviceMessagesRequest& request,
                      grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(request.conversation_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
            EXPECT_EQ(request.device_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
            EXPECT_EQ(request.since_sequence(), 10);
            EXPECT_EQ(request.max_messages(), 25);
            return grpc::Result<securecloud::messaging::v1::SyncDeviceMessagesResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_sync_messages(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["device_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    EXPECT_EQ(body["conversation_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    EXPECT_TRUE(body["has_more"]);
    EXPECT_EQ(body["next_sequence"], 36);
    EXPECT_EQ(body["latest_sequence"], 50);
    ASSERT_EQ(body["messages"].size(), 1);
    EXPECT_EQ(body["messages"][0]["message_id"], "msg-001");
    EXPECT_EQ(body["messages"][0]["priority"], "urgent");
    EXPECT_EQ(body["messages"][0]["delivery_targets"][0]["encrypted_payload"]["ciphertext_blob"],
              "encrypted-bytes-opaque");
    EXPECT_EQ(body["cursor"]["last_delivered_sequence"], 35);
}

TEST_F(MessagingProxySyncTest, SyncMessagesLimitClamping) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/conversations/conv-123/messages";
    req.path_params["id"] = "conv-123";
    req.params.emplace("limit", "500"); // Above 100 max ceiling

    EXPECT_CALL(*mock_client_, sync_device_messages(_, _))
        .WillOnce([&](const securecloud::messaging::v1::SyncDeviceMessagesRequest& request, grpc::ClientCallContext&) {
            EXPECT_EQ(request.max_messages(), 100); // Clamped to 100
            securecloud::messaging::v1::SyncDeviceMessagesResponse resp;
            resp.set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
            return grpc::Result<securecloud::messaging::v1::SyncDeviceMessagesResponse>(resp);
        });

    httplib::Response res;
    handler_->handle_sync_messages(req, res, make_test_auth_context());
    EXPECT_EQ(res.status, 200);
}

TEST_F(MessagingProxySyncTest, SyncMessagesZeroLimitClampedToOne) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/conversations/conv-123/messages";
    req.path_params["id"] = "conv-123";
    req.params.emplace("limit", "0"); // Below 1 floor

    EXPECT_CALL(*mock_client_, sync_device_messages(_, _))
        .WillOnce([&](const securecloud::messaging::v1::SyncDeviceMessagesRequest& request, grpc::ClientCallContext&) {
            EXPECT_EQ(request.max_messages(), 1); // Clamped to 1
            securecloud::messaging::v1::SyncDeviceMessagesResponse resp;
            resp.set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
            return grpc::Result<securecloud::messaging::v1::SyncDeviceMessagesResponse>(resp);
        });

    httplib::Response res;
    handler_->handle_sync_messages(req, res, make_test_auth_context());
    EXPECT_EQ(res.status, 200);
}

TEST_F(MessagingProxySyncTest, SyncMessagesMissingConversationIdReturns400) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/conversations//messages";
    req.path_params.clear();

    httplib::Response res;
    handler_->handle_sync_messages(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "INVALID_ARGUMENT");
}

TEST_F(MessagingProxySyncTest, SyncMessagesNegativeSequenceReturns400) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/conversations/conv-123/messages";
    req.path_params["id"] = "conv-123";
    req.params.emplace("since_sequence", "-10");

    httplib::Response res;
    handler_->handle_sync_messages(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "INVALID_ARGUMENT");
}

TEST_F(MessagingProxySyncTest, SyncMessagesDownstreamErrorsMapped) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/conversations/conv-123/messages";
    req.path_params["id"] = "conv-123";

    EXPECT_CALL(*mock_client_, sync_device_messages(_, _))
        .WillOnce(Return(grpc::DependencyError{grpc::DependencyErrorKind::NotFound, "Conversation not found",
                                               ::grpc::StatusCode::NOT_FOUND}));

    httplib::Response res;
    handler_->handle_sync_messages(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 404);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "NOT_FOUND");
}

// ============================================================================
// GetSyncCursor Route Tests
// ============================================================================

TEST_F(MessagingProxySyncTest, GetSyncCursorSuccess) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices/0191ec4d-91b4-7b4d-b6a9-8e41e3d36099/cursor";
    req.path_params["deviceId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";
    req.params.emplace("conversation_id", "conv-999");

    securecloud::messaging::v1::GetSyncCursorResponse grpc_resp;
    auto* cursor = grpc_resp.mutable_cursor();
    cursor->set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    cursor->set_conversation_id("conv-999");
    cursor->set_last_delivered_sequence(42);
    cursor->set_last_sync_timestamp_unix_ms(1760000005000);

    EXPECT_CALL(*mock_client_, get_sync_cursor(_, _))
        .WillOnce([&](const securecloud::messaging::v1::GetSyncCursorRequest& request, grpc::ClientCallContext&) {
            EXPECT_EQ(request.device_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
            EXPECT_EQ(request.conversation_id(), "conv-999");
            return grpc::Result<securecloud::messaging::v1::GetSyncCursorResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_get_sync_cursor(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["device_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    EXPECT_EQ(body["conversation_id"], "conv-999");
    EXPECT_EQ(body["last_delivered_sequence"], 42);
    EXPECT_EQ(body["last_sync_timestamp_unix_ms"], 1760000005000);
}

TEST_F(MessagingProxySyncTest, GetSyncCursorMismatchedDeviceIdReturns403) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices/other-device-id/cursor";
    req.path_params["deviceId"] = "other-device-id";

    httplib::Response res;
    handler_->handle_get_sync_cursor(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "PERMISSION_DENIED");
}

TEST_F(MessagingProxySyncTest, GetSyncCursorMissingDeviceIdReturns400) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices//cursor";
    req.path_params.clear();

    httplib::Response res;
    handler_->handle_get_sync_cursor(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "INVALID_ARGUMENT");
}

// ============================================================================
// UpdateSyncCursor Route Tests
// ============================================================================

TEST_F(MessagingProxySyncTest, UpdateSyncCursorSuccess) {
    httplib::Request req;
    req.method = "PUT";
    req.path = "/api/v1/devices/0191ec4d-91b4-7b4d-b6a9-8e41e3d36099/cursor";
    req.path_params["deviceId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";
    req.body = R"({
        "conversation_id": "conv-999",
        "last_delivered_sequence": 50,
        "last_sync_timestamp_unix_ms": 1760000009000
    })";

    securecloud::messaging::v1::UpdateSyncCursorResponse grpc_resp;
    grpc_resp.set_success(true);
    auto* cursor = grpc_resp.mutable_cursor();
    cursor->set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    cursor->set_conversation_id("conv-999");
    cursor->set_last_delivered_sequence(50);
    cursor->set_last_sync_timestamp_unix_ms(1760000009000);

    EXPECT_CALL(*mock_client_, update_sync_cursor(_, _))
        .WillOnce([&](const securecloud::messaging::v1::UpdateSyncCursorRequest& request, grpc::ClientCallContext&) {
            EXPECT_EQ(request.cursor().device_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
            EXPECT_EQ(request.cursor().conversation_id(), "conv-999");
            EXPECT_EQ(request.cursor().last_delivered_sequence(), 50);
            EXPECT_EQ(request.cursor().last_sync_timestamp_unix_ms(), 1760000009000);
            return grpc::Result<securecloud::messaging::v1::UpdateSyncCursorResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_update_sync_cursor(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_TRUE(body["success"]);
    EXPECT_EQ(body["cursor"]["last_delivered_sequence"], 50);
}

TEST_F(MessagingProxySyncTest, UpdateSyncCursorMismatchedDeviceIdReturns403) {
    httplib::Request req;
    req.method = "PUT";
    req.path = "/api/v1/devices/other-device-id/cursor";
    req.path_params["deviceId"] = "other-device-id";
    req.body = R"({"conversation_id": "conv-999", "last_delivered_sequence": 10})";

    httplib::Response res;
    handler_->handle_update_sync_cursor(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "PERMISSION_DENIED");
}

TEST_F(MessagingProxySyncTest, UpdateSyncCursorInvalidJsonReturns400) {
    httplib::Request req;
    req.method = "PUT";
    req.path = "/api/v1/devices/0191ec4d-91b4-7b4d-b6a9-8e41e3d36099/cursor";
    req.path_params["deviceId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";
    req.body = "{malformed-json";

    httplib::Response res;
    handler_->handle_update_sync_cursor(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "INVALID_ARGUMENT");
}

// ============================================================================
// Resilience & Bulkhead Rejections
// ============================================================================

TEST_F(MessagingProxySyncTest, BulkheadExhaustionReturns503) {
    // Exhaust all 10 slots
    std::vector<BulkheadLease> leases;
    for (int i = 0; i < 10; ++i) {
        leases.push_back(bulkhead_manager_->acquire(WorkloadCategory::Messaging));
        EXPECT_TRUE(leases.back());
    }

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/conversations/conv-123/messages";
    req.path_params["id"] = "conv-123";

    httplib::Response res;
    handler_->handle_sync_messages(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 503);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");
}

TEST_F(MessagingProxySyncTest, CircuitBreakerOpenReturns503) {
    circuit_breaker_->record_failure(true);
    circuit_breaker_->record_failure(true);
    EXPECT_EQ(circuit_breaker_->state(), CircuitState::Open);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/conversations/conv-123/messages";
    req.path_params["id"] = "conv-123";

    httplib::Response res;
    handler_->handle_sync_messages(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 503);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "CIRCUIT_BREAKER_OPEN");
}

} // namespace
} // namespace securecloud::gateway::http
