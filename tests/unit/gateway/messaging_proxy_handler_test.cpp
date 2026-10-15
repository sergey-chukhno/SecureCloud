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

class MessagingProxyHandlerTest : public ::testing::Test {
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
// Send Message Proxy Tests
// ============================================================================

TEST_F(MessagingProxyHandlerTest, SendMessageSuccess) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages";
    req.set_header("Content-Type", "application/json");
    req.set_header("X-Request-ID", "req-send-msg-001");
    req.set_header("X-Idempotency-Token", "tok-proxy-test-123");

    nlohmann::json payload;
    payload["conversation_id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    payload["priority"] = "normal";
    payload["delivery_targets"] =
        nlohmann::json::array({{{"recipient_user_id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002"},
                                {"recipient_device_id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36022"},
                                {"encrypted_payload",
                                 {{"ciphertext_blob", "encrypted-blob-data"},
                                  {"ephemeral_public_key", "ephemeral-key-bytes"},
                                  {"initialization_vector", "iv-bytes-12345678"},
                                  {"auth_tag", "tag-bytes-1234567"},
                                  {"algorithm", "XChaCha20-Poly1305"}}}}});
    req.body = payload.dump();

    securecloud::messaging::v1::SendMessageResponse grpc_resp;
    grpc_resp.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    grpc_resp.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    grpc_resp.set_accepted_at_unix_ms(1760000000000LL);
    grpc_resp.set_initial_state(securecloud::messaging::v1::DELIVERY_STATE_QUEUED);
    grpc_resp.set_target_count(1);

    EXPECT_CALL(*mock_client_, send_message(_, _))
        .WillOnce([&](const securecloud::messaging::v1::SendMessageRequest& r, grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(r.conversation_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
            EXPECT_EQ(r.client_idempotency_token(), "tok-proxy-test-123");
            EXPECT_EQ(r.delivery_targets_size(), 1);
            return grpc::Result<securecloud::messaging::v1::SendMessageResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_send_message(req, res, make_test_context());

    EXPECT_EQ(res.status, 201);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["message_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    EXPECT_EQ(body["conversation_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    EXPECT_EQ(body["initial_state"], "QUEUED");
    EXPECT_EQ(body["target_count"], 1);
}

TEST_F(MessagingProxyHandlerTest, SendMessageInvalidJsonBodyReturnsBadRequest) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages";
    req.body = "not valid json {(";

    httplib::Response res;
    handler_->handle_send_message(req, res, make_test_context());

    EXPECT_EQ(res.status, 400);
}

TEST_F(MessagingProxyHandlerTest, SendMessageIdempotencyConflictReturns409) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages";
    req.body = R"({"conversation_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001", "idempotency_token": "tok-123"})";

    grpc::DependencyError conflict_err{
        .kind = grpc::DependencyErrorKind::Internal,
        .message = "Idempotency key reused with conflicting request payload",
        .grpc_code = ::grpc::StatusCode::ALREADY_EXISTS,
    };

    EXPECT_CALL(*mock_client_, send_message(_, _))
        .WillOnce(Return(grpc::Result<securecloud::messaging::v1::SendMessageResponse>(conflict_err)));

    httplib::Response res;
    handler_->handle_send_message(req, res, make_test_context());

    EXPECT_EQ(res.status, 409);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "CONFLICT");
}

TEST_F(MessagingProxyHandlerTest, SendMessagePermissionDeniedReturns403) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages";
    req.body = R"({"conversation_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"})";

    grpc::DependencyError auth_err{
        .kind = grpc::DependencyErrorKind::PermissionDenied,
        .message = "Caller is not a member of the conversation",
        .grpc_code = ::grpc::StatusCode::PERMISSION_DENIED,
    };

    EXPECT_CALL(*mock_client_, send_message(_, _))
        .WillOnce(Return(grpc::Result<securecloud::messaging::v1::SendMessageResponse>(auth_err)));

    httplib::Response res;
    handler_->handle_send_message(req, res, make_test_context());

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "PERMISSION_DENIED");
}

TEST_F(MessagingProxyHandlerTest, SendMessageBulkheadRejectionReturns503) {
    // Saturated bulkhead
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
    req.path = "/api/v1/messages";
    req.body = R"({"conversation_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"})";

    httplib::Response res;
    rejecting_handler.handle_send_message(req, res, make_test_context());

    EXPECT_EQ(res.status, 503);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");
}

} // namespace
} // namespace securecloud::gateway::http
