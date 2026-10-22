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

// ============================================================================
// Send Read Receipt Proxy Tests (MSG-008)
// ============================================================================

TEST_F(MessagingProxyHandlerTest, SendReadReceiptSuccess) {
    httplib::Request req;
    req.method = "POST";
    req.path =
        "/api/v1/conversations/0191ec4d-91b4-7b4d-b6a9-8e41e3d36001/messages/0191ec4d-91b4-7b4d-b6a9-8e41e3d36099/read";
    req.path_params["conversationId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    req.path_params["messageId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";
    req.set_header("Content-Type", "application/json");
    req.set_header("X-Request-ID", "req-read-receipt-001");
    req.body = R"({"read_at_unix_ms": 1760000000000, "reader_device_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099"})";

    securecloud::messaging::v1::SendReadReceiptResponse grpc_resp;
    grpc_resp.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    grpc_resp.set_state(securecloud::messaging::v1::DELIVERY_STATE_DELIVERED);
    grpc_resp.set_recorded_at_unix_ms(1760000000000LL);

    EXPECT_CALL(*mock_client_, send_read_receipt(_, _))
        .WillOnce([&](const securecloud::messaging::v1::SendReadReceiptRequest& r, grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(r.conversation_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
            EXPECT_EQ(r.message_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
            EXPECT_EQ(r.reader_device_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
            EXPECT_EQ(r.read_at_unix_ms(), 1760000000000LL);
            return grpc::Result<securecloud::messaging::v1::SendReadReceiptResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_send_read_receipt(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["message_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    EXPECT_EQ(body["state"], "READ");
    EXPECT_EQ(body["recorded_at_unix_ms"], 1760000000000LL);
}

TEST_F(MessagingProxyHandlerTest, SendReadReceiptInvalidJsonBodyReturnsBadRequest) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/0191ec4d-91b4-7b4d-b6a9-8e41e3d36099/read";
    req.path_params["id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";
    req.body = "malformed json {(";

    httplib::Response res;
    handler_->handle_send_read_receipt(req, res, make_test_context());

    EXPECT_EQ(res.status, 400);
}

TEST_F(MessagingProxyHandlerTest, SendReadReceiptPermissionDeniedReturns403) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/0191ec4d-91b4-7b4d-b6a9-8e41e3d36099/read";
    req.path_params["id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";

    grpc::DependencyError auth_err{
        .kind = grpc::DependencyErrorKind::PermissionDenied,
        .message = "Caller is not a member of the conversation",
        .grpc_code = ::grpc::StatusCode::PERMISSION_DENIED,
    };

    EXPECT_CALL(*mock_client_, send_read_receipt(_, _))
        .WillOnce(Return(grpc::Result<securecloud::messaging::v1::SendReadReceiptResponse>(auth_err)));

    httplib::Response res;
    handler_->handle_send_read_receipt(req, res, make_test_context());

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "PERMISSION_DENIED");
}

TEST_F(MessagingProxyHandlerTest, SendReadReceiptBulkheadRejectionReturns503) {
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
    req.path = "/api/v1/messages/0191ec4d-91b4-7b4d-b6a9-8e41e3d36099/read";
    req.path_params["id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";

    httplib::Response res;
    rejecting_handler.handle_send_read_receipt(req, res, make_test_context());

    EXPECT_EQ(res.status, 503);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");
}

TEST_F(MessagingProxyHandlerTest, SendReadReceiptCircuitBreakerRejectionReturns503) {
    auto cb = std::make_shared<CircuitBreaker>("messaging", GatewayCircuitBreakerConfig{
                                                                .enabled = true,
                                                                .failure_threshold = 1,
                                                                .recovery_timeout_ms = 60000,
                                                                .half_open_probe_count = 1,
                                                            });
    cb->record_failure(); // Trips breaker open

    MessagingProxyHandler tripped_handler(mock_client_, deadline_manager_, retry_policy_, bulkhead_manager_, cb);

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages/0191ec4d-91b4-7b4d-b6a9-8e41e3d36099/read";
    req.path_params["id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";

    httplib::Response res;
    tripped_handler.handle_send_read_receipt(req, res, make_test_context());

    EXPECT_EQ(res.status, 503);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "CIRCUIT_BREAKER_OPEN");
}

// ============================================================================
// Get Message Delivery Status Proxy Tests (MSG-008)
// ============================================================================

TEST_F(MessagingProxyHandlerTest, GetMessageDeliveryStatusSuccess) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/conversations/0191ec4d-91b4-7b4d-b6a9-8e41e3d36001/messages/"
               "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099/delivery-status";
    req.path_params["conversationId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    req.path_params["messageId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";
    req.set_header("X-Request-ID", "req-status-001");

    securecloud::messaging::v1::GetMessageDeliveryStatusResponse grpc_resp;
    grpc_resp.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    grpc_resp.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");

    auto* summary = grpc_resp.mutable_summary();
    summary->set_total_targets(2);
    summary->set_delivered_targets(1);
    summary->set_pending_targets(1);
    summary->set_expired_targets(0);

    auto* ds1 = grpc_resp.add_device_statuses();
    ds1->set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36021");
    ds1->set_recipient_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    ds1->set_delivery_state(securecloud::messaging::v1::DELIVERY_STATE_DELIVERED);
    ds1->set_delivered_at_unix_ms(1760000000100LL);
    ds1->set_attempt_count(1);

    auto* ds2 = grpc_resp.add_device_statuses();
    ds2->set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36022");
    ds2->set_recipient_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    ds2->set_delivery_state(securecloud::messaging::v1::DELIVERY_STATE_QUEUED);
    ds2->set_delivered_at_unix_ms(0);
    ds2->set_attempt_count(0);

    auto* rrs = grpc_resp.add_recipient_read_statuses();
    rrs->set_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    rrs->set_is_read(true);
    rrs->set_read_at_unix_ms(1760000000200LL);
    rrs->set_reader_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36021");

    EXPECT_CALL(*mock_client_, get_message_delivery_status(_, _))
        .WillOnce([&](const securecloud::messaging::v1::GetMessageDeliveryStatusRequest& r,
                      grpc::ClientCallContext& /*ctx*/) {
            EXPECT_EQ(r.conversation_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
            EXPECT_EQ(r.message_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
            return grpc::Result<securecloud::messaging::v1::GetMessageDeliveryStatusResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_get_delivery_status(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["message_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    EXPECT_EQ(body["conversation_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    EXPECT_EQ(body["summary"]["total_targets"], 2);
    EXPECT_EQ(body["summary"]["delivered_targets"], 1);
    EXPECT_EQ(body["summary"]["pending_targets"], 1);
    EXPECT_EQ(body["summary"]["expired_targets"], 0);

    ASSERT_EQ(body["device_statuses"].size(), 2);
    EXPECT_EQ(body["device_statuses"][0]["delivery_state"], "DELIVERED");
    EXPECT_EQ(body["device_statuses"][0]["attempt_count"], 1);
    EXPECT_EQ(body["device_statuses"][1]["delivery_state"], "QUEUED");

    ASSERT_EQ(body["recipient_read_statuses"].size(), 1);
    EXPECT_EQ(body["recipient_read_statuses"][0]["user_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    EXPECT_TRUE(body["recipient_read_statuses"][0]["is_read"].get<bool>());
    EXPECT_EQ(body["recipient_read_statuses"][0]["reader_device_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36021");
}

TEST_F(MessagingProxyHandlerTest, GetMessageDeliveryStatusMissingMessageIdReturnsBadRequest) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/messages//delivery-status";

    httplib::Response res;
    handler_->handle_get_delivery_status(req, res, make_test_context());

    EXPECT_EQ(res.status, 400);
}

TEST_F(MessagingProxyHandlerTest, GetMessageDeliveryStatusPermissionDeniedReturns403) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/messages/0191ec4d-91b4-7b4d-b6a9-8e41e3d36099/delivery-status";
    req.path_params["id"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";

    grpc::DependencyError auth_err{
        .kind = grpc::DependencyErrorKind::PermissionDenied,
        .message = "Caller is not a member of the conversation",
        .grpc_code = ::grpc::StatusCode::PERMISSION_DENIED,
    };

    EXPECT_CALL(*mock_client_, get_message_delivery_status(_, _))
        .WillOnce(Return(grpc::Result<securecloud::messaging::v1::GetMessageDeliveryStatusResponse>(auth_err)));

    httplib::Response res;
    handler_->handle_get_delivery_status(req, res, make_test_context());

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "PERMISSION_DENIED");
}

} // namespace
} // namespace securecloud::gateway::http
