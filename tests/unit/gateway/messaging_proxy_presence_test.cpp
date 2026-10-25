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
    return AuthenticatedContext(user_id, device_id, "session-test-presence",
                                securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                {"messaging:read", "messaging:write"}, 1750000000000LL);
}

class MessagingProxyPresenceTest : public ::testing::Test {
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
// 1. UpdatePresence Route Tests
// ============================================================================

TEST_F(MessagingProxyPresenceTest, UpdatePresenceSuccessWithUserId) {
    httplib::Request req;
    req.method = "PUT";
    req.path = "/v1/users/0191ec4d-91b4-7b4d-b6a9-8e41e3d36001/presence";
    req.path_params["userId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    req.body = R"({"status": "online", "custom_status_message": "Working on MSG-010"})";

    securecloud::messaging::v1::UpdatePresenceResponse grpc_resp;
    auto* p = grpc_resp.mutable_presence();
    p->set_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    p->set_status(securecloud::messaging::v1::PRESENCE_STATUS_ONLINE);
    p->set_last_active_unix_ms(1760000005000);
    p->set_custom_status_message("Working on MSG-010");

    EXPECT_CALL(*mock_client_, update_presence(_, _))
        .WillOnce([&](const securecloud::messaging::v1::UpdatePresenceRequest& request, grpc::ClientCallContext&) {
            EXPECT_EQ(request.status(), securecloud::messaging::v1::PRESENCE_STATUS_ONLINE);
            EXPECT_EQ(request.custom_status_message(), "Working on MSG-010");
            return grpc::Result<securecloud::messaging::v1::UpdatePresenceResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_update_presence(req, res, make_test_auth_context("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"));

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["user_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    EXPECT_EQ(body["status"], "online");
    EXPECT_EQ(body["last_active_unix_ms"], 1760000005000);
    EXPECT_EQ(body["custom_status_message"], "Working on MSG-010");
}

TEST_F(MessagingProxyPresenceTest, UpdatePresenceSuccessWithPresenceMe) {
    httplib::Request req;
    req.method = "PUT";
    req.path = "/v1/presence/me";
    req.body = R"({"status": "busy", "custom_status_message": "In a critical review"})";

    securecloud::messaging::v1::UpdatePresenceResponse grpc_resp;
    auto* p = grpc_resp.mutable_presence();
    p->set_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    p->set_status(securecloud::messaging::v1::PRESENCE_STATUS_BUSY);
    p->set_last_active_unix_ms(1760000006000);
    p->set_custom_status_message("In a critical review");

    EXPECT_CALL(*mock_client_, update_presence(_, _))
        .WillOnce([&](const securecloud::messaging::v1::UpdatePresenceRequest& request, grpc::ClientCallContext&) {
            EXPECT_EQ(request.status(), securecloud::messaging::v1::PRESENCE_STATUS_BUSY);
            EXPECT_EQ(request.custom_status_message(), "In a critical review");
            return grpc::Result<securecloud::messaging::v1::UpdatePresenceResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_update_presence(req, res, make_test_auth_context("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"));

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["status"], "busy");
    EXPECT_EQ(body["custom_status_message"], "In a critical review");
}

TEST_F(MessagingProxyPresenceTest, UpdatePresenceMismatchedCallerForbidden403) {
    httplib::Request req;
    req.method = "PUT";
    req.path = "/v1/users/0191ec4d-91b4-7b4d-b6a9-8e41e3d36999/presence";
    req.path_params["userId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36999";
    req.body = R"({"status": "online"})";

    EXPECT_CALL(*mock_client_, update_presence(_, _)).Times(0);

    httplib::Response res;
    handler_->handle_update_presence(req, res, make_test_auth_context("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"));

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "PERMISSION_DENIED");
}

TEST_F(MessagingProxyPresenceTest, UpdatePresenceInvalidJsonBadRequest400) {
    httplib::Request req;
    req.method = "PUT";
    req.path = "/v1/presence/me";
    req.body = "{not-valid-json}";

    EXPECT_CALL(*mock_client_, update_presence(_, _)).Times(0);

    httplib::Response res;
    handler_->handle_update_presence(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "INVALID_ARGUMENT");
}

TEST_F(MessagingProxyPresenceTest, UpdatePresenceMissingStatusBadRequest400) {
    httplib::Request req;
    req.method = "PUT";
    req.path = "/v1/presence/me";
    req.body = R"({"custom_status_message": "Missing status"})";

    EXPECT_CALL(*mock_client_, update_presence(_, _)).Times(0);

    httplib::Response res;
    handler_->handle_update_presence(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "INVALID_ARGUMENT");
}

TEST_F(MessagingProxyPresenceTest, UpdatePresenceInvalidStatusValueBadRequest400) {
    httplib::Request req;
    req.method = "PUT";
    req.path = "/v1/presence/me";
    req.body = R"({"status": "invisible_ninja"})";

    EXPECT_CALL(*mock_client_, update_presence(_, _)).Times(0);

    httplib::Response res;
    handler_->handle_update_presence(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "INVALID_ARGUMENT");
}

TEST_F(MessagingProxyPresenceTest, UpdatePresenceRateLimitedDownstream429) {
    httplib::Request req;
    req.method = "PUT";
    req.path = "/v1/presence/me";
    req.body = R"({"status": "offline"})";

    grpc::DependencyError rate_limited_error{
        .kind = grpc::DependencyErrorKind::Internal,
        .message = "Presence update rate limit exceeded (max 12 per minute)",
        .grpc_code = ::grpc::StatusCode::RESOURCE_EXHAUSTED,
    };

    EXPECT_CALL(*mock_client_, update_presence(_, _))
        .WillOnce(Return(grpc::Result<securecloud::messaging::v1::UpdatePresenceResponse>(rate_limited_error)));

    httplib::Response res;
    handler_->handle_update_presence(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 429);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "RESOURCE_EXHAUSTED");
}

// ============================================================================
// 2. GetPresence Route Tests
// ============================================================================

TEST_F(MessagingProxyPresenceTest, GetPresenceSuccessWithUserId) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/v1/users/0191ec4d-91b4-7b4d-b6a9-8e41e3d36002/presence";
    req.path_params["userId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";

    securecloud::messaging::v1::GetPresenceResponse grpc_resp;
    auto* p = grpc_resp.mutable_presence();
    p->set_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    p->set_status(securecloud::messaging::v1::PRESENCE_STATUS_AWAY);
    p->set_last_active_unix_ms(1760000007000);
    p->set_custom_status_message("Away from keyboard");

    EXPECT_CALL(*mock_client_, get_presence(_, _))
        .WillOnce([&](const securecloud::messaging::v1::GetPresenceRequest& request, grpc::ClientCallContext&) {
            EXPECT_EQ(request.user_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
            return grpc::Result<securecloud::messaging::v1::GetPresenceResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_get_presence(req, res, make_test_auth_context("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"));

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["user_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    EXPECT_EQ(body["status"], "away");
    EXPECT_EQ(body["last_active_unix_ms"], 1760000007000);
    EXPECT_EQ(body["custom_status_message"], "Away from keyboard");
}

TEST_F(MessagingProxyPresenceTest, GetPresenceSuccessWithPresenceMe) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/v1/presence/me";

    securecloud::messaging::v1::GetPresenceResponse grpc_resp;
    auto* p = grpc_resp.mutable_presence();
    p->set_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    p->set_status(securecloud::messaging::v1::PRESENCE_STATUS_ONLINE);
    p->set_last_active_unix_ms(1760000008000);

    EXPECT_CALL(*mock_client_, get_presence(_, _))
        .WillOnce([&](const securecloud::messaging::v1::GetPresenceRequest& request, grpc::ClientCallContext&) {
            EXPECT_EQ(request.user_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
            return grpc::Result<securecloud::messaging::v1::GetPresenceResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_get_presence(req, res, make_test_auth_context("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"));

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["user_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    EXPECT_EQ(body["status"], "online");
}

TEST_F(MessagingProxyPresenceTest, GetPresenceDownstreamNotFoundMapped) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/v1/users/0191ec4d-91b4-7b4d-b6a9-8e41e3d36002/presence";
    req.path_params["userId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";

    grpc::DependencyError not_found_error{
        .kind = grpc::DependencyErrorKind::NotFound,
        .message = "User not found",
        .grpc_code = ::grpc::StatusCode::NOT_FOUND,
    };

    EXPECT_CALL(*mock_client_, get_presence(_, _))
        .WillOnce(Return(grpc::Result<securecloud::messaging::v1::GetPresenceResponse>(not_found_error)));

    httplib::Response res;
    handler_->handle_get_presence(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 404);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "NOT_FOUND");
}

// ============================================================================
// 3. BatchGetPresence Route Tests
// ============================================================================

TEST_F(MessagingProxyPresenceTest, BatchGetPresenceSuccess) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/v1/users/presence/batch";
    req.body = R"({"user_ids": ["0191ec4d-91b4-7b4d-b6a9-8e41e3d36001", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002"]})";

    securecloud::messaging::v1::BatchGetPresenceResponse grpc_resp;
    auto* p1 = grpc_resp.add_presences();
    p1->set_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    p1->set_status(securecloud::messaging::v1::PRESENCE_STATUS_ONLINE);
    p1->set_last_active_unix_ms(1760000009000);

    auto* p2 = grpc_resp.add_presences();
    p2->set_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    p2->set_status(securecloud::messaging::v1::PRESENCE_STATUS_OFFLINE);
    p2->set_last_active_unix_ms(0);

    EXPECT_CALL(*mock_client_, batch_get_presence(_, _))
        .WillOnce([&](const securecloud::messaging::v1::BatchGetPresenceRequest& request, grpc::ClientCallContext&) {
            EXPECT_EQ(request.user_ids_size(), 2);
            EXPECT_EQ(request.user_ids(0), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
            EXPECT_EQ(request.user_ids(1), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
            return grpc::Result<securecloud::messaging::v1::BatchGetPresenceResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_batch_get_presence(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    ASSERT_TRUE(body.is_array());
    ASSERT_EQ(body.size(), 2);
    EXPECT_EQ(body[0]["user_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    EXPECT_EQ(body[0]["status"], "online");
    EXPECT_EQ(body[1]["user_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    EXPECT_EQ(body[1]["status"], "offline");
}

TEST_F(MessagingProxyPresenceTest, BatchGetPresenceExceedsMaxBatchSizeBadRequest400) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/v1/users/presence/batch";

    nlohmann::json req_body;
    req_body["user_ids"] = nlohmann::json::array();
    for (int i = 0; i < 101; ++i) {
        req_body["user_ids"].push_back("0191ec4d-91b4-7b4d-b6a9-" +
                                       std::to_string(100000000000ULL + static_cast<unsigned long long>(i)));
    }
    req.body = req_body.dump();

    EXPECT_CALL(*mock_client_, batch_get_presence(_, _)).Times(0);

    httplib::Response res;
    handler_->handle_batch_get_presence(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 400);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "INVALID_ARGUMENT");
}

// ============================================================================
// 4. Resilience & Protection Tests (Circuit Breaker & Bulkhead)
// ============================================================================

TEST_F(MessagingProxyPresenceTest, CircuitBreakerOpenRejection503) {
    // Force circuit breaker to open state by recording consecutive failures
    circuit_breaker_->record_failure();
    circuit_breaker_->record_failure();
    ASSERT_FALSE(circuit_breaker_->allow_request());

    EXPECT_CALL(*mock_client_, update_presence(_, _)).Times(0);

    httplib::Request req;
    req.method = "PUT";
    req.path = "/v1/presence/me";
    req.body = R"({"status": "online"})";

    httplib::Response res;
    handler_->handle_update_presence(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 503);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "CIRCUIT_BREAKER_OPEN");
}

TEST_F(MessagingProxyPresenceTest, BulkheadLimitExceededRejection503) {
    // Create saturated bulkhead manager with 0 slots
    auto saturated_bulkhead = std::make_shared<BulkheadManager>(GatewayBulkheadConfig{
        .auth_max_concurrent = 0,
        .messaging_max_concurrent = 0,
        .files_max_concurrent = 0,
        .emergency_reserved_slots = 0,
    });

    auto isolated_handler = std::make_unique<MessagingProxyHandler>(mock_client_, deadline_manager_, retry_policy_,
                                                                    saturated_bulkhead, circuit_breaker_);

    EXPECT_CALL(*mock_client_, get_presence(_, _)).Times(0);

    httplib::Request req;
    req.method = "GET";
    req.path = "/v1/presence/me";

    httplib::Response res;
    isolated_handler->handle_get_presence(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 503);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");
}

} // namespace
} // namespace securecloud::gateway::http
