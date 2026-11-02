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
                                            const std::string& device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d360a1") {
    return AuthenticatedContext(user_id, device_id, "session-multi-device-test",
                                securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                {"messaging:read", "messaging:write"}, 1750000000000LL);
}

class MessagingProxyMultiDeviceTest : public ::testing::Test {
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
                                                                             .failure_threshold = 3,
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

TEST_F(MessagingProxyMultiDeviceTest, SendMessagePropagatesDeviceContextAndMultiDeviceTargets) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/messages";
    req.body = R"({
        "conversation_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36100",
        "idempotency_token": "idem-multi-dev-001",
        "priority": "normal",
        "delivery_targets": [
            {
                "recipient_user_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
                "recipient_device_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2",
                "encrypted_payload": {
                    "ciphertext_blob": "CT_ALICE_COMPANION_A2",
                    "ephemeral_public_key": "EPK_A2",
                    "initialization_vector": "IV_A2",
                    "auth_tag": "TAG_A2",
                    "algorithm": "XChaCha20-Poly1305"
                }
            },
            {
                "recipient_user_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
                "recipient_device_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d360b1",
                "encrypted_payload": {
                    "ciphertext_blob": "CT_BOB_B1",
                    "ephemeral_public_key": "EPK_B1",
                    "initialization_vector": "IV_B1",
                    "auth_tag": "TAG_B1",
                    "algorithm": "XChaCha20-Poly1305"
                }
            },
            {
                "recipient_user_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
                "recipient_device_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d360b2",
                "encrypted_payload": {
                    "ciphertext_blob": "CT_BOB_B2",
                    "ephemeral_public_key": "EPK_B2",
                    "initialization_vector": "IV_B2",
                    "auth_tag": "TAG_B2",
                    "algorithm": "XChaCha20-Poly1305"
                }
            }
        ]
    })";

    securecloud::messaging::v1::SendMessageResponse grpc_resp;
    grpc_resp.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36999");
    grpc_resp.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36100");
    grpc_resp.set_accepted_at_unix_ms(1760000000000LL);
    grpc_resp.set_initial_state(securecloud::messaging::v1::DELIVERY_STATE_QUEUED);
    grpc_resp.set_target_count(3);

    EXPECT_CALL(*mock_client_, send_message(_, _))
        .WillOnce([&](const securecloud::messaging::v1::SendMessageRequest& grpc_req,
                      grpc::ClientCallContext& call_ctx) {
            EXPECT_FALSE(call_ctx.is_cancelled());
            EXPECT_EQ(grpc_req.sender_device_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d360a1");
            EXPECT_EQ(grpc_req.delivery_targets_size(), 3);
            if (grpc_req.delivery_targets_size() == 3) {
                EXPECT_EQ(grpc_req.delivery_targets(0).recipient_device_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2");
                EXPECT_EQ(grpc_req.delivery_targets(0).encrypted_payload().ciphertext_blob(), "CT_ALICE_COMPANION_A2");
                EXPECT_EQ(grpc_req.delivery_targets(1).recipient_device_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d360b1");
                EXPECT_EQ(grpc_req.delivery_targets(2).recipient_device_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d360b2");
            }
            return grpc::Result<securecloud::messaging::v1::SendMessageResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_send_message(req, res, make_test_auth_context());
    EXPECT_EQ(res.status, 201);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["target_count"], 3);
}

TEST_F(MessagingProxyMultiDeviceTest, SyncMessagesBindsCallerDeviceAndSerializesPreAndPostEnrollmentEnvelopes) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/v1/conversations/0191ec4d-91b4-7b4d-b6a9-8e41e3d36100/messages";
    req.path_params["conversationId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36100";
    req.params.emplace("since_sequence", "0");
    req.params.emplace("limit", "10");

    securecloud::messaging::v1::SyncDeviceMessagesResponse grpc_resp;
    grpc_resp.set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2");
    grpc_resp.set_has_more(false);
    grpc_resp.set_next_sequence(3);
    grpc_resp.set_latest_sequence(2);

    // Message 1: Pre-enrollment (zero delivery_targets)
    auto* m1 = grpc_resp.add_messages();
    m1->set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36901");
    m1->set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36100");
    m1->set_sender_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    m1->set_sender_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d360b1");
    m1->set_created_at_unix_ms(1760000001000LL);

    // Message 2: Post-enrollment (targeted to 0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2)
    auto* m2 = grpc_resp.add_messages();
    m2->set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36902");
    m2->set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36100");
    m2->set_sender_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    m2->set_sender_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d360b1");
    m2->set_created_at_unix_ms(1760000002000LL);
    auto* t2 = m2->add_delivery_targets();
    t2->set_recipient_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2");
    t2->set_state(securecloud::messaging::v1::DELIVERY_STATE_QUEUED);
    t2->mutable_encrypted_payload()->set_ciphertext_blob("CIPHERTEXT_FOR_A2");
    t2->mutable_encrypted_payload()->set_algorithm("XChaCha20-Poly1305");

    EXPECT_CALL(*mock_client_, sync_device_messages(_, _))
        .WillOnce([&](const securecloud::messaging::v1::SyncDeviceMessagesRequest& grpc_req,
                      grpc::ClientCallContext& call_ctx) {
            EXPECT_FALSE(call_ctx.is_cancelled());
            EXPECT_EQ(grpc_req.device_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2");
            return grpc::Result<securecloud::messaging::v1::SyncDeviceMessagesResponse>(grpc_resp);
        });

    httplib::Response res;
    handler_->handle_sync_messages(
        req, res,
        make_test_auth_context("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001", "0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2"));

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    ASSERT_EQ(body["messages"].size(), 2u);
    EXPECT_TRUE(body["messages"][0]["delivery_targets"].empty());
    ASSERT_EQ(body["messages"][1]["delivery_targets"].size(), 1u);
    EXPECT_EQ(body["messages"][1]["delivery_targets"][0]["recipient_device_id"],
              "0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2");
    EXPECT_EQ(body["messages"][1]["delivery_targets"][0]["encrypted_payload"]["ciphertext_blob"], "CIPHERTEXT_FOR_A2");
}

TEST_F(MessagingProxyMultiDeviceTest, SyncMessagesRejectsCrossDeviceImpersonationQueryParam) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/v1/conversations/0191ec4d-91b4-7b4d-b6a9-8e41e3d36100/messages";
    req.path_params["conversationId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36100";
    req.params.emplace("recipient_device_id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2"); // Different from caller A1!

    httplib::Response res;
    handler_->handle_sync_messages(
        req, res,
        make_test_auth_context("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001", "0191ec4d-91b4-7b4d-b6a9-8e41e3d360a1"));

    EXPECT_EQ(res.status, 403);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["error"]["code"], "PERMISSION_DENIED");
}

TEST_F(MessagingProxyMultiDeviceTest, GetDeliveryStatusSerializesMultiDeviceStatusesAndLogicalRecipientReadStatuses) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/v1/conversations/0191ec4d-91b4-7b4d-b6a9-8e41e3d36100/messages/"
               "0191ec4d-91b4-7b4d-b6a9-8e41e3d36999/delivery-status";
    req.path_params["conversationId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36100";
    req.path_params["messageId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36999";

    securecloud::messaging::v1::GetMessageDeliveryStatusResponse grpc_resp;
    grpc_resp.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36999");
    grpc_resp.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36100");
    grpc_resp.mutable_summary()->set_total_targets(3);
    grpc_resp.mutable_summary()->set_delivered_targets(2);
    grpc_resp.mutable_summary()->set_pending_targets(1);
    grpc_resp.mutable_summary()->set_expired_targets(0);

    auto* ds1 = grpc_resp.add_device_statuses();
    ds1->set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2");
    ds1->set_recipient_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    ds1->set_delivery_state(securecloud::messaging::v1::DELIVERY_STATE_DELIVERED);
    ds1->set_delivered_at_unix_ms(1760000001000LL);

    auto* ds2 = grpc_resp.add_device_statuses();
    ds2->set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d360b1");
    ds2->set_recipient_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    ds2->set_delivery_state(securecloud::messaging::v1::DELIVERY_STATE_DELIVERED);
    ds2->set_delivered_at_unix_ms(1760000002000LL);

    auto* ds3 = grpc_resp.add_device_statuses();
    ds3->set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d360b2");
    ds3->set_recipient_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    ds3->set_delivery_state(securecloud::messaging::v1::DELIVERY_STATE_QUEUED);

    auto* rrs1 = grpc_resp.add_recipient_read_statuses();
    rrs1->set_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    rrs1->set_is_read(true);
    rrs1->set_read_at_unix_ms(1760000003000LL);
    rrs1->set_reader_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d360b1");

    EXPECT_CALL(*mock_client_, get_message_delivery_status(_, _))
        .WillOnce(Return(grpc::Result<securecloud::messaging::v1::GetMessageDeliveryStatusResponse>(grpc_resp)));

    httplib::Response res;
    handler_->handle_get_delivery_status(req, res, make_test_auth_context());

    EXPECT_EQ(res.status, 200);
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body["summary"]["total_targets"], 3);
    EXPECT_EQ(body["summary"]["delivered_targets"], 2);
    EXPECT_EQ(body["summary"]["pending_targets"], 1);
    ASSERT_EQ(body["device_statuses"].size(), 3u);
    EXPECT_EQ(body["device_statuses"][0]["delivery_state"], "DELIVERED");
    EXPECT_EQ(body["device_statuses"][1]["delivery_state"], "DELIVERED");
    EXPECT_EQ(body["device_statuses"][2]["delivery_state"], "QUEUED");
    ASSERT_EQ(body["recipient_read_statuses"].size(), 1u);
    EXPECT_TRUE(body["recipient_read_statuses"][0]["is_read"].get<bool>());
    EXPECT_EQ(body["recipient_read_statuses"][0]["reader_device_id"], "0191ec4d-91b4-7b4d-b6a9-8e41e3d360b1");
}

TEST_F(MessagingProxyMultiDeviceTest, GetAndUpdateSyncCursorRejectCrossDeviceAccess) {
    httplib::Request get_req;
    get_req.method = "GET";
    get_req.path = "/v1/devices/0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2/cursor";
    get_req.path_params["deviceId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2";

    httplib::Response get_res;
    handler_->handle_get_sync_cursor(get_req, get_res, make_test_auth_context());
    EXPECT_EQ(get_res.status, 403);

    httplib::Request put_req;
    put_req.method = "PUT";
    put_req.path = "/v1/devices/0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2/cursor";
    put_req.path_params["deviceId"] = "0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2";
    put_req.body = R"({"conversation_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36100", "last_delivered_sequence": 10})";

    httplib::Response put_res;
    handler_->handle_update_sync_cursor(put_req, put_res, make_test_auth_context());
    EXPECT_EQ(put_res.status, 403);
}

} // namespace
} // namespace securecloud::gateway::http
