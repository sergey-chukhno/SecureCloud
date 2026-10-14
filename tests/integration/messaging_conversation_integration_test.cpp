#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "concurrency/bounded_worker_pool.hpp"
#include "gateway_config.hpp"
#include "grpc/messaging_service_client.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/auth/request_context.hpp"
#include "http/proxy/messaging_proxy_handler.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/retry_policy.hpp"
#include "http/routing/router.hpp"
#include "messaging_config.hpp"
#include "repository/in_memory_conversation_repository.hpp"
#include "repository/in_memory_membership_repository.hpp"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "securecloud/security/mtls_config.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/conversation_service.hpp"
#include "service/messaging_service_impl.hpp"

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include <chrono>
#include <filesystem>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace securecloud::messaging {
namespace {

using common::health::HealthServiceImpl;
using common::health::HealthStatusManager;
using common::security::MtlsCredentialLoader;
using common::security::SecurityCredentialsConfig;
using service::ConversationAuthorizationService;
using service::ConversationService;
using service::MessagingServiceImpl;

constexpr std::chrono::milliseconds k_server_shutdown_timeout{500};
constexpr std::chrono::seconds k_rpc_deadline{5};

// Canonical RFC 4122 UUID test constants
constexpr const char* k_user_alice = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
constexpr const char* k_user_bob = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
constexpr const char* k_user_charlie = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";
constexpr const char* k_user_david = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36004";

constexpr const char* k_device_alice_phone = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36011";
constexpr const char* k_device_alice_laptop = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36012";

class MessagingConversationIntegrationTest : public ::testing::Test {
  protected:
    static std::filesystem::path find_pki_root() {
#ifdef SECURECLOUD_DEV_PKI_DIR
        std::filesystem::path defined_path(SECURECLOUD_DEV_PKI_DIR);
        if (std::filesystem::exists(defined_path / "ca" / "ca.crt")) {
            return defined_path;
        }
#endif
        auto curr = std::filesystem::current_path();
        while (!curr.empty() && curr != curr.root_path()) {
            if (std::filesystem::exists(curr / "deploy" / "dev-pki" / "ca" / "ca.crt")) {
                return curr / "deploy" / "dev-pki";
            }
            curr = curr.parent_path();
        }
        return "deploy/dev-pki";
    }

    void SetUp() override {
        auto pki_root = find_pki_root();
        ca_path_ = pki_root / "ca" / "ca.crt";
        messaging_cert_path_ = pki_root / "services" / "messaging" / "messaging.crt";
        messaging_key_path_ = pki_root / "services" / "messaging" / "messaging.key";
        gateway_cert_path_ = pki_root / "services" / "gateway" / "gateway.crt";
        gateway_key_path_ = pki_root / "services" / "gateway" / "gateway.key";

        const std::vector<std::filesystem::path> required_paths = {ca_path_, messaging_cert_path_, messaging_key_path_,
                                                                   gateway_cert_path_, gateway_key_path_};

        for (const auto& path : required_paths) {
            ASSERT_TRUE(std::filesystem::exists(path)) << "Required dev PKI credential missing: " << path;
        }

        messaging_config_ = SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = messaging_cert_path_,
            .service_key_path = messaging_key_path_,
        };

        gateway_config_ = SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = gateway_cert_path_,
            .service_key_path = gateway_key_path_,
        };

        // Worker pools for messaging service
        submission_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "sub-conv-integ");
        delivery_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "del-conv-integ");
        sync_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "sync-conv-integ");

        // Repositories and domain services
        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        member_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *member_repo_);
        conv_service_ = std::make_shared<ConversationService>(*conv_repo_, *member_repo_, *auth_service_);

        // Live gRPC messaging service implementation
        messaging_service_ =
            std::make_unique<MessagingServiceImpl>(submission_pool_, delivery_pool_, sync_pool_, conv_service_);

        start_server();
        setup_clients();
    }

    void TearDown() override {
        stop_server();
        if (submission_pool_ && !submission_pool_->is_shutdown()) {
            submission_pool_->shutdown();
        }
        if (delivery_pool_ && !delivery_pool_->is_shutdown()) {
            delivery_pool_->shutdown();
        }
        if (sync_pool_ && !sync_pool_->is_shutdown()) {
            sync_pool_->shutdown();
        }
    }

    struct RunningServer {
        std::unique_ptr<grpc::Server> server;
        std::string address;
        int port{0};
    };

    void start_server() {
        auto server_creds = MtlsCredentialLoader::create_server_credentials(messaging_config_);
        ASSERT_NE(server_creds, nullptr);

        grpc::ServerBuilder builder;
        int selected_port = 0;
        builder.AddListeningPort("127.0.0.1:0", server_creds, &selected_port);
        builder.RegisterService(messaging_service_.get());

        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);
        ASSERT_GT(selected_port, 0);

        server_address_ = "127.0.0.1:" + std::to_string(selected_port);
    }

    void stop_server() {
        if (server_) {
            server_->Shutdown(std::chrono::system_clock::now() + k_server_shutdown_timeout);
            server_.reset();
        }
    }

    void setup_clients() {
        // Direct gRPC client channel over mTLS as "gateway" peer
        channel_ = MtlsCredentialLoader::create_mtls_channel(server_address_, gateway_config_, "messaging");
        ASSERT_NE(channel_, nullptr);
        grpc_stub_ = v1::MessagingService::NewStub(channel_);

        // Gateway downstream IMessagingClient adapter
        gateway_client_ = std::make_shared<gateway::grpc::MessagingServiceClient>(channel_);

        // Gateway proxy handler dependencies
        auto deadline_mgr = std::make_shared<gateway::http::DeadlineManager>(
            gateway::GatewayServiceDeadlinesConfig{.messaging_timeout_ms = 5000});
        auto retry_policy = std::make_shared<gateway::http::RetryPolicy>();
        auto bulkhead_mgr = std::make_shared<gateway::http::BulkheadManager>(
            gateway::GatewayBulkheadConfig{.messaging_max_concurrent = 20});
        auto circuit_breaker = std::make_shared<gateway::http::CircuitBreaker>(
            "messaging", gateway::GatewayCircuitBreakerConfig{.enabled = true});

        proxy_handler_ = std::make_shared<gateway::http::MessagingProxyHandler>(
            gateway_client_, deadline_mgr, retry_policy, bulkhead_mgr, circuit_breaker);
    }

    void configure_context(grpc::ClientContext& context, const std::string& user_id, const std::string& device_id = "",
                           const std::string& correlation_id = "corr-conv-test") {
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        context.AddMetadata("x-user-id", user_id);
        context.AddMetadata("x-correlation-id", correlation_id);
        if (!device_id.empty()) {
            context.AddMetadata("x-device-id", device_id);
        }
    }

    std::filesystem::path ca_path_;
    std::filesystem::path messaging_cert_path_;
    std::filesystem::path messaging_key_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;

    SecurityCredentialsConfig messaging_config_;
    SecurityCredentialsConfig gateway_config_;

    std::shared_ptr<concurrency::BoundedWorkerPool> submission_pool_;
    std::shared_ptr<concurrency::BoundedWorkerPool> delivery_pool_;
    std::shared_ptr<concurrency::BoundedWorkerPool> sync_pool_;

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> member_repo_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<ConversationService> conv_service_;
    std::unique_ptr<MessagingServiceImpl> messaging_service_;

    std::unique_ptr<grpc::Server> server_;
    std::string server_address_;

    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::MessagingService::Stub> grpc_stub_;
    std::shared_ptr<gateway::grpc::MessagingServiceClient> gateway_client_;
    std::shared_ptr<gateway::http::MessagingProxyHandler> proxy_handler_;
};

// ============================================================================
// Scenario 1: Direct Conversation Idempotency & Canonical Ordering
// ============================================================================

TEST_F(MessagingConversationIntegrationTest, DirectConversationIdempotencyAndCanonicalOrdering) {
    // 1. User Alice creates direct conversation with Bob
    std::string conv_id_first;
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_alice, k_device_alice_phone);

        v1::CreateConversationRequest req;
        req.set_type(v1::CONVERSATION_TYPE_DIRECT);
        req.add_participant_user_ids(k_user_bob);

        v1::CreateConversationResponse resp;
        auto status = grpc_stub_->CreateConversation(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << "Alice CreateConversation failed: " << status.error_message();
        ASSERT_TRUE(resp.has_conversation());
        conv_id_first = resp.conversation().conversation_id();
        EXPECT_FALSE(conv_id_first.empty());
        EXPECT_EQ(resp.conversation().type(), v1::CONVERSATION_TYPE_DIRECT);
    }

    // 2. User Bob creates direct conversation with Alice (inverse order)
    std::string conv_id_second;
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_bob);

        v1::CreateConversationRequest req;
        req.set_type(v1::CONVERSATION_TYPE_DIRECT);
        req.add_participant_user_ids(k_user_alice);

        v1::CreateConversationResponse resp;
        auto status = grpc_stub_->CreateConversation(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << "Bob CreateConversation failed: " << status.error_message();
        ASSERT_TRUE(resp.has_conversation());
        conv_id_second = resp.conversation().conversation_id();
    }

    // Verify idempotent deduplication: exactly same UUID returned
    EXPECT_EQ(conv_id_first, conv_id_second);

    // 3. Verify roster has exactly Alice and Bob
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_alice);

        v1::GetConversationRequest req;
        req.set_conversation_id(conv_id_first);

        v1::GetConversationResponse resp;
        auto status = grpc_stub_->GetConversation(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << "GetConversation failed: " << status.error_message();
        ASSERT_TRUE(resp.has_conversation());
        EXPECT_EQ(resp.conversation().participant_user_ids_size(), 2);
    }

    // 4. Attempt to add a 3rd participant (Charlie) to the direct conversation -> REJECTED
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_alice);

        v1::AddParticipantRequest req;
        req.set_conversation_id(conv_id_first);
        req.set_participant_user_id(k_user_charlie);

        v1::AddParticipantResponse resp;
        auto status = grpc_stub_->AddParticipant(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
        EXPECT_NE(status.error_message().find("direct conversation"), std::string::npos);
    }
}

// ============================================================================
// Scenario 2: Group Conversation Lifecycle & Admin Hierarchy
// ============================================================================

TEST_F(MessagingConversationIntegrationTest, GroupConversationLifecycleAndAdminHierarchy) {
    std::string group_id;

    // 1. Admin Alice creates group "Alpha Squad" with initial members Bob and Charlie
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_alice);

        v1::CreateConversationRequest req;
        req.set_type(v1::CONVERSATION_TYPE_GROUP);
        req.set_title("Alpha Squad");
        req.add_participant_user_ids(k_user_bob);
        req.add_participant_user_ids(k_user_charlie);

        v1::CreateConversationResponse resp;
        auto status = grpc_stub_->CreateConversation(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << "Create group failed: " << status.error_message();
        group_id = resp.conversation().conversation_id();
        EXPECT_FALSE(group_id.empty());
        EXPECT_EQ(resp.conversation().type(), v1::CONVERSATION_TYPE_GROUP);
        EXPECT_EQ(resp.conversation().title(), "Alpha Squad");
    }

    // 2. Non-admin Bob attempts to add David -> REJECTED with PERMISSION_DENIED
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_bob);

        v1::AddParticipantRequest req;
        req.set_conversation_id(group_id);
        req.set_participant_user_id(k_user_david);

        v1::AddParticipantResponse resp;
        auto status = grpc_stub_->AddParticipant(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    }

    // 3. Admin Alice adds David -> SUCCEEDS (roster now has Alice, Bob, Charlie, David)
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_alice);

        v1::AddParticipantRequest req;
        req.set_conversation_id(group_id);
        req.set_participant_user_id(k_user_david);

        v1::AddParticipantResponse resp;
        auto status = grpc_stub_->AddParticipant(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << "Admin AddParticipant failed: " << status.error_message();
        EXPECT_EQ(resp.total_participants(), 4);
    }

    // 4. Admin Alice removes Charlie -> SUCCEEDS
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_alice);

        v1::RemoveParticipantRequest req;
        req.set_conversation_id(group_id);
        req.set_participant_user_id(k_user_charlie);

        v1::RemoveParticipantResponse resp;
        auto status = grpc_stub_->RemoveParticipant(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << "Admin RemoveParticipant failed: " << status.error_message();
        EXPECT_EQ(resp.total_participants(), 3);
    }

    // 5. Removed member Charlie attempts to query conversation -> REJECTED with PERMISSION_DENIED
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_charlie);

        v1::GetConversationRequest req;
        req.set_conversation_id(group_id);

        v1::GetConversationResponse resp;
        auto status = grpc_stub_->GetConversation(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    }
}

// ============================================================================
// Scenario 3: Voluntary Participant Exit (LeaveConversation)
// ============================================================================

TEST_F(MessagingConversationIntegrationTest, VoluntaryParticipantExit) {
    std::string group_id;

    // 1. Admin Alice creates group with Bob and David
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_alice);

        v1::CreateConversationRequest req;
        req.set_type(v1::CONVERSATION_TYPE_GROUP);
        req.set_title("Beta Team");
        req.add_participant_user_ids(k_user_bob);
        req.add_participant_user_ids(k_user_david);

        v1::CreateConversationResponse resp;
        auto status = grpc_stub_->CreateConversation(&ctx, req, &resp);
        ASSERT_TRUE(status.ok());
        group_id = resp.conversation().conversation_id();
    }

    // 2. Member David voluntarily leaves the conversation
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_david);

        v1::LeaveConversationRequest req;
        req.set_conversation_id(group_id);

        v1::LeaveConversationResponse resp;
        auto status = grpc_stub_->LeaveConversation(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << "David LeaveConversation failed: " << status.error_message();
        EXPECT_TRUE(resp.success());
    }

    // 3. David can no longer view conversation details
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_david);

        v1::GetConversationRequest req;
        req.set_conversation_id(group_id);

        v1::GetConversationResponse resp;
        auto status = grpc_stub_->GetConversation(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    }

    // 4. Listing conversations for David returns zero active conversations
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_david);

        v1::ListConversationsRequest req;
        req.set_max_results(10);

        v1::ListConversationsResponse resp;
        auto status = grpc_stub_->ListConversations(&ctx, req, &resp);
        ASSERT_TRUE(status.ok());
        EXPECT_EQ(resp.conversations_size(), 0);
    }
}

// ============================================================================
// Scenario 4: Group Close & Mutation Lockout
// ============================================================================

TEST_F(MessagingConversationIntegrationTest, GroupCloseAndMutationLockout) {
    std::string group_id;

    // 1. Admin Alice creates group "Gamma Ops"
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_alice);

        v1::CreateConversationRequest req;
        req.set_type(v1::CONVERSATION_TYPE_GROUP);
        req.set_title("Gamma Ops");
        req.add_participant_user_ids(k_user_bob);

        v1::CreateConversationResponse resp;
        auto status = grpc_stub_->CreateConversation(&ctx, req, &resp);
        ASSERT_TRUE(status.ok());
        group_id = resp.conversation().conversation_id();
    }

    // 2. Close group conversation at storage layer
    auto parsed_id = domain::ConversationId::from_string(group_id);
    ASSERT_TRUE(parsed_id.has_value());
    auto group_meta = conv_repo_->find_group_metadata(*parsed_id);
    ASSERT_TRUE(group_meta.has_value());
    group_meta->status = domain::GroupStatus::Closed;
    conv_repo_->save_group_metadata(*group_meta);

    // 3. Attempt to add participant to CLOSED group -> REJECTED with FAILED_PRECONDITION
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_alice);

        v1::AddParticipantRequest req;
        req.set_conversation_id(group_id);
        req.set_participant_user_id(k_user_david);

        v1::AddParticipantResponse resp;
        auto status = grpc_stub_->AddParticipant(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
    }

    // 4. Attempt to update metadata on CLOSED group -> REJECTED with FAILED_PRECONDITION
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_alice);

        v1::UpdateConversationMetadataRequest req;
        req.set_conversation_id(group_id);
        req.set_title("Gamma Ops - Renamed");

        v1::UpdateConversationMetadataResponse resp;
        auto status = grpc_stub_->UpdateConversationMetadata(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
    }
}

// ============================================================================
// Scenario 5: Multi-Device Participant Invariance
// ============================================================================

TEST_F(MessagingConversationIntegrationTest, MultiDeviceParticipantInvariance) {
    // 1. Alice creates direct conversation using phone device ID
    std::string conv_id;
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_alice, k_device_alice_phone);

        v1::CreateConversationRequest req;
        req.set_type(v1::CONVERSATION_TYPE_DIRECT);
        req.add_participant_user_ids(k_user_bob);

        v1::CreateConversationResponse resp;
        auto status = grpc_stub_->CreateConversation(&ctx, req, &resp);
        ASSERT_TRUE(status.ok());
        conv_id = resp.conversation().conversation_id();
    }

    // 2. Alice retrieves conversation using laptop device ID
    {
        grpc::ClientContext ctx;
        configure_context(ctx, k_user_alice, k_device_alice_laptop);

        v1::GetConversationRequest req;
        req.set_conversation_id(conv_id);

        v1::GetConversationResponse resp;
        auto status = grpc_stub_->GetConversation(&ctx, req, &resp);
        ASSERT_TRUE(status.ok());
        ASSERT_TRUE(resp.has_conversation());

        // Invariant: Membership maintains logical UserId identity, invariant to device
        EXPECT_EQ(resp.conversation().participant_user_ids_size(), 2);
        EXPECT_EQ(resp.conversation().creator_user_id(), k_user_alice);
    }
}

// ============================================================================
// Scenario 6: Gateway HTTP Proxy End-to-End
// ============================================================================

TEST_F(MessagingConversationIntegrationTest, GatewayHttpProxyEndToEnd) {
    gateway::http::AuthenticatedContext auth_ctx(
        k_user_alice, k_device_alice_phone, "sess-integ-01",
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {"messaging:read", "messaging:write"},
        1750000000000LL);

    std::string created_conv_id;

    // 1. POST /api/v1/conversations through Gateway Proxy Handler
    {
        httplib::Request req;
        req.method = "POST";
        req.path = "/api/v1/conversations";
        req.set_header("Content-Type", "application/json");
        req.body = nlohmann::json({{"type", "group"},
                                   {"title", "Gateway E2E Core"},
                                   {"participant_user_ids", {k_user_bob, k_user_charlie}}})
                       .dump();

        httplib::Response res;
        proxy_handler_->handle_create_conversation(req, res, auth_ctx);

        EXPECT_EQ(res.status, 201);
        auto body = nlohmann::json::parse(res.body);
        EXPECT_TRUE(body.contains("conversation"));
        created_conv_id = body["conversation"]["conversation_id"];
        EXPECT_FALSE(created_conv_id.empty());
        EXPECT_EQ(body["conversation"]["title"], "Gateway E2E Core");
    }

    // 2. GET /api/v1/conversations/:id through Gateway Proxy Handler
    {
        httplib::Request req;
        req.method = "GET";
        req.path = "/api/v1/conversations/" + created_conv_id;
        req.path_params["id"] = created_conv_id;

        httplib::Response res;
        proxy_handler_->handle_get_conversation(req, res, auth_ctx);

        EXPECT_EQ(res.status, 200);
        auto body = nlohmann::json::parse(res.body);
        EXPECT_EQ(body["conversation"]["conversation_id"], created_conv_id);
        EXPECT_EQ(body["conversation"]["title"], "Gateway E2E Core");
    }

    // 3. POST /api/v1/conversations/:id/participants through Gateway Proxy Handler
    {
        httplib::Request req;
        req.method = "POST";
        req.path = "/api/v1/conversations/" + created_conv_id + "/participants";
        req.path_params["id"] = created_conv_id;
        req.set_header("Content-Type", "application/json");
        req.body = nlohmann::json({{"participant_user_id", k_user_david}}).dump();

        httplib::Response res;
        proxy_handler_->handle_add_participant(req, res, auth_ctx);

        EXPECT_EQ(res.status, 200);
        auto body = nlohmann::json::parse(res.body);
        EXPECT_EQ(body["total_participants"], 4);
    }

    // 4. PATCH /api/v1/conversations/:id/metadata through Gateway Proxy Handler
    {
        httplib::Request req;
        req.method = "PATCH";
        req.path = "/api/v1/conversations/" + created_conv_id + "/metadata";
        req.path_params["id"] = created_conv_id;
        req.set_header("Content-Type", "application/json");
        req.body = nlohmann::json({{"title", "Gateway E2E Renamed"}}).dump();

        httplib::Response res;
        proxy_handler_->handle_update_metadata(req, res, auth_ctx);

        EXPECT_EQ(res.status, 200);
        auto body = nlohmann::json::parse(res.body);
        EXPECT_EQ(body["conversation"]["title"], "Gateway E2E Renamed");
    }
}

} // namespace
} // namespace securecloud::messaging
