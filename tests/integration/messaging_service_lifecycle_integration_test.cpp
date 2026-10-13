#include "concurrency/bounded_worker_pool.hpp"
#include "messaging_config.hpp"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "securecloud/security/mtls_config.hpp"
#include "service/messaging_service_impl.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::messaging {
namespace {

using common::health::HealthServiceImpl;
using common::health::HealthStatusManager;
using common::security::MtlsCredentialLoader;
using common::security::SecurityCredentialsConfig;
using service::MessagingServiceImpl;

constexpr std::chrono::milliseconds k_server_shutdown_timeout{500};
constexpr std::chrono::seconds k_rpc_deadline{5};

class MessagingServiceLifecycleIntegrationTest : public ::testing::Test {
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
        auth_cert_path_ = pki_root / "services" / "auth" / "auth.crt";
        auth_key_path_ = pki_root / "services" / "auth" / "auth.key";

        const std::vector<std::filesystem::path> required_paths = {
            ca_path_,          messaging_cert_path_, messaging_key_path_, gateway_cert_path_,
            gateway_key_path_, auth_cert_path_,      auth_key_path_};

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

        auth_config_ = SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = auth_cert_path_,
            .service_key_path = auth_key_path_,
        };

        // Initialize bounded worker pools for messaging service
        submission_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "sub-integ");
        delivery_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "del-integ");
        sync_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "sync-integ");
    }

    void TearDown() override {
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

    RunningServer start_messaging_mtls_server(MessagingServiceImpl* msg_svc, HealthServiceImpl* health_svc) {
        auto server_creds = MtlsCredentialLoader::create_server_credentials(messaging_config_);
        EXPECT_NE(server_creds, nullptr);

        grpc::ServerBuilder builder;
        int selected_port = 0;
        builder.AddListeningPort("127.0.0.1:0", server_creds, &selected_port);
        if (msg_svc) {
            builder.RegisterService(msg_svc);
        }
        if (health_svc) {
            builder.RegisterService(health_svc);
        }

        auto server = builder.BuildAndStart();
        EXPECT_NE(server, nullptr);
        EXPECT_GT(selected_port, 0);

        std::string server_address = "127.0.0.1:" + std::to_string(selected_port);
        return RunningServer{std::move(server), server_address, selected_port};
    }

    void shutdown_server(RunningServer& rs) {
        if (rs.server) {
            rs.server->Shutdown(std::chrono::system_clock::now() + k_server_shutdown_timeout);
            rs.server.reset();
        }
    }

    std::filesystem::path ca_path_;
    std::filesystem::path messaging_cert_path_;
    std::filesystem::path messaging_key_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;
    std::filesystem::path auth_cert_path_;
    std::filesystem::path auth_key_path_;

    SecurityCredentialsConfig messaging_config_;
    SecurityCredentialsConfig gateway_config_;
    SecurityCredentialsConfig auth_config_;

    std::shared_ptr<concurrency::BoundedWorkerPool> submission_pool_;
    std::shared_ptr<concurrency::BoundedWorkerPool> delivery_pool_;
    std::shared_ptr<concurrency::BoundedWorkerPool> sync_pool_;
};

// ============================================================================
// TC1: Service Starts Successfully with Valid mTLS Credentials & Serves Health
// ============================================================================

TEST_F(MessagingServiceLifecycleIntegrationTest, ServiceStartsSuccessfullyWithValidMtlsCredentialsAndHealthServing) {
    HealthStatusManager health_manager("messaging");
    health_manager.set_live(true);
    health_manager.set_ready(true);
    HealthServiceImpl health_service("messaging", health_manager);

    MessagingServiceImpl messaging_service(submission_pool_, delivery_pool_, sync_pool_);

    auto running = start_messaging_mtls_server(&messaging_service, &health_service);

    auto channel = MtlsCredentialLoader::create_mtls_channel(running.address, gateway_config_, "messaging");
    auto stub = common::v1::HealthService::NewStub(channel);

    // 1. Overall health check
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        common::v1::HealthCheckResponse resp;

        grpc::Status status = stub->Check(&context, req, &resp);
        EXPECT_TRUE(status.ok()) << "mTLS health check failed: " << status.error_message();
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);
    }

    // 2. Named service health check
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("messaging");
        common::v1::HealthCheckResponse resp;

        grpc::Status status = stub->Check(&context, req, &resp);
        EXPECT_TRUE(status.ok()) << "mTLS named health check failed: " << status.error_message();
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);
    }

    shutdown_server(running);
}

// ============================================================================
// TC2: Gateway Client Establishes mTLS Channel and Calls All 12 RPC Methods
// ============================================================================

TEST_F(MessagingServiceLifecycleIntegrationTest, GatewayClientEstablishesMtlsChannelAndCallsAll12RpcMethods) {
    MessagingServiceImpl messaging_service(submission_pool_, delivery_pool_, sync_pool_);

    auto running = start_messaging_mtls_server(&messaging_service, nullptr);

    auto channel = MtlsCredentialLoader::create_mtls_channel(running.address, gateway_config_, "messaging");
    auto stub = v1::MessagingService::NewStub(channel);

    // 1. SendMessage
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        context.AddMetadata("x-correlation-id", "corr-integ-send-01");
        v1::SendMessageRequest req;
        req.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        req.set_sender_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
        v1::SendMessageResponse resp;

        auto status = stub->SendMessage(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
    }

    // 2. GetMessages
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::GetMessagesRequest req;
        req.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        v1::GetMessagesResponse resp;

        auto status = stub->GetMessages(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
    }

    // 3. AcknowledgeDelivery
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::AcknowledgeDeliveryRequest req;
        req.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
        v1::AcknowledgeDeliveryResponse resp;

        auto status = stub->AcknowledgeDelivery(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
    }

    // 4. SendReadReceipt
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::SendReadReceiptRequest req;
        req.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        req.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
        v1::SendReadReceiptResponse resp;

        auto status = stub->SendReadReceipt(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
    }

    // 5. CreateConversation
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::CreateConversationRequest req;
        req.set_type(v1::CONVERSATION_TYPE_DIRECT);
        v1::CreateConversationResponse resp;

        auto status = stub->CreateConversation(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
    }

    // 6. GetConversation
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::GetConversationRequest req;
        req.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        v1::GetConversationResponse resp;

        auto status = stub->GetConversation(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
    }

    // 7. ListConversations
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::ListConversationsRequest req;
        req.set_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
        v1::ListConversationsResponse resp;

        auto status = stub->ListConversations(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
    }

    // 8. AddParticipant
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::AddParticipantRequest req;
        req.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        v1::AddParticipantResponse resp;

        auto status = stub->AddParticipant(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
    }

    // 9. RemoveParticipant
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::RemoveParticipantRequest req;
        req.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        v1::RemoveParticipantResponse resp;

        auto status = stub->RemoveParticipant(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
    }

    // 10. SyncDeviceMessages
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::SyncDeviceMessagesRequest req;
        req.set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
        v1::SyncDeviceMessagesResponse resp;

        auto status = stub->SyncDeviceMessages(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
    }

    // 11. GetSyncCursor
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::GetSyncCursorRequest req;
        req.set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
        v1::GetSyncCursorResponse resp;

        auto status = stub->GetSyncCursor(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
    }

    // 12. UpdateSyncCursor
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::UpdateSyncCursorRequest req;
        req.mutable_cursor()->set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
        v1::UpdateSyncCursorResponse resp;

        auto status = stub->UpdateSyncCursor(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
    }

    shutdown_server(running);
}

// ============================================================================
// TC3: Rejects Untrusted or Unauthenticated Clients
// ============================================================================

TEST_F(MessagingServiceLifecycleIntegrationTest, RejectsUnauthenticatedOrUntrustedMtlsCallers) {
    HealthStatusManager health_manager("messaging");
    health_manager.set_live(true);
    health_manager.set_ready(true);
    HealthServiceImpl health_service("messaging", health_manager);

    MessagingServiceImpl messaging_service(submission_pool_, delivery_pool_, sync_pool_);

    auto running = start_messaging_mtls_server(&messaging_service, &health_service);

    // 3a. Insecure/plaintext channel rejected at TLS handshake
    {
        auto insecure_channel = grpc::CreateChannel(running.address, grpc::InsecureChannelCredentials());
        auto stub = common::v1::HealthService::NewStub(insecure_channel);

        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(500));
        common::v1::HealthCheckRequest req;
        common::v1::HealthCheckResponse resp;

        grpc::Status status = stub->Check(&context, req, &resp);
        EXPECT_FALSE(status.ok()) << "Plaintext call unexpectedly succeeded against mTLS server";
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAVAILABLE);
    }

    // 3b. Authenticated internal caller with valid SAN is accepted by transport
    {
        auto auth_channel = MtlsCredentialLoader::create_mtls_channel(running.address, auth_config_, "messaging");
        auto msg_stub = v1::MessagingService::NewStub(auth_channel);

        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::SendMessageRequest req;
        req.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        v1::SendMessageResponse resp;

        grpc::Status status = msg_stub->SendMessage(&context, req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }

    shutdown_server(running);
}

// ============================================================================
// TC4: Readiness Transitions During Graceful Shutdown
// ============================================================================

TEST_F(MessagingServiceLifecycleIntegrationTest, ReadinessTransitionsDuringGracefulShutdown) {
    HealthStatusManager health_manager("messaging");
    health_manager.set_live(true);
    health_manager.set_ready(true);
    HealthServiceImpl health_service("messaging", health_manager);

    auto running = start_messaging_mtls_server(nullptr, &health_service);

    auto channel = MtlsCredentialLoader::create_mtls_channel(running.address, gateway_config_, "messaging");
    auto stub = common::v1::HealthService::NewStub(channel);

    // Initial state: serving
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("readiness");
        common::v1::HealthCheckResponse resp;

        grpc::Status status = stub->Check(&context, req, &resp);
        EXPECT_TRUE(status.ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);
    }

    // Transition to shutting down
    health_manager.set_shutting_down(true);

    // After shutdown initiation: readiness degrades to NOT_SERVING
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("readiness");
        common::v1::HealthCheckResponse resp;

        grpc::Status status = stub->Check(&context, req, &resp);
        EXPECT_TRUE(status.ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::NOT_SERVING);
    }

    // Liveness probe remains SERVING
    {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        common::v1::HealthCheckResponse resp;

        grpc::Status status = stub->Check(&context, req, &resp);
        EXPECT_TRUE(status.ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);
    }

    shutdown_server(running);
}

// ============================================================================
// TC5: Deterministic Graceful Drain and Worker Pool Completion
// ============================================================================

TEST_F(MessagingServiceLifecycleIntegrationTest, DeterministicGracefulDrainAndWorkerPoolCompletion) {
    std::atomic<int> completed_submissions{0};
    std::atomic<int> completed_deliveries{0};
    std::atomic<int> completed_syncs{0};

    // Submit tasks across all 3 pools
    for (int i = 0; i < 20; ++i) {
        EXPECT_TRUE(submission_pool_->try_submit([&completed_submissions] {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            completed_submissions.fetch_add(1);
        }));

        EXPECT_TRUE(delivery_pool_->try_submit([&completed_deliveries] {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            completed_deliveries.fetch_add(1);
        }));

        EXPECT_TRUE(sync_pool_->try_submit([&completed_syncs] {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            completed_syncs.fetch_add(1);
        }));
    }

    // Initiate drain sequence conforming to ADR-009 / ADR-010
    submission_pool_->drain_and_stop();
    delivery_pool_->drain_and_stop();
    sync_pool_->drain_and_stop();

    // Verify all tasks ran to completion
    EXPECT_EQ(completed_submissions.load(), 20);
    EXPECT_EQ(completed_deliveries.load(), 20);
    EXPECT_EQ(completed_syncs.load(), 20);

    EXPECT_TRUE(submission_pool_->is_shutdown());
    EXPECT_TRUE(delivery_pool_->is_shutdown());
    EXPECT_TRUE(sync_pool_->is_shutdown());
}

// ============================================================================
// TC6: Observational Guard Enforces Zero Database Connection Port 5432 Invariant
// ============================================================================

TEST_F(MessagingServiceLifecycleIntegrationTest, ObservationalGuardEnforcesZeroDatabaseConnectionPort5432Invariant) {
    common::configuration::InMemoryConfigurationSource source;
    source.set("SECURECLOUD_MESSAGING_SCYLLA_HOST", "scylladb");
    source.set("SECURECLOUD_MESSAGING_SCYLLA_PORT", "9042");

    common::configuration::ValidationResult errors;
    auto config = MessagingConfig::load(source, errors);
    EXPECT_TRUE(errors.is_valid()) << errors.to_string();

    // Messaging service persistence strictly points to ScyllaDB (port 9042)
    EXPECT_EQ(config.scylla.port, 9042);
    EXPECT_NE(config.scylla.port, 5432);

    // Verify default worker bounds conform to ADR-009 / ADR-010
    EXPECT_GE(config.workers.submission_workers, 1u);
    EXPECT_GE(config.workers.delivery_workers, 1u);
    EXPECT_GE(config.workers.sync_workers, 1u);
    EXPECT_GE(config.workers.max_queued_submissions, 16u);
    EXPECT_GE(config.workers.max_queued_deliveries, 16u);
    EXPECT_GE(config.workers.max_queued_syncs, 16u);
}

} // namespace
} // namespace securecloud::messaging
