#include "concurrency/bounded_worker_pool.hpp"
#include "messaging_config.hpp"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "securecloud/security/mtls_config.hpp"
#include "service/messaging_service_impl.hpp"

#include <filesystem>
#include <fstream>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::service {
namespace {

// ============================================================================
// Mock AuthContext for testing peer SAN extraction and verification
// ============================================================================

class TestAuthPropertyIterator : public grpc::AuthPropertyIterator {
  public:
    TestAuthPropertyIterator() = default;
};

class TestAuthContext : public grpc::AuthContext {
  public:
    explicit TestAuthContext(bool is_authenticated, std::vector<std::pair<std::string, std::string>> properties = {})
        : is_authenticated_(is_authenticated), properties_(std::move(properties)) {}

    [[nodiscard]] bool IsPeerAuthenticated() const override { return is_authenticated_; }

    [[nodiscard]] std::string GetPeerIdentityPropertyName() const override { return "x509_subject_alternative_name"; }

    [[nodiscard]] std::vector<grpc::string_ref> GetPeerIdentity() const override {
        std::vector<grpc::string_ref> result;
        for (const auto& [key, value] : properties_) {
            if (key == "x509_subject_alternative_name") {
                result.emplace_back(value.data(), value.size());
            }
        }
        return result;
    }

    [[nodiscard]] std::vector<grpc::string_ref> FindPropertyValues(const std::string& name) const override {
        std::vector<grpc::string_ref> result;
        for (const auto& [key, value] : properties_) {
            if (key == name) {
                result.emplace_back(value.data(), value.size());
            }
        }
        return result;
    }

    [[nodiscard]] grpc::AuthPropertyIterator begin() const override { return TestAuthPropertyIterator{}; }
    [[nodiscard]] grpc::AuthPropertyIterator end() const override { return TestAuthPropertyIterator{}; }
    void AddProperty(const std::string& /*name*/, const grpc::string_ref& /*value*/) override {}
    bool SetPeerIdentityPropertyName(const std::string& /*name*/) override { return false; }

  private:
    bool is_authenticated_;
    std::vector<std::pair<std::string, std::string>> properties_;
};

// ============================================================================
// In-Process gRPC Server & Client Fixture
// ============================================================================

class MessagingServiceInProcessTest : public ::testing::Test {
  protected:
    void SetUp() override {
        service_impl_ = std::make_unique<MessagingServiceImpl>();

        grpc::ServerBuilder builder;
        builder.RegisterService(service_impl_.get());
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);

        channel_ = server_->InProcessChannel(grpc::ChannelArguments{});
        ASSERT_NE(channel_, nullptr);

        stub_ = v1::MessagingService::NewStub(channel_);
        ASSERT_NE(stub_, nullptr);
    }

    void TearDown() override {
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    std::unique_ptr<MessagingServiceImpl> service_impl_;
    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::MessagingService::Stub> stub_;
};

// ============================================================================
// RPC In-Process Tests: All 12 RPCs Must Return UNIMPLEMENTED Deterministically
// ============================================================================

TEST_F(MessagingServiceInProcessTest, SendMessageReturnsUnimplemented) {
    grpc::ClientContext context;
    context.AddMetadata("x-correlation-id", "corr-send-msg-001");

    v1::SendMessageRequest request;
    request.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    request.set_sender_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    request.set_priority(v1::MESSAGE_PRIORITY_NORMAL);
    request.set_client_idempotency_token("idemp-token-123");
    request.set_expires_at_unix_ms(1760000000000);

    v1::SendMessageResponse response;
    auto status = stub_->SendMessage(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

TEST_F(MessagingServiceInProcessTest, GetMessagesReturnsUnimplemented) {
    grpc::ClientContext context;
    context.AddMetadata("x-request-id", "req-get-msg-002");

    v1::GetMessagesRequest request;
    request.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    request.set_recipient_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36004");
    request.set_since_sequence(0);
    request.set_max_results(50);

    v1::GetMessagesResponse response;
    auto status = stub_->GetMessages(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

TEST_F(MessagingServiceInProcessTest, AcknowledgeDeliveryReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::AcknowledgeDeliveryRequest request;
    request.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    request.set_recipient_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36004");
    request.set_delivered_at_unix_ms(1760000000000);

    v1::AcknowledgeDeliveryResponse response;
    auto status = stub_->AcknowledgeDelivery(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

TEST_F(MessagingServiceInProcessTest, SendReadReceiptReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::SendReadReceiptRequest request;
    request.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    request.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    request.set_reader_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36004");
    request.set_read_at_unix_ms(1760000000000);

    v1::SendReadReceiptResponse response;
    auto status = stub_->SendReadReceipt(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

TEST_F(MessagingServiceInProcessTest, CreateConversationReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::CreateConversationRequest request;
    request.set_type(v1::CONVERSATION_TYPE_DIRECT);
    request.set_title("Direct Chat");
    request.add_participant_user_ids("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    request.add_participant_user_ids("0191ec4d-91b4-7b4d-b6a9-8e41e3d36005");

    v1::CreateConversationResponse response;
    auto status = stub_->CreateConversation(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

TEST_F(MessagingServiceInProcessTest, GetConversationReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::GetConversationRequest request;
    request.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");

    v1::GetConversationResponse response;
    auto status = stub_->GetConversation(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

TEST_F(MessagingServiceInProcessTest, ListConversationsReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::ListConversationsRequest request;
    request.set_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    request.set_max_results(20);

    v1::ListConversationsResponse response;
    auto status = stub_->ListConversations(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

TEST_F(MessagingServiceInProcessTest, AddParticipantReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::AddParticipantRequest request;
    request.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    request.set_participant_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36006");

    v1::AddParticipantResponse response;
    auto status = stub_->AddParticipant(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

TEST_F(MessagingServiceInProcessTest, RemoveParticipantReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::RemoveParticipantRequest request;
    request.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    request.set_participant_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36006");

    v1::RemoveParticipantResponse response;
    auto status = stub_->RemoveParticipant(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

TEST_F(MessagingServiceInProcessTest, SyncDeviceMessagesReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::SyncDeviceMessagesRequest request;
    request.set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    request.set_since_sequence(0);
    request.set_max_messages(100);

    v1::SyncDeviceMessagesResponse response;
    auto status = stub_->SyncDeviceMessages(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

TEST_F(MessagingServiceInProcessTest, GetSyncCursorReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::GetSyncCursorRequest request;
    request.set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");

    v1::GetSyncCursorResponse response;
    auto status = stub_->GetSyncCursor(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

TEST_F(MessagingServiceInProcessTest, UpdateSyncCursorReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::UpdateSyncCursorRequest request;
    auto* cursor = request.mutable_cursor();
    cursor->set_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    cursor->set_last_delivered_sequence(42);
    cursor->set_last_sync_timestamp_unix_ms(1760000000000);

    v1::UpdateSyncCursorResponse response;
    auto status = stub_->UpdateSyncCursor(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);
}

// ============================================================================
// Correlation ID Extraction Unit Tests
// ============================================================================

TEST(MessagingServiceImplTest, ExtractCorrelationIdFromNullContextReturnsEmpty) {
    EXPECT_EQ(MessagingServiceImpl::extract_correlation_id(nullptr), "");
}

TEST(MessagingServiceImplTest, ExtractCorrelationIdFromEmptyContextReturnsEmpty) {
    grpc::ServerContext context;
    EXPECT_EQ(MessagingServiceImpl::extract_correlation_id(&context), "");
}

// ============================================================================
// Peer SAN Identity Extraction & Authorization Tests
// ============================================================================

TEST(MessagingServiceImplAuthTest, ExtractPeerIdentityNullContextReturnsAnonymous) {
    EXPECT_EQ(MessagingServiceImpl::extract_peer_identity(static_cast<const grpc::ServerContext*>(nullptr)),
              "anonymous");
    EXPECT_EQ(MessagingServiceImpl::extract_peer_identity(static_cast<const grpc::AuthContext*>(nullptr)), "anonymous");
    EXPECT_FALSE(MessagingServiceImpl::is_authorized_peer(static_cast<const grpc::ServerContext*>(nullptr)));
    EXPECT_FALSE(MessagingServiceImpl::is_authorized_peer(static_cast<const grpc::AuthContext*>(nullptr)));
}

TEST(MessagingServiceImplAuthTest, ExtractPeerIdentityUnauthenticatedReturnsAnonymous) {
    TestAuthContext unauth_ctx(false);
    EXPECT_EQ(MessagingServiceImpl::extract_peer_identity(&unauth_ctx), "anonymous");
    EXPECT_FALSE(MessagingServiceImpl::is_authorized_peer(&unauth_ctx));
}

TEST(MessagingServiceImplAuthTest, ExtractsGatewayPeerIdentityAndAuthorizes) {
    TestAuthContext auth_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});
    EXPECT_EQ(MessagingServiceImpl::extract_peer_identity(&auth_ctx), "gateway");
    EXPECT_TRUE(MessagingServiceImpl::is_authorized_peer(&auth_ctx));
}

TEST(MessagingServiceImplAuthTest, ExtractsRawGatewayPeerIdentityAndAuthorizes) {
    TestAuthContext auth_ctx(true, {{"x509_subject_alternative_name", "gateway"}});
    EXPECT_EQ(MessagingServiceImpl::extract_peer_identity(&auth_ctx), "gateway");
    EXPECT_TRUE(MessagingServiceImpl::is_authorized_peer(&auth_ctx));
}

TEST(MessagingServiceImplAuthTest, ExtractsAuthAndMessagingPeersAndAuthorizes) {
    TestAuthContext auth_peer_ctx(true, {{"x509_subject_alternative_name", "DNS:auth"}});
    EXPECT_EQ(MessagingServiceImpl::extract_peer_identity(&auth_peer_ctx), "auth");
    EXPECT_TRUE(MessagingServiceImpl::is_authorized_peer(&auth_peer_ctx));

    TestAuthContext msg_peer_ctx(true, {{"x509_subject_alternative_name", "DNS:messaging"}});
    EXPECT_EQ(MessagingServiceImpl::extract_peer_identity(&msg_peer_ctx), "messaging");
    EXPECT_TRUE(MessagingServiceImpl::is_authorized_peer(&msg_peer_ctx));

    TestAuthContext files_peer_ctx(true, {{"x509_subject_alternative_name", "DNS:files"}});
    EXPECT_EQ(MessagingServiceImpl::extract_peer_identity(&files_peer_ctx), "files");
    EXPECT_TRUE(MessagingServiceImpl::is_authorized_peer(&files_peer_ctx));
}

TEST(MessagingServiceImplAuthTest, RejectsUnknownOrUnauthorizedPeerIdentity) {
    TestAuthContext rogue_ctx(true, {{"x509_subject_alternative_name", "DNS:untrusted-service"}});
    EXPECT_EQ(MessagingServiceImpl::extract_peer_identity(&rogue_ctx), "untrusted-service");
    EXPECT_FALSE(MessagingServiceImpl::is_authorized_peer(&rogue_ctx));
}

TEST(MessagingServiceImplAuthTest, RejectsMissingSanIdentity) {
    TestAuthContext no_san_ctx(true, {{"x509_common_name", "messaging"}});
    EXPECT_EQ(MessagingServiceImpl::extract_peer_identity(&no_san_ctx), "unknown_peer");
    EXPECT_FALSE(MessagingServiceImpl::is_authorized_peer(&no_san_ctx));
}

// ============================================================================
// Dependency Injection Verification Test
// ============================================================================

TEST(MessagingServiceImplDependencyTest, InjectsWorkerPoolDependencies) {
    WorkerPoolConfig config{
        .submission_workers = 2,
        .delivery_workers = 4,
        .sync_workers = 2,
        .max_queued_submissions = 16,
        .max_queued_deliveries = 32,
        .max_queued_syncs = 16,
    };

    auto sub_pool = std::make_shared<concurrency::BoundedWorkerPool>(config.submission_workers,
                                                                     config.max_queued_submissions, "test-sub");
    auto del_pool = std::make_shared<concurrency::BoundedWorkerPool>(config.delivery_workers,
                                                                     config.max_queued_deliveries, "test-del");
    auto sync_pool =
        std::make_shared<concurrency::BoundedWorkerPool>(config.sync_workers, config.max_queued_syncs, "test-sync");

    MessagingServiceImpl service(sub_pool, del_pool, sync_pool);

    EXPECT_EQ(service.submission_pool(), sub_pool);
    EXPECT_EQ(service.delivery_pool(), del_pool);
    EXPECT_EQ(service.sync_pool(), sync_pool);

    // Default construction leaves them nullptr
    MessagingServiceImpl default_service;
    EXPECT_EQ(default_service.submission_pool(), nullptr);
    EXPECT_EQ(default_service.delivery_pool(), nullptr);
    EXPECT_EQ(default_service.sync_pool(), nullptr);

    sub_pool->drain_and_stop();
    del_pool->drain_and_stop();
    sync_pool->drain_and_stop();
}

// ============================================================================
// mTLS Server Credentials Loader Verification Test
// ============================================================================

TEST(MessagingServiceMtlsTest, CreateServerCredentialsSucceedsForDevPkiOrMock) {
    std::filesystem::path ca_path = "deploy/dev-pki/ca/ca.crt";
    std::filesystem::path cert_path = "deploy/dev-pki/services/messaging/messaging.crt";
    std::filesystem::path key_path = "deploy/dev-pki/services/messaging/messaging.key";

    if (std::filesystem::exists(ca_path) && std::filesystem::exists(cert_path) && std::filesystem::exists(key_path)) {
        common::security::SecurityCredentialsConfig config{
            .ca_cert_path = ca_path,
            .service_cert_path = cert_path,
            .service_key_path = key_path,
        };
        auto server_creds = common::security::MtlsCredentialLoader::create_server_credentials(config);
        EXPECT_NE(server_creds, nullptr);
    } else {
        auto temp_dir = std::filesystem::temp_directory_path() / "msg_mtls_test";
        std::filesystem::create_directories(temp_dir);

        auto test_ca = temp_dir / "ca.crt";
        auto test_cert = temp_dir / "service.crt";
        auto test_key = temp_dir / "service.key";

        {
            std::ofstream(test_ca) << "-----BEGIN CERTIFICATE-----\nCA_TEST\n-----END CERTIFICATE-----\n";
            std::ofstream(test_cert) << "-----BEGIN CERTIFICATE-----\nCERT_TEST\n-----END CERTIFICATE-----\n";
            std::ofstream(test_key) << "-----BEGIN PRIVATE KEY-----\nKEY_TEST\n-----END PRIVATE KEY-----\n";
        }

        common::security::SecurityCredentialsConfig config{
            .ca_cert_path = test_ca,
            .service_cert_path = test_cert,
            .service_key_path = test_key,
        };
        auto server_creds = common::security::MtlsCredentialLoader::create_server_credentials(config);
        EXPECT_NE(server_creds, nullptr);

        std::filesystem::remove_all(temp_dir);
    }
}

TEST(MessagingServiceMtlsTest, CreateServerCredentialsFailsClosedForMissingFiles) {
    common::security::SecurityCredentialsConfig config{
        .ca_cert_path = "/nonexistent/ca.crt",
        .service_cert_path = "/nonexistent/messaging.crt",
        .service_key_path = "/nonexistent/messaging.key",
    };
    EXPECT_THROW(common::security::MtlsCredentialLoader::create_server_credentials(config), std::runtime_error);
}

} // namespace
} // namespace securecloud::messaging::service
