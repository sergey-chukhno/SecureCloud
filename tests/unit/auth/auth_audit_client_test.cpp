#include "auth/audit/auth_audit_client.hpp"
#include "auth/domain/uuid.hpp"

#include <chrono>
#include <filesystem>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace securecloud::auth::audit::test {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;

class MockAuditIngestionStub : public ::securecloud::audit::v1::AuditIngestionService::StubInterface {
  public:
    MOCK_METHOD(grpc::Status, SubmitAuditEvent,
                (grpc::ClientContext * context, const ::securecloud::audit::v1::SubmitAuditEventRequest& request,
                 ::securecloud::audit::v1::SubmitAuditEventResponse* response),
                (override));

    MOCK_METHOD(grpc::Status, BatchSubmitAuditEvents,
                (grpc::ClientContext * context, const ::securecloud::audit::v1::BatchSubmitAuditEventsRequest& request,
                 ::securecloud::audit::v1::BatchSubmitAuditEventsResponse* response),
                (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<::securecloud::audit::v1::SubmitAuditEventResponse>*,
                AsyncSubmitAuditEventRaw,
                (grpc::ClientContext * context, const ::securecloud::audit::v1::SubmitAuditEventRequest& request,
                 grpc::CompletionQueue* cq),
                (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<::securecloud::audit::v1::SubmitAuditEventResponse>*,
                PrepareAsyncSubmitAuditEventRaw,
                (grpc::ClientContext * context, const ::securecloud::audit::v1::SubmitAuditEventRequest& request,
                 grpc::CompletionQueue* cq),
                (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<::securecloud::audit::v1::BatchSubmitAuditEventsResponse>*,
                AsyncBatchSubmitAuditEventsRaw,
                (grpc::ClientContext * context, const ::securecloud::audit::v1::BatchSubmitAuditEventsRequest& request,
                 grpc::CompletionQueue* cq),
                (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<::securecloud::audit::v1::BatchSubmitAuditEventsResponse>*,
                PrepareAsyncBatchSubmitAuditEventsRaw,
                (grpc::ClientContext * context, const ::securecloud::audit::v1::BatchSubmitAuditEventsRequest& request,
                 grpc::CompletionQueue* cq),
                (override));
};

::securecloud::audit::v1::AuditEventProto make_proto_event() {
    ::securecloud::audit::v1::AuditEventProto ev;
    ev.set_event_id(domain::Uuid::generate_v7().to_string());
    ev.set_occurred_at_ms(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    ev.set_event_type("auth.login.succeeded");
    ev.set_severity(::securecloud::audit::v1::SEVERITY_INFO);
    ev.set_producer_service(::securecloud::audit::v1::PRODUCER_SERVICE_AUTH);
    ev.set_producer_instance("auth-1");
    ev.set_actor_type(::securecloud::audit::v1::ACTOR_TYPE_USER);
    ev.set_actor_id(domain::Uuid::generate_v7().to_string());
    ev.set_target_type(::securecloud::audit::v1::TARGET_TYPE_USER);
    ev.set_target_id(domain::Uuid::generate_v7().to_string());
    ev.set_correlation_id(ev.event_id());
    return ev;
}

TEST(AuthAuditClientTest, Constructor_FailsClosedOnMissingMtlsCredentialsOrInvalidConfig) {
    AuthAuditClientConfig empty_endpoint;
    empty_endpoint.target_endpoint = "";
    EXPECT_THROW(AuthAuditClient{empty_endpoint}, std::invalid_argument);

    AuthAuditClientConfig missing_tls;
    missing_tls.target_endpoint = "audit:50055";
    missing_tls.timeout = std::chrono::milliseconds(1000);
    missing_tls.tls_credentials.ca_cert_path = "/nonexistent/ca.crt";
    missing_tls.tls_credentials.service_cert_path = "/nonexistent/auth.crt";
    missing_tls.tls_credentials.service_key_path = "/nonexistent/auth.key";

    EXPECT_THROW(AuthAuditClient{missing_tls}, std::runtime_error);

    auto stub = std::make_shared<NiceMock<MockAuditIngestionStub>>();
    AuthAuditClientConfig zero_timeout;
    zero_timeout.timeout = std::chrono::milliseconds(0);
    EXPECT_THROW((AuthAuditClient{zero_timeout, stub}), std::invalid_argument);
    EXPECT_THROW((AuthAuditClient{AuthAuditClientConfig{}, nullptr}), std::invalid_argument);
}

TEST(AuthAuditClientTest, SubmitBatch_EmptyVector_ReturnsSuccessWithoutRpc) {
    auto stub = std::make_shared<NiceMock<MockAuditIngestionStub>>();
    EXPECT_CALL(*stub, BatchSubmitAuditEvents(_, _, _)).Times(0);

    AuthAuditClient client(AuthAuditClientConfig{}, stub);
    const auto result = client.submit_batch({});

    EXPECT_TRUE(result.rpc_success);
    EXPECT_TRUE(result.status.ok());
    EXPECT_EQ(result.accepted_count, 0u);
    EXPECT_EQ(result.rejected_count, 0u);
}

TEST(AuthAuditClientTest, SubmitBatch_EnforcesTimeoutDeadlineAndMapsPartialRejections) {
    auto stub = std::make_shared<NiceMock<MockAuditIngestionStub>>();

    AuthAuditClientConfig cfg;
    cfg.timeout = std::chrono::milliseconds(1500);

    const auto ev1 = make_proto_event();
    const auto ev2 = make_proto_event();

    ::securecloud::audit::v1::BatchSubmitAuditEventsResponse mock_resp;
    mock_resp.set_accepted_count(1);
    mock_resp.set_rejected_count(1);
    mock_resp.add_rejected_event_ids(ev2.event_id());

    const auto before_call = std::chrono::system_clock::now();
    EXPECT_CALL(*stub, BatchSubmitAuditEvents(_, _, _))
        .WillOnce(DoAll(
            Invoke([&](grpc::ClientContext* ctx, const ::securecloud::audit::v1::BatchSubmitAuditEventsRequest& req,
                       ::securecloud::audit::v1::BatchSubmitAuditEventsResponse*) {
                EXPECT_EQ(req.events_size(), 2);
                const auto deadline = ctx->deadline();
                EXPECT_GE(deadline, before_call + std::chrono::milliseconds(1000));
                EXPECT_LE(deadline, before_call + std::chrono::milliseconds(2500));
            }),
            SetArgPointee<2>(mock_resp), Return(grpc::Status::OK)));

    AuthAuditClient client(cfg, stub);
    const auto result = client.submit_batch({ev1, ev2});

    EXPECT_TRUE(result.rpc_success);
    EXPECT_EQ(result.accepted_count, 1u);
    EXPECT_EQ(result.rejected_count, 1u);
    ASSERT_EQ(result.rejected_event_ids.size(), 1u);
    EXPECT_EQ(result.rejected_event_ids[0], ev2.event_id());
}

TEST(AuthAuditClientTest, SubmitBatch_PropagatesGrpcFailureStatus) {
    auto stub = std::make_shared<NiceMock<MockAuditIngestionStub>>();
    EXPECT_CALL(*stub, BatchSubmitAuditEvents(_, _, _))
        .WillOnce(Return(grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit service down")));

    AuthAuditClient client(AuthAuditClientConfig{}, stub);
    const auto result = client.submit_batch({make_proto_event()});

    EXPECT_FALSE(result.rpc_success);
    EXPECT_EQ(result.status.error_code(), grpc::StatusCode::UNAVAILABLE);
}

#ifdef SECURECLOUD_DEV_PKI_DIR
TEST(AuthAuditClientTest, MtlsEndToEnd_VerifiesAuditPeerSanAndDeliversBatch) {
    const std::filesystem::path pki_dir{SECURECLOUD_DEV_PKI_DIR};
    const auto ca_path = pki_dir / "ca.crt";
    const auto auth_cert = pki_dir / "auth.crt";
    const auto auth_key = pki_dir / "auth.key";
    const auto audit_cert = pki_dir / "audit.crt";
    const auto audit_key = pki_dir / "audit.key";

    if (!std::filesystem::exists(ca_path) || !std::filesystem::exists(auth_cert) ||
        !std::filesystem::exists(audit_cert)) {
        GTEST_SKIP() << "Dev PKI certificates not found at " << pki_dir;
    }

    class FakeAuditIngestionService final : public ::securecloud::audit::v1::AuditIngestionService::Service {
      public:
        grpc::Status
        BatchSubmitAuditEvents(grpc::ServerContext* context,
                               const ::securecloud::audit::v1::BatchSubmitAuditEventsRequest* request,
                               ::securecloud::audit::v1::BatchSubmitAuditEventsResponse* response) override {
            if (!common::security::verify_peer_service_identity(*context->auth_context(), "auth")) {
                return grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "Expected auth peer SAN");
            }
            response->set_accepted_count(static_cast<uint32_t>(request->events_size()));
            response->set_rejected_count(0);
            return grpc::Status::OK;
        }
    };

    FakeAuditIngestionService service;
    auto server_creds =
        common::security::MtlsCredentialLoader::create_server_credentials({ca_path, audit_cert, audit_key});

    int bound_port = 0;
    grpc::ServerBuilder builder;
    builder.AddListeningPort("127.0.0.1:0", server_creds, &bound_port);
    builder.RegisterService(&service);
    auto server = builder.BuildAndStart();
    ASSERT_NE(server, nullptr);
    ASSERT_GT(bound_port, 0);

    AuthAuditClientConfig client_cfg;
    client_cfg.target_endpoint = "127.0.0.1:" + std::to_string(bound_port);
    client_cfg.timeout = std::chrono::milliseconds(3000);
    client_cfg.tls_credentials = {ca_path, auth_cert, auth_key};
    client_cfg.expected_peer_san = "audit";

    AuthAuditClient client(client_cfg);
    const auto result = client.submit_batch({make_proto_event()});

    server->Shutdown();

    EXPECT_TRUE(result.rpc_success) << result.status.error_message();
    EXPECT_EQ(result.accepted_count, 1u);
    EXPECT_EQ(result.rejected_count, 0u);
}
#endif

} // namespace
} // namespace securecloud::auth::audit::test
