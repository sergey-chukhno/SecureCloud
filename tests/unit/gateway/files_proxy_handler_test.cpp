#include "grpc/files_client_interface.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/auth/request_context.hpp"
#include "http/proxy/files_proxy_handler.hpp"
#include "http/routing/router.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace securecloud::gateway::http {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

class MockFilesClient : public grpc::IFilesClient {
  public:
    MOCK_METHOD(grpc::Result<securecloud::files::v1::CreateFileUploadResponse>, create_file_upload,
                (const securecloud::files::v1::CreateFileUploadRequest& req, grpc::ClientCallContext& ctx), (override));

    MOCK_METHOD(grpc::Result<securecloud::files::v1::UploadChunkResponse>, upload_chunk,
                (const securecloud::files::v1::UploadChunkRequest& req, grpc::ClientCallContext& ctx), (override));

    MOCK_METHOD(grpc::Result<securecloud::files::v1::FinalizeFileUploadResponse>, finalize_file_upload,
                (const securecloud::files::v1::FinalizeFileUploadRequest& req, grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(grpc::Result<securecloud::files::v1::GetFileMetadataResponse>, get_file_metadata,
                (const securecloud::files::v1::GetFileMetadataRequest& req, grpc::ClientCallContext& ctx), (override));

    MOCK_METHOD(grpc::Result<securecloud::files::v1::DownloadChunkResponse>, download_chunk,
                (const securecloud::files::v1::DownloadChunkRequest& req, grpc::ClientCallContext& ctx), (override));

    MOCK_METHOD(grpc::Result<securecloud::files::v1::CancelFileUploadResponse>, cancel_file_upload,
                (const securecloud::files::v1::CancelFileUploadRequest& req, grpc::ClientCallContext& ctx), (override));

    MOCK_METHOD(grpc::Result<securecloud::files::v1::DeleteFileResponse>, delete_file,
                (const securecloud::files::v1::DeleteFileRequest& req, grpc::ClientCallContext& ctx), (override));
};

AuthenticatedContext make_test_context(const std::string& user_id = "user-123",
                                       const std::string& device_id = "dev-456") {
    return AuthenticatedContext(user_id, device_id, "session-test-1",
                                securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                {"files:read", "files:write"}, 1750000000000LL);
}

class FilesProxyHandlerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_client_ = std::make_shared<MockFilesClient>();
        bulkhead_manager_ = std::make_shared<BulkheadManager>(GatewayBulkheadConfig{
            .auth_max_concurrent = 10,
            .messaging_max_concurrent = 10,
            .files_max_concurrent = 5,
            .emergency_reserved_slots = 1,
        });
        deadline_manager_ = std::make_shared<DeadlineManager>(GatewayServiceDeadlinesConfig{
            .files_metadata_timeout_ms = 2000,
        });
        retry_policy_ = std::make_shared<RetryPolicy>();
        circuit_breaker_ = std::make_shared<CircuitBreaker>("files", GatewayCircuitBreakerConfig{
                                                                         .enabled = true,
                                                                         .failure_threshold = 2,
                                                                         .recovery_timeout_ms = 1000,
                                                                         .half_open_probe_count = 1,
                                                                     });

        streaming_config_.max_chunk_size_bytes = 1024 * 1024;        // 1 MiB
        streaming_config_.max_stream_buffer_bytes = 2 * 1024 * 1024; // 2 MiB
        streaming_config_.idle_timeout_ms = 10000;

        handler_ = std::make_shared<FilesProxyHandler>(mock_client_, deadline_manager_, retry_policy_,
                                                       bulkhead_manager_, circuit_breaker_, streaming_config_);
    }

    std::shared_ptr<MockFilesClient> mock_client_;
    std::shared_ptr<BulkheadManager> bulkhead_manager_;
    std::shared_ptr<DeadlineManager> deadline_manager_;
    std::shared_ptr<RetryPolicy> retry_policy_;
    std::shared_ptr<CircuitBreaker> circuit_breaker_;
    GatewayStreamingConfig streaming_config_;
    std::shared_ptr<FilesProxyHandler> handler_;
};

// 1. POST /api/v1/files/upload/init
TEST_F(FilesProxyHandlerTest, UploadInitSuccess) {
    securecloud::files::v1::CreateFileUploadResponse grpc_resp;
    grpc_resp.set_upload_id("u-uuid-1");
    grpc_resp.set_file_id("f-uuid-1");
    grpc_resp.set_status(securecloud::files::v1::TransferStatus::TRANSFER_STATUS_PENDING);
    grpc_resp.set_expires_at_unix_ms(1750000000000LL);

    EXPECT_CALL(*mock_client_, create_file_upload(_, _)).WillOnce(Return(grpc_resp));

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/files/upload/init";
    req.body =
        nlohmann::json{
            {"encrypted_size_bytes", 2048},
            {"expected_chunk_count", 1},
            {"encryption_version", "v1"},
        }
            .dump();

    httplib::Response res;
    handler_->handle_upload_init(req, res, make_test_context());

    EXPECT_EQ(res.status, 201);
    auto resp_json = nlohmann::json::parse(res.body);
    EXPECT_EQ(resp_json["upload_id"], "u-uuid-1");
    EXPECT_EQ(resp_json["file_id"], "f-uuid-1");
    EXPECT_EQ(resp_json["status"], "TRANSFER_STATUS_PENDING");
}

TEST_F(FilesProxyHandlerTest, UploadInitInvalidJsonRejected) {
    httplib::Request req;
    req.body = "{not-valid-json";
    httplib::Response res;

    handler_->handle_upload_init(req, res, make_test_context());
    EXPECT_EQ(res.status, 400);
}

TEST_F(FilesProxyHandlerTest, UploadInitMissingFieldsRejected) {
    httplib::Request req;
    req.body = nlohmann::json{{"expected_chunk_count", 1}}.dump(); // missing encrypted_size_bytes
    httplib::Response res;

    handler_->handle_upload_init(req, res, make_test_context());
    EXPECT_EQ(res.status, 400);
}

// 2. POST /api/v1/files/upload/chunk
TEST_F(FilesProxyHandlerTest, UploadChunkSuccess) {
    securecloud::files::v1::UploadChunkResponse grpc_resp;
    grpc_resp.set_upload_id("u-1");
    grpc_resp.set_chunk_index(0);
    grpc_resp.set_accepted(true);
    grpc_resp.set_received_sha256("hash-abc");

    EXPECT_CALL(*mock_client_, upload_chunk(_, _)).WillOnce(Return(grpc_resp));

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/files/upload/chunk";
    req.set_header("Upload-Id", "u-1");
    req.set_header("Chunk-Index", "0");
    req.body = "ciphertext-binary-chunk-data";

    httplib::Response res;
    handler_->handle_upload_chunk(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto resp_json = nlohmann::json::parse(res.body);
    EXPECT_TRUE(resp_json["accepted"]);
}

TEST_F(FilesProxyHandlerTest, UploadChunkMissingHeaderRejected) {
    httplib::Request req;
    req.set_header("Chunk-Index", "0");
    req.body = "chunk";
    httplib::Response res;

    handler_->handle_upload_chunk(req, res, make_test_context());
    EXPECT_EQ(res.status, 400);
}

TEST_F(FilesProxyHandlerTest, UploadChunkOversizedRejected) {
    httplib::Request req;
    req.set_header("Upload-Id", "u-1");
    req.set_header("Chunk-Index", "0");
    req.body = std::string(streaming_config_.max_chunk_size_bytes + 1, 'x');
    httplib::Response res;

    handler_->handle_upload_chunk(req, res, make_test_context());
    EXPECT_EQ(res.status, 413);
}

TEST_F(FilesProxyHandlerTest, UploadChunkHashMismatchRejected) {
    httplib::Request req;
    req.set_header("Upload-Id", "u-1");
    req.set_header("Chunk-Index", "0");
    req.set_header("X-Ciphertext-SHA256", "0000000000000000000000000000000000000000000000000000000000000000");
    req.body = "real-data";
    httplib::Response res;

    handler_->handle_upload_chunk(req, res, make_test_context());
    EXPECT_EQ(res.status, 400);
}

// 3. POST /api/v1/files/upload/finalize
TEST_F(FilesProxyHandlerTest, UploadFinalizeSuccess) {
    securecloud::files::v1::FinalizeFileUploadResponse grpc_resp;
    grpc_resp.set_file_id("f-1");
    grpc_resp.set_lifecycle_state(securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_AVAILABLE);
    grpc_resp.set_available_at_unix_ms(1750000000000LL);

    EXPECT_CALL(*mock_client_, finalize_file_upload(_, _)).WillOnce(Return(grpc_resp));

    httplib::Request req;
    req.body =
        nlohmann::json{
            {"upload_id", "u-1"},
            {"file_id", "f-1"},
            {"expected_ciphertext_sha256", "sha-xyz"},
        }
            .dump();

    httplib::Response res;
    handler_->handle_upload_finalize(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto resp_json = nlohmann::json::parse(res.body);
    EXPECT_EQ(resp_json["file_id"], "f-1");
}

// 4. POST /api/v1/files/upload/cancel
TEST_F(FilesProxyHandlerTest, UploadCancelSuccess) {
    securecloud::files::v1::CancelFileUploadResponse grpc_resp;
    grpc_resp.set_upload_id("u-1");
    grpc_resp.set_status(securecloud::files::v1::TransferStatus::TRANSFER_STATUS_CANCELLED);

    EXPECT_CALL(*mock_client_, cancel_file_upload(_, _)).WillOnce(Return(grpc_resp));

    httplib::Request req;
    req.body =
        nlohmann::json{
            {"upload_id", "u-1"},
            {"reason", "Client aborted"},
        }
            .dump();

    httplib::Response res;
    handler_->handle_upload_cancel(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto resp_json = nlohmann::json::parse(res.body);
    EXPECT_EQ(resp_json["status"], "TRANSFER_STATUS_CANCELLED");
}

// 5. GET /api/v1/files/:file_id/metadata
TEST_F(FilesProxyHandlerTest, GetMetadataSuccess) {
    securecloud::files::v1::GetFileMetadataResponse grpc_resp;
    grpc_resp.set_file_id("f-100");
    grpc_resp.set_encrypted_size_bytes(8388608);
    grpc_resp.set_chunk_count(2);
    grpc_resp.set_encryption_version("v1");
    grpc_resp.set_lifecycle_state(securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_AVAILABLE);

    EXPECT_CALL(*mock_client_, get_file_metadata(_, _)).WillOnce(Return(grpc_resp));

    httplib::Request req;
    req.path = "/api/v1/files/f-100/metadata";

    httplib::Response res;
    handler_->handle_get_metadata(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto resp_json = nlohmann::json::parse(res.body);
    EXPECT_EQ(resp_json["file_id"], "f-100");
    EXPECT_EQ(resp_json["chunk_count"], 2);
}

TEST_F(FilesProxyHandlerTest, GetMetadataNotFoundReturns404) {
    EXPECT_CALL(*mock_client_, get_file_metadata(_, _))
        .WillOnce(Return(grpc::DependencyError{
            .kind = grpc::DependencyErrorKind::NotFound,
            .message = "File does not exist",
            .grpc_code = ::grpc::StatusCode::NOT_FOUND,
        }));

    httplib::Request req;
    req.path = "/api/v1/files/f-missing/metadata";

    httplib::Response res;
    handler_->handle_get_metadata(req, res, make_test_context());

    EXPECT_EQ(res.status, 404);
}

// 6. GET /api/v1/files/:file_id/chunks/:chunk_index
TEST_F(FilesProxyHandlerTest, DownloadChunkSuccess) {
    securecloud::files::v1::DownloadChunkResponse grpc_resp;
    grpc_resp.set_file_id("f-100");
    grpc_resp.set_chunk_index(1);
    grpc_resp.set_encrypted_data("binary-chunk-payload-data");
    grpc_resp.set_chunk_size_bytes(25);
    grpc_resp.set_ciphertext_sha256("sha256-abc");

    EXPECT_CALL(*mock_client_, download_chunk(_, _)).WillOnce(Return(grpc_resp));

    httplib::Request req;
    req.path = "/api/v1/files/f-100/chunks/1";

    httplib::Response res;
    handler_->handle_download_chunk(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(res.get_header_value("Content-Type"), "application/octet-stream");
    EXPECT_EQ(res.body, "binary-chunk-payload-data");
}

// 7. GET /api/v1/files/:file_id/download
TEST_F(FilesProxyHandlerTest, StreamingDownloadSuccess) {
    securecloud::files::v1::GetFileMetadataResponse meta_resp;
    meta_resp.set_file_id("f-stream");
    meta_resp.set_encrypted_size_bytes(10);
    meta_resp.set_chunk_count(2);

    securecloud::files::v1::DownloadChunkResponse chunk0;
    chunk0.set_file_id("f-stream");
    chunk0.set_chunk_index(0);
    chunk0.set_encrypted_data("hello-");

    securecloud::files::v1::DownloadChunkResponse chunk1;
    chunk1.set_file_id("f-stream");
    chunk1.set_chunk_index(1);
    chunk1.set_encrypted_data("world");

    EXPECT_CALL(*mock_client_, get_file_metadata(_, _)).WillOnce(Return(meta_resp));
    EXPECT_CALL(*mock_client_, download_chunk(_, _)).WillOnce(Return(chunk0)).WillOnce(Return(chunk1));

    httplib::Request req;
    req.path = "/api/v1/files/f-stream/download";

    httplib::Response res;
    handler_->handle_streaming_download(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(res.body, "hello-world");
}

// 8. DELETE /api/v1/files/:file_id
TEST_F(FilesProxyHandlerTest, DeleteFileSuccess) {
    securecloud::files::v1::DeleteFileResponse grpc_resp;
    grpc_resp.set_file_id("f-del");
    grpc_resp.set_lifecycle_state(securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_DELETED);
    grpc_resp.set_deleted(true);

    EXPECT_CALL(*mock_client_, delete_file(_, _)).WillOnce(Return(grpc_resp));

    httplib::Request req;
    req.path = "/api/v1/files/f-del";

    httplib::Response res;
    handler_->handle_delete_file(req, res, make_test_context());

    EXPECT_EQ(res.status, 200);
    auto resp_json = nlohmann::json::parse(res.body);
    EXPECT_TRUE(resp_json["deleted"]);
}

TEST_F(FilesProxyHandlerTest, DeleteFilePermissionDeniedReturns403) {
    EXPECT_CALL(*mock_client_, delete_file(_, _))
        .WillOnce(Return(grpc::DependencyError{
            .kind = grpc::DependencyErrorKind::PermissionDenied,
            .message = "Forbidden",
            .grpc_code = ::grpc::StatusCode::PERMISSION_DENIED,
        }));

    httplib::Request req;
    req.path = "/api/v1/files/f-unauthorized";

    httplib::Response res;
    handler_->handle_delete_file(req, res, make_test_context());

    EXPECT_EQ(res.status, 403);
}

// 9. Bulkhead rejection
TEST_F(FilesProxyHandlerTest, BulkheadSaturationRejection) {
    // Acquire all slots
    std::vector<BulkheadLease> leases;
    for (int i = 0; i < 5; ++i) {
        leases.push_back(bulkhead_manager_->acquire(WorkloadCategory::Files));
        EXPECT_TRUE(leases.back());
    }

    httplib::Request req;
    req.body = nlohmann::json{{"encrypted_size_bytes", 100}, {"expected_chunk_count", 1}}.dump();
    httplib::Response res;

    handler_->handle_upload_init(req, res, make_test_context());
    EXPECT_EQ(res.status, 503);
    EXPECT_EQ(res.get_header_value("Retry-After"), "5");
}

// 10. Circuit breaker open rejection
TEST_F(FilesProxyHandlerTest, CircuitBreakerOpenRejection) {
    circuit_breaker_->record_failure();
    circuit_breaker_->record_failure();
    EXPECT_EQ(circuit_breaker_->state(), CircuitState::Open);

    httplib::Request req;
    req.body = nlohmann::json{{"encrypted_size_bytes", 100}, {"expected_chunk_count", 1}}.dump();
    httplib::Response res;

    handler_->handle_upload_init(req, res, make_test_context());
    EXPECT_EQ(res.status, 503);
}

// 11. Request cancellation
TEST_F(FilesProxyHandlerTest, CancelRequestPropagates) {
    grpc::ClientCallContext ctx;
    handler_->register_active_call("req-cancel", &ctx);

    EXPECT_FALSE(ctx.is_cancelled());
    EXPECT_TRUE(handler_->cancel_request("req-cancel"));
    EXPECT_TRUE(ctx.is_cancelled());

    handler_->unregister_active_call("req-cancel");
    EXPECT_FALSE(handler_->cancel_request("req-cancel"));
}

// 12. Route registration into Router
TEST_F(FilesProxyHandlerTest, RouteRegistrationIntoRouter) {
    Router router;
    handler_->register_routes(router);
    EXPECT_GE(router.route_count(), 8u);
}

} // namespace
} // namespace securecloud::gateway::http

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
#ifdef _WIN32
    std::fflush(nullptr);
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
#else
    return result;
#endif
}
