#include "grpc/client_call_context.hpp"
#include "grpc/files_service_client.hpp"

#include <chrono>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace securecloud::gateway::grpc {
namespace {

class FakeFilesService final : public securecloud::files::v1::FilesService::Service {
  public:
    ::grpc::StatusCode return_code{::grpc::StatusCode::OK};
    std::string return_message{"Success"};

    ::grpc::Status CreateFileUpload(::grpc::ServerContext* /*context*/,
                                    const securecloud::files::v1::CreateFileUploadRequest* request,
                                    securecloud::files::v1::CreateFileUploadResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_upload_id("upload-session-1234");
        response->set_file_id(request->file_id().empty() ? "file-uuid-5678" : request->file_id());
        response->set_status(securecloud::files::v1::TransferStatus::TRANSFER_STATUS_PENDING);
        response->set_expires_at_unix_ms(1750000000000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status UploadChunk(::grpc::ServerContext* /*context*/,
                               const securecloud::files::v1::UploadChunkRequest* request,
                               securecloud::files::v1::UploadChunkResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_upload_id(request->upload_id());
        response->set_chunk_index(request->chunk_index());
        response->set_accepted(true);
        response->set_received_sha256(request->ciphertext_sha256());
        return ::grpc::Status::OK;
    }

    ::grpc::Status FinalizeFileUpload(::grpc::ServerContext* /*context*/,
                                      const securecloud::files::v1::FinalizeFileUploadRequest* request,
                                      securecloud::files::v1::FinalizeFileUploadResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_file_id(request->file_id());
        response->set_lifecycle_state(securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_AVAILABLE);
        response->set_available_at_unix_ms(1750000050000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status GetFileMetadata(::grpc::ServerContext* /*context*/,
                                   const securecloud::files::v1::GetFileMetadataRequest* request,
                                   securecloud::files::v1::GetFileMetadataResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_file_id(request->file_id());
        response->set_lifecycle_state(securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_AVAILABLE);
        response->set_encrypted_size_bytes(8388608ULL); // 8 MiB
        response->set_chunk_count(2);
        response->set_encryption_version("v1");
        response->set_ciphertext_integrity_hash("sha256-mock-integrity-hash");
        response->set_created_at_unix_ms(1750000000000LL);
        response->set_available_at_unix_ms(1750000050000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status DownloadChunk(::grpc::ServerContext* /*context*/,
                                 const securecloud::files::v1::DownloadChunkRequest* request,
                                 securecloud::files::v1::DownloadChunkResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_file_id(request->file_id());
        response->set_chunk_index(request->chunk_index());
        response->set_encrypted_data("encrypted-chunk-ciphertext-data");
        response->set_chunk_size_bytes(31);
        response->set_ciphertext_sha256("sha256-chunk-hash");
        return ::grpc::Status::OK;
    }

    ::grpc::Status CancelFileUpload(::grpc::ServerContext* /*context*/,
                                    const securecloud::files::v1::CancelFileUploadRequest* request,
                                    securecloud::files::v1::CancelFileUploadResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_upload_id(request->upload_id());
        response->set_status(securecloud::files::v1::TransferStatus::TRANSFER_STATUS_CANCELLED);
        return ::grpc::Status::OK;
    }

    ::grpc::Status DeleteFile(::grpc::ServerContext* /*context*/,
                              const securecloud::files::v1::DeleteFileRequest* request,
                              securecloud::files::v1::DeleteFileResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_file_id(request->file_id());
        response->set_lifecycle_state(securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_DELETED);
        response->set_deleted(true);
        return ::grpc::Status::OK;
    }
};

class FilesServiceClientTest : public ::testing::Test {
  protected:
    void SetUp() override {
        fake_service_ = std::make_unique<FakeFilesService>();

        ::grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", ::grpc::InsecureServerCredentials(), &bound_port_);
        builder.RegisterService(fake_service_.get());
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);
        ASSERT_GT(bound_port_, 0);

        server_address_ = "127.0.0.1:" + std::to_string(bound_port_);
        channel_ = ::grpc::CreateChannel(server_address_, ::grpc::InsecureChannelCredentials());
        client_ = std::make_unique<FilesServiceClient>(channel_);
    }

    void TearDown() override {
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    std::unique_ptr<FakeFilesService> fake_service_;
    std::unique_ptr<::grpc::Server> server_;
    int bound_port_{0};
    std::string server_address_;
    std::shared_ptr<::grpc::Channel> channel_;
    std::unique_ptr<FilesServiceClient> client_;
};

// 1. CreateFileUpload
TEST_F(FilesServiceClientTest, CreateFileUploadSuccess) {
    securecloud::files::v1::CreateFileUploadRequest req;
    req.set_file_id("f-123");
    req.set_owner_user_id("user-1");
    req.set_owner_device_id("dev-1");
    req.set_encrypted_size_bytes(4194304);
    req.set_expected_chunk_count(1);
    req.set_encryption_version("v1");

    ClientCallContext ctx(std::chrono::milliseconds(2000));
    auto result = client_->create_file_upload(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().upload_id(), "upload-session-1234");
    EXPECT_EQ(result.value().file_id(), "f-123");
    EXPECT_EQ(result.value().status(), securecloud::files::v1::TransferStatus::TRANSFER_STATUS_PENDING);
    EXPECT_GT(result.value().expires_at_unix_ms(), 0);
}

TEST_F(FilesServiceClientTest, CreateFileUploadErrorMapping) {
    fake_service_->return_code = ::grpc::StatusCode::INVALID_ARGUMENT;
    fake_service_->return_message = "Invalid expected chunk count";

    securecloud::files::v1::CreateFileUploadRequest req;
    ClientCallContext ctx(std::chrono::milliseconds(2000));
    auto result = client_->create_file_upload(req, ctx);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, DependencyErrorKind::InvalidArgument);
    EXPECT_EQ(result.error().grpc_code, ::grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(result.error().message, "Invalid expected chunk count");
}

// 2. UploadChunk
TEST_F(FilesServiceClientTest, UploadChunkSuccess) {
    securecloud::files::v1::UploadChunkRequest req;
    req.set_upload_id("u-123");
    req.set_chunk_index(0);
    req.set_encrypted_data("ciphertext-bytes");
    req.set_chunk_size_bytes(16);
    req.set_ciphertext_sha256("sha256-digest-abc");

    ClientCallContext ctx(std::chrono::milliseconds(2000));
    auto result = client_->upload_chunk(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().upload_id(), "u-123");
    EXPECT_EQ(result.value().chunk_index(), 0u);
    EXPECT_TRUE(result.value().accepted());
    EXPECT_EQ(result.value().received_sha256(), "sha256-digest-abc");
}

TEST_F(FilesServiceClientTest, UploadChunkUnavailableMapping) {
    fake_service_->return_code = ::grpc::StatusCode::UNAVAILABLE;
    fake_service_->return_message = "Storage backend unreachable";

    securecloud::files::v1::UploadChunkRequest req;
    ClientCallContext ctx(std::chrono::milliseconds(2000));
    auto result = client_->upload_chunk(req, ctx);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, DependencyErrorKind::ServiceUnavailable);
    EXPECT_EQ(result.error().grpc_code, ::grpc::StatusCode::UNAVAILABLE);
}

// 3. FinalizeFileUpload
TEST_F(FilesServiceClientTest, FinalizeFileUploadSuccess) {
    securecloud::files::v1::FinalizeFileUploadRequest req;
    req.set_upload_id("u-123");
    req.set_file_id("f-123");
    req.set_expected_ciphertext_sha256("final-sha256");

    ClientCallContext ctx(std::chrono::milliseconds(2000));
    auto result = client_->finalize_file_upload(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().file_id(), "f-123");
    EXPECT_EQ(result.value().lifecycle_state(),
              securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_AVAILABLE);
    EXPECT_GT(result.value().available_at_unix_ms(), 0);
}

// 4. GetFileMetadata
TEST_F(FilesServiceClientTest, GetFileMetadataSuccess) {
    securecloud::files::v1::GetFileMetadataRequest req;
    req.set_file_id("f-123");

    ClientCallContext ctx(std::chrono::milliseconds(2000));
    auto result = client_->get_file_metadata(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().file_id(), "f-123");
    EXPECT_EQ(result.value().encrypted_size_bytes(), 8388608ULL);
    EXPECT_EQ(result.value().chunk_count(), 2u);
    EXPECT_EQ(result.value().encryption_version(), "v1");
}

TEST_F(FilesServiceClientTest, GetFileMetadataNotFoundMapping) {
    fake_service_->return_code = ::grpc::StatusCode::NOT_FOUND;
    fake_service_->return_message = "File not found";

    securecloud::files::v1::GetFileMetadataRequest req;
    req.set_file_id("nonexistent");

    ClientCallContext ctx(std::chrono::milliseconds(2000));
    auto result = client_->get_file_metadata(req, ctx);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, DependencyErrorKind::NotFound);
    EXPECT_EQ(result.error().grpc_code, ::grpc::StatusCode::NOT_FOUND);
}

// 5. DownloadChunk
TEST_F(FilesServiceClientTest, DownloadChunkSuccess) {
    securecloud::files::v1::DownloadChunkRequest req;
    req.set_file_id("f-123");
    req.set_chunk_index(1);

    ClientCallContext ctx(std::chrono::milliseconds(2000));
    auto result = client_->download_chunk(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().file_id(), "f-123");
    EXPECT_EQ(result.value().chunk_index(), 1u);
    EXPECT_EQ(result.value().encrypted_data(), "encrypted-chunk-ciphertext-data");
    EXPECT_EQ(result.value().chunk_size_bytes(), 31u);
}

// 6. CancelFileUpload
TEST_F(FilesServiceClientTest, CancelFileUploadSuccess) {
    securecloud::files::v1::CancelFileUploadRequest req;
    req.set_upload_id("u-123");
    req.set_reason("Client aborted transfer");

    ClientCallContext ctx(std::chrono::milliseconds(2000));
    auto result = client_->cancel_file_upload(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().upload_id(), "u-123");
    EXPECT_EQ(result.value().status(), securecloud::files::v1::TransferStatus::TRANSFER_STATUS_CANCELLED);
}

// 7. DeleteFile
TEST_F(FilesServiceClientTest, DeleteFileSuccess) {
    securecloud::files::v1::DeleteFileRequest req;
    req.set_file_id("f-123");

    ClientCallContext ctx(std::chrono::milliseconds(2000));
    auto result = client_->delete_file(req, ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().file_id(), "f-123");
    EXPECT_EQ(result.value().lifecycle_state(),
              securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_DELETED);
    EXPECT_TRUE(result.value().deleted());
}

TEST_F(FilesServiceClientTest, DeleteFilePermissionDeniedMapping) {
    fake_service_->return_code = ::grpc::StatusCode::PERMISSION_DENIED;
    fake_service_->return_message = "Caller not authorized to delete file";

    securecloud::files::v1::DeleteFileRequest req;
    req.set_file_id("f-123");

    ClientCallContext ctx(std::chrono::milliseconds(2000));
    auto result = client_->delete_file(req, ctx);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, DependencyErrorKind::PermissionDenied);
    EXPECT_EQ(result.error().grpc_code, ::grpc::StatusCode::PERMISSION_DENIED);
}

// 8. Null stub handling
TEST(FilesServiceClientEdgeCases, NullStubReturnsServiceUnavailable) {
    FilesServiceClient null_client(std::shared_ptr<::grpc::Channel>{nullptr});

    ClientCallContext ctx(std::chrono::milliseconds(1000));
    securecloud::files::v1::CreateFileUploadRequest req1;
    EXPECT_EQ(null_client.create_file_upload(req1, ctx).error().kind, DependencyErrorKind::ServiceUnavailable);

    securecloud::files::v1::UploadChunkRequest req2;
    EXPECT_EQ(null_client.upload_chunk(req2, ctx).error().kind, DependencyErrorKind::ServiceUnavailable);

    securecloud::files::v1::FinalizeFileUploadRequest req3;
    EXPECT_EQ(null_client.finalize_file_upload(req3, ctx).error().kind, DependencyErrorKind::ServiceUnavailable);

    securecloud::files::v1::GetFileMetadataRequest req4;
    EXPECT_EQ(null_client.get_file_metadata(req4, ctx).error().kind, DependencyErrorKind::ServiceUnavailable);

    securecloud::files::v1::DownloadChunkRequest req5;
    EXPECT_EQ(null_client.download_chunk(req5, ctx).error().kind, DependencyErrorKind::ServiceUnavailable);

    securecloud::files::v1::CancelFileUploadRequest req6;
    EXPECT_EQ(null_client.cancel_file_upload(req6, ctx).error().kind, DependencyErrorKind::ServiceUnavailable);

    securecloud::files::v1::DeleteFileRequest req7;
    EXPECT_EQ(null_client.delete_file(req7, ctx).error().kind, DependencyErrorKind::ServiceUnavailable);
}

// 9. Cancellation propagation
TEST_F(FilesServiceClientTest, ClientCallContextCancellationPropagated) {
    ClientCallContext ctx(std::chrono::milliseconds(2000));
    ctx.cancel();
    EXPECT_TRUE(ctx.is_cancelled());

    securecloud::files::v1::GetFileMetadataRequest req;
    req.set_file_id("f-123");
    auto result = client_->get_file_metadata(req, ctx);

    ASSERT_TRUE(result.has_error());
    EXPECT_TRUE(result.error().grpc_code == ::grpc::StatusCode::CANCELLED ||
                result.error().grpc_code == ::grpc::StatusCode::DEADLINE_EXCEEDED ||
                result.error().kind == DependencyErrorKind::Internal);
}

} // namespace
} // namespace securecloud::gateway::grpc

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
