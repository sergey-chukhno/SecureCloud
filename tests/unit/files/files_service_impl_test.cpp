#include "files/service/files_service_impl.hpp"
#include "securecloud/files/v1/files.grpc.pb.h"
#include "securecloud/files/v1/files.pb.h"

#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#ifdef DeleteFile
#undef DeleteFile
#endif

namespace securecloud::files::service {
namespace {

// ============================================================================
// Test Mock AuthContext for mTLS Peer Identity Verification
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
// In-Process gRPC Server & Channel Fixture
// ============================================================================

class FilesServiceInProcessTest : public ::testing::Test {
  protected:
    void SetUp() override {
        // Construct FilesServiceImpl with empty expected identity for in-process channel testing
        service_impl_ = std::make_unique<FilesServiceImpl>(FilesServiceDependencies{}, "");

        grpc::ServerBuilder builder;
        builder.RegisterService(service_impl_.get());
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);

        channel_ = server_->InProcessChannel(grpc::ChannelArguments());
        ASSERT_NE(channel_, nullptr);

        stub_ = v1::FilesService::NewStub(channel_);
        ASSERT_NE(stub_, nullptr);
    }

    void TearDown() override {
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    std::unique_ptr<FilesServiceImpl> service_impl_;
    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::FilesService::Stub> stub_;
};

// ============================================================================
// RPC In-Process Tests: All 7 RPCs Must Return UNIMPLEMENTED Deterministically
// ============================================================================

TEST_F(FilesServiceInProcessTest, CreateFileUploadReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::CreateFileUploadRequest request;
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    request.set_owner_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    request.set_owner_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    request.set_encrypted_size_bytes(4194304);
    request.set_expected_chunk_count(1);
    request.set_encryption_version("v1-xchacha20poly1305");

    v1::CreateFileUploadResponse response;
    auto status = stub_->CreateFileUpload(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), FilesServiceImpl::k_unimplemented_skeleton_message);
}

TEST_F(FilesServiceInProcessTest, UploadChunkReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::UploadChunkRequest request;
    request.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    request.set_chunk_index(0);
    request.set_encrypted_data("encrypted-chunk-ciphertext-bytes");
    request.set_chunk_size_bytes(32);
    request.set_ciphertext_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    v1::UploadChunkResponse response;
    auto status = stub_->UploadChunk(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), FilesServiceImpl::k_unimplemented_skeleton_message);
}

TEST_F(FilesServiceInProcessTest, FinalizeFileUploadReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::FinalizeFileUploadRequest request;
    request.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    request.set_expected_ciphertext_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    v1::FinalizeFileUploadResponse response;
    auto status = stub_->FinalizeFileUpload(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), FilesServiceImpl::k_unimplemented_skeleton_message);
}

TEST_F(FilesServiceInProcessTest, GetFileMetadataReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::GetFileMetadataRequest request;
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");

    v1::GetFileMetadataResponse response;
    auto status = stub_->GetFileMetadata(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), FilesServiceImpl::k_unimplemented_skeleton_message);
}

TEST_F(FilesServiceInProcessTest, DownloadChunkReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::DownloadChunkRequest request;
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    request.set_chunk_index(0);

    v1::DownloadChunkResponse response;
    auto status = stub_->DownloadChunk(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), FilesServiceImpl::k_unimplemented_skeleton_message);
}

TEST_F(FilesServiceInProcessTest, CancelFileUploadReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::CancelFileUploadRequest request;
    request.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    request.set_reason("Client user cancelled transfer session");

    v1::CancelFileUploadResponse response;
    auto status = stub_->CancelFileUpload(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), FilesServiceImpl::k_unimplemented_skeleton_message);
}

TEST_F(FilesServiceInProcessTest, DeleteFileReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::DeleteFileRequest request;
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");

    v1::DeleteFileResponse response;
    auto status = stub_->DeleteFile(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), FilesServiceImpl::k_unimplemented_skeleton_message);
}

// ============================================================================
// Null Argument Validation Tests
// ============================================================================

TEST(FilesServiceImplDirectTest, RejectsNullArguments) {
    FilesServiceImpl service(FilesServiceDependencies{}, "");
    TestAuthContext auth_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    v1::CreateFileUploadRequest req;
    v1::CreateFileUploadResponse resp;

    // 1. Null request
    auto status = service.CreateFileUpload(&auth_ctx, nullptr, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);

    // 2. Null response
    status = service.CreateFileUpload(&auth_ctx, &req, nullptr);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);

    // 3. Null request and response
    status = service.CreateFileUpload(&auth_ctx, nullptr, nullptr);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

// ============================================================================
// mTLS Peer Certificate SAN Authorization Tests
// ============================================================================

TEST(FilesServiceImplAuthTest, RejectsUnauthenticatedCallerWhenPeerRequired) {
    FilesServiceImpl service(FilesServiceDependencies{}, "gateway");

    v1::CreateFileUploadRequest req;
    v1::CreateFileUploadResponse resp;

    // 1. Null AuthContext
    auto status = service.CreateFileUpload(static_cast<const grpc::AuthContext*>(nullptr), &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);

    // 2. Unauthenticated TestAuthContext
    TestAuthContext unauth_ctx(false);
    status = service.CreateFileUpload(&unauth_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

TEST(FilesServiceImplAuthTest, RejectsUnauthorizedPeerServiceIdentity) {
    FilesServiceImpl service(FilesServiceDependencies{}, "gateway");

    v1::CreateFileUploadRequest req;
    v1::CreateFileUploadResponse resp;

    // Authenticated caller from unauthorized service (messaging instead of gateway)
    TestAuthContext unauthorized_ctx(true, {{"x509_subject_alternative_name", "DNS:messaging"}});
    auto status = service.CreateFileUpload(&unauthorized_ctx, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_EQ(status.error_message(), "Caller peer identity not authorized");
}

TEST(FilesServiceImplAuthTest, AcceptsAuthorizedPeerGateway) {
    FilesServiceImpl service(FilesServiceDependencies{}, "gateway");

    v1::CreateFileUploadRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    v1::CreateFileUploadResponse resp;

    // 1. Authorized peer with "DNS:gateway" SAN
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});
    auto status = service.CreateFileUpload(&gateway_ctx, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), FilesServiceImpl::k_unimplemented_skeleton_message);

    // 2. Authorized peer with raw "gateway" SAN
    TestAuthContext raw_gateway_ctx(true, {{"x509_subject_alternative_name", "gateway"}});
    status = service.CreateFileUpload(&raw_gateway_ctx, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), FilesServiceImpl::k_unimplemented_skeleton_message);
}

// ============================================================================
// Modular Architecture Dependency Injection Test
// ============================================================================

TEST(FilesServiceImplModularTest, InjectsSubComponentDependencies) {
    FilesServiceDependencies deps{
        .db_pool = nullptr,
        .s3_client = nullptr,
        .upload_session_manager = std::make_shared<UploadSessionManager>(),
        .download_manager = std::make_shared<DownloadManager>(),
        .storage_engine = std::make_shared<StorageEngine>(),
        .metadata_manager = std::make_shared<MetadataManager>(),
    };

    FilesServiceImpl service(deps, "gateway");

    EXPECT_EQ(service.expected_client_identity(), "gateway");
    EXPECT_NE(service.dependencies().upload_session_manager, nullptr);
    EXPECT_NE(service.dependencies().download_manager, nullptr);
    EXPECT_NE(service.dependencies().storage_engine, nullptr);
    EXPECT_NE(service.dependencies().metadata_manager, nullptr);

    service.set_expected_client_identity("custom_gateway");
    EXPECT_EQ(service.expected_client_identity(), "custom_gateway");
}

} // namespace
} // namespace securecloud::files::service
