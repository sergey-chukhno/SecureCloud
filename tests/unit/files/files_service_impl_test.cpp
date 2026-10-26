#include "files/domain/lifecycle_state_machine.hpp"
#include "files/domain/metadata_validator.hpp"
#include "files/service/file_lifecycle_service.hpp"
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
// Mock FileLifecycleService for Service Unit Testing
// ============================================================================

class TestMockLifecycleService : public FileLifecycleService {
  public:
    TestMockLifecycleService() : FileLifecycleService(nullptr) {}

    std::string create_file(const CreateFileRequestDto& dto, std::chrono::system_clock::time_point /*now*/) override {
        if (throw_validation_) {
            throw FileLifecycleValidationException("Validation failed in mock");
        }
        last_dto_ = dto;
        return dto.file_id;
    }

    std::optional<FileMetadataSummary> get_file_metadata(const std::string& file_id,
                                                         const std::string& /*caller_user_id*/) override {
        if (throw_unauthorized_) {
            throw UnauthorizedFileAccessException("Caller not authorized");
        }
        if (file_id != mock_summary_.file.file_id) {
            return std::nullopt;
        }
        return mock_summary_;
    }

    bool delete_file(const std::string& file_id, const std::string& /*caller_user_id*/,
                     const std::string& /*reason*/) override {
        if (throw_unauthorized_) {
            throw UnauthorizedFileAccessException("Caller not authorized");
        }
        if (file_id != mock_summary_.file.file_id) {
            throw FileNotFoundException("File not found: " + file_id);
        }
        mock_summary_.file.status = FileStatus::Deleted;
        return true;
    }

    void set_mock_summary(FileMetadataSummary summary) { mock_summary_ = std::move(summary); }
    void set_throw_validation(bool val) { throw_validation_ = val; }
    void set_throw_unauthorized(bool val) { throw_unauthorized_ = val; }

  private:
    bool throw_validation_{false};
    bool throw_unauthorized_{false};
    CreateFileRequestDto last_dto_;
    FileMetadataSummary mock_summary_;
};

// ============================================================================
// In-Process gRPC Server & Channel Fixture
// ============================================================================

class FilesServiceInProcessTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_lifecycle_ = std::make_shared<TestMockLifecycleService>();
        FilesServiceDependencies deps{
            .lifecycle_service = mock_lifecycle_,
        };

        // Construct FilesServiceImpl with empty expected identity for in-process channel testing
        service_impl_ = std::make_unique<FilesServiceImpl>(deps, "");

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

    std::shared_ptr<TestMockLifecycleService> mock_lifecycle_;
    std::unique_ptr<FilesServiceImpl> service_impl_;
    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::FilesService::Stub> stub_;
};

// ============================================================================
// RPC In-Process Tests: Unimplemented Skeleton Endpoints
// ============================================================================

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

TEST_F(FilesServiceInProcessTest, FinalizeFileUploadChecksPreconditionsAndReturnsUnimplemented) {
    grpc::ClientContext context;
    v1::FinalizeFileUploadRequest request;
    request.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    request.set_expected_ciphertext_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    v1::FinalizeFileUploadResponse response;
    auto status = stub_->FinalizeFileUpload(&context, request, &response);

    // Passed UUID validation and lifecycle hook check, now returns skeleton unimplemented until FILE-006
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), FilesServiceImpl::k_unimplemented_skeleton_message);
}

TEST_F(FilesServiceInProcessTest, FinalizeFileUploadRejectsInvalidFileId) {
    grpc::ClientContext context;
    v1::FinalizeFileUploadRequest request;
    request.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    request.set_file_id("not-a-uuid");

    v1::FinalizeFileUploadResponse response;
    auto status = stub_->FinalizeFileUpload(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(status.error_message(), "Invalid file_id format");
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

// ============================================================================
// Implemented RPC Tests: CreateFileUpload, GetFileMetadata, DeleteFile
// ============================================================================

TEST_F(FilesServiceInProcessTest, CreateFileUploadRejectsMissingCryptoMetadata) {
    grpc::ClientContext context;
    v1::CreateFileUploadRequest request;
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    request.set_owner_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    request.set_owner_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    request.set_encrypted_size_bytes(4194304);
    request.set_expected_chunk_count(1);
    request.set_encryption_version("XChaCha20-Poly1305");
    // Missing client_crypto_metadata

    v1::CreateFileUploadResponse response;
    auto status = stub_->CreateFileUpload(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(status.error_message(), "client_crypto_metadata is required");
}

TEST_F(FilesServiceInProcessTest, CreateFileUploadSuccess) {
    grpc::ClientContext context;
    v1::CreateFileUploadRequest request;
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    request.set_owner_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    request.set_owner_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    request.set_encrypted_size_bytes(4194304);
    request.set_expected_chunk_count(1);
    request.set_encryption_version("XChaCha20-Poly1305");

    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    std::string json_meta = "{\"encrypted_filename_hex\":\"deadbeef\",\"metadata_nonce_hex\":\"" + nonce_hex +
                            "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}";
    request.set_client_crypto_metadata(json_meta);

    v1::CreateFileUploadResponse response;
    auto status = stub_->CreateFileUpload(&context, request, &response);

    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_FALSE(response.upload_id().empty());
    EXPECT_EQ(response.file_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    EXPECT_EQ(response.status(), v1::TRANSFER_STATUS_PENDING);
    EXPECT_GT(response.expires_at_unix_ms(), 0);
}

TEST_F(FilesServiceInProcessTest, GetFileMetadataRejectsInvalidFileId) {
    grpc::ClientContext context;
    v1::GetFileMetadataRequest request;
    request.set_file_id("invalid-uuid-format");

    v1::GetFileMetadataResponse response;
    auto status = stub_->GetFileMetadata(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(status.error_message(), "Invalid file_id format");
}

TEST_F(FilesServiceInProcessTest, GetFileMetadataReturnsNotFound) {
    grpc::ClientContext context;
    v1::GetFileMetadataRequest request;
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36999"); // Non-existent

    v1::GetFileMetadataResponse response;
    auto status = stub_->GetFileMetadata(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
}

TEST_F(FilesServiceInProcessTest, GetFileMetadataSuccess) {
    FileEntity file_entity{
        .file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
        .owner_user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
        .owner_device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
        .encrypted_size = 4194304,
        .encryption_algorithm = "XChaCha20-Poly1305",
        .status = FileStatus::Available,
    };
    EncryptedFileMetadataEntity enc_meta{
        .file_id = file_entity.file_id,
        .encrypted_filename = {0x01, 0x02},
        .metadata_nonce = std::vector<uint8_t>(24, 0x01),
        .metadata_tag = std::vector<uint8_t>(16, 0x02),
        .client_encryption_metadata_json = "{}",
    };
    FileVersionEntity active_ver{
        .version_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36010",
        .file_id = file_entity.file_id,
        .version_number = 1,
        .checksum_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    };
    mock_lifecycle_->set_mock_summary(FileMetadataSummary{
        .file = file_entity,
        .encrypted_meta = enc_meta,
        .active_version = active_ver,
        .expected_chunk_count = 1,
    });

    grpc::ClientContext context;
    v1::GetFileMetadataRequest request;
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");

    v1::GetFileMetadataResponse response;
    auto status = stub_->GetFileMetadata(&context, request, &response);

    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(response.lifecycle_state(), v1::FILE_LIFECYCLE_STATE_AVAILABLE);
    EXPECT_EQ(response.encrypted_size_bytes(), 4194304);
    EXPECT_EQ(response.chunk_count(), 1);
    EXPECT_EQ(response.encryption_version(), "XChaCha20-Poly1305");
    EXPECT_EQ(response.ciphertext_integrity_hash(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(FilesServiceInProcessTest, DeleteFileRejectsInvalidFileId) {
    grpc::ClientContext context;
    v1::DeleteFileRequest request;
    request.set_file_id("bad-uuid");

    v1::DeleteFileResponse response;
    auto status = stub_->DeleteFile(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(status.error_message(), "Invalid file_id format");
}

TEST_F(FilesServiceInProcessTest, DeleteFileReturnsNotFound) {
    grpc::ClientContext context;
    v1::DeleteFileRequest request;
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36999");

    v1::DeleteFileResponse response;
    auto status = stub_->DeleteFile(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
}

TEST_F(FilesServiceInProcessTest, DeleteFileSuccess) {
    FileEntity file_entity{
        .file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
        .owner_user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
        .status = FileStatus::Available,
    };
    mock_lifecycle_->set_mock_summary(FileMetadataSummary{.file = file_entity});

    grpc::ClientContext context;
    v1::DeleteFileRequest request;
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");

    v1::DeleteFileResponse response;
    auto status = stub_->DeleteFile(&context, request, &response);

    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(response.file_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    EXPECT_EQ(response.lifecycle_state(), v1::FILE_LIFECYCLE_STATE_DELETED);
    EXPECT_TRUE(response.deleted());
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
    auto mock_lifecycle = std::make_shared<TestMockLifecycleService>();
    FilesServiceDependencies deps{.lifecycle_service = mock_lifecycle};
    FilesServiceImpl service(deps, "gateway");

    v1::CreateFileUploadRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_owner_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    req.set_owner_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    req.set_encrypted_size_bytes(4194304);
    req.set_expected_chunk_count(1);
    req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                   "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse resp;

    // 1. Authorized peer with "DNS:gateway" SAN
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});
    auto status = service.CreateFileUpload(&gateway_ctx, &req, &resp);
    EXPECT_TRUE(status.ok()) << status.error_message();

    // 2. Authorized peer with raw "gateway" SAN
    TestAuthContext raw_gateway_ctx(true, {{"x509_subject_alternative_name", "gateway"}});
    status = service.CreateFileUpload(&raw_gateway_ctx, &req, &resp);
    EXPECT_TRUE(status.ok()) << status.error_message();
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
        .lifecycle_service = std::make_shared<TestMockLifecycleService>(),
    };

    FilesServiceImpl service(deps, "gateway");

    EXPECT_EQ(service.expected_client_identity(), "gateway");
    EXPECT_NE(service.dependencies().upload_session_manager, nullptr);
    EXPECT_NE(service.dependencies().download_manager, nullptr);
    EXPECT_NE(service.dependencies().storage_engine, nullptr);
    EXPECT_NE(service.dependencies().metadata_manager, nullptr);
    EXPECT_NE(service.dependencies().lifecycle_service, nullptr);

    service.set_expected_client_identity("custom_gateway");
    EXPECT_EQ(service.expected_client_identity(), "custom_gateway");
}

} // namespace
} // namespace securecloud::files::service
