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

TEST_F(FilesServiceInProcessTest, UploadChunkReturnsNotFoundWhenSessionDoesNotExist) {
    grpc::ClientContext context;
    v1::UploadChunkRequest request;
    request.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    request.set_chunk_index(0);
    request.set_encrypted_data("encrypted-chunk-ciphertext-bytes");
    request.set_chunk_size_bytes(32);
    request.set_ciphertext_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    v1::UploadChunkResponse response;
    auto status = stub_->UploadChunk(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
    EXPECT_EQ(status.error_message(), "Transfer session not found: 0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
}

TEST_F(FilesServiceInProcessTest, FinalizeFileUploadReturnsUnavailableWhenServiceUninitialized) {
    grpc::ClientContext context;
    v1::FinalizeFileUploadRequest request;
    request.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    request.set_expected_ciphertext_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    v1::FinalizeFileUploadResponse response;
    auto status = stub_->FinalizeFileUpload(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(status.error_message(), "Finalization service uninitialized");
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

TEST_F(FilesServiceInProcessTest, DownloadChunkReturnsUnavailableWhenDownloadManagerNotConfigured) {
    grpc::ClientContext context;
    v1::DownloadChunkRequest request;
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    request.set_chunk_index(0);

    v1::DownloadChunkResponse response;
    auto status = stub_->DownloadChunk(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(status.error_message(), "DownloadManager is not configured");
}

TEST_F(FilesServiceInProcessTest, CancelFileUploadReturnsNotFoundWhenSessionManagerNotConfigured) {
    grpc::ClientContext context;
    v1::CancelFileUploadRequest request;
    request.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    request.set_reason("Client user cancelled transfer session");

    v1::CancelFileUploadResponse response;
    auto status = stub_->CancelFileUpload(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
    EXPECT_EQ(status.error_message(), "Upload session not found: 0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
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
    const auto now = std::chrono::system_clock::now();
    FileEntity file_entity{
        .file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
        .owner_user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
        .owner_device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
        .conversation_id = std::nullopt,
        .encrypted_size = 4194304,
        .content_type = std::nullopt,
        .encryption_algorithm = "XChaCha20-Poly1305",
        .status = FileStatus::Available,
        .retention_until = std::nullopt,
        .created_at = now,
        .updated_at = now,
    };
    EncryptedFileMetadataEntity enc_meta{
        .file_id = file_entity.file_id,
        .encrypted_filename = {0x01, 0x02},
        .encrypted_mime_type = std::nullopt,
        .metadata_nonce = std::vector<uint8_t>(24, 0x01),
        .metadata_tag = std::vector<uint8_t>(16, 0x02),
        .client_encryption_metadata_json = "{}",
        .updated_at = now,
    };
    FileVersionEntity active_ver{
        .version_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36010",
        .file_id = file_entity.file_id,
        .version_number = 1,
        .encrypted_size = 4194304,
        .minio_object_key = "files/test-object-key",
        .checksum_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        .created_at = now,
        .is_active = true,
    };
    mock_lifecycle_->set_mock_summary(FileMetadataSummary{
        .file = file_entity,
        .encrypted_meta = enc_meta,
        .active_version = active_ver,
        .all_versions = {active_ver},
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
    const auto now = std::chrono::system_clock::now();
    FileEntity file_entity{
        .file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
        .owner_user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
        .owner_device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
        .conversation_id = std::nullopt,
        .encrypted_size = 0,
        .content_type = std::nullopt,
        .encryption_algorithm = "XChaCha20-Poly1305",
        .status = FileStatus::Available,
        .retention_until = std::nullopt,
        .created_at = now,
        .updated_at = now,
    };
    mock_lifecycle_->set_mock_summary(FileMetadataSummary{
        .file = file_entity,
        .encrypted_meta = {},
        .active_version = std::nullopt,
        .all_versions = {},
        .expected_chunk_count = 0,
    });

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

// ============================================================================
// FILES-005: UploadChunk & CancelFileUpload Tests
// ============================================================================

class MockHttpTransport : public storage::IHttpTransport {
  public:
    storage::HttpResponse execute(const storage::HttpRequest& /*req*/) override {
        return storage::HttpResponse{
            .status_code = 200,
            .status_message = "OK",
            .headers = {{"ETag", "\"etag-12345\""}},
            .body = "",
        };
    }
};

TEST(FilesServiceImplUploadChunkTest, UploadChunkSuccessWithValidPayload) {
    auto session_mgr = std::make_shared<UploadSessionManager>(nullptr, nullptr, nullptr);
    auto transport = std::make_shared<MockHttpTransport>();
    storage::S3ClientConfig s3_cfg{
        .endpoint = "http://127.0.0.1:9000",
        .bucket = "securecloud-files-encrypted",
        .access_key = "test_key",
        .secret_key = common::configuration::SecretString("test_secret"),
    };
    auto s3_client = std::make_shared<storage::S3Client>(s3_cfg, transport);
    auto chunk_storage = std::make_shared<ChunkStorageService>(nullptr, s3_client, nullptr, nullptr, nullptr);

    FilesServiceDependencies deps{
        .upload_session_manager = session_mgr,
        .chunk_storage_service = chunk_storage,
    };
    FilesServiceImpl service(deps, "gateway");

    // Create session for 1 chunk of size 100 bytes
    std::string payload(100, 'z');
    std::string sha = compute_sha256_hex(payload);

    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    init_req.set_owner_user_id("user-alice");
    init_req.set_owner_device_id("device-alice");
    init_req.set_encrypted_size_bytes(payload.size());
    init_req.set_expected_chunk_count(1);
    auto session = session_mgr->create_session(init_req);
    ASSERT_TRUE(session.has_value());

    v1::UploadChunkRequest req;
    req.set_upload_id(session->upload_id);
    req.set_chunk_index(0);
    req.set_encrypted_data(payload);
    req.set_chunk_size_bytes(static_cast<uint32_t>(payload.size()));
    req.set_ciphertext_sha256(sha);

    v1::UploadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.UploadChunk(&gateway_ctx, &req, &resp);
    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(resp.upload_id(), session->upload_id);
    EXPECT_EQ(resp.chunk_index(), 0);
    EXPECT_TRUE(resp.accepted());
    EXPECT_EQ(resp.received_sha256(), sha);
}

TEST(FilesServiceImplUploadChunkTest, UploadChunkRejectsInvalidUuid) {
    FilesServiceImpl service({}, "gateway");

    v1::UploadChunkRequest req;
    req.set_upload_id("malformed-uuid");
    req.set_chunk_index(0);
    req.set_encrypted_data("data");
    req.set_chunk_size_bytes(4);
    req.set_ciphertext_sha256(compute_sha256_hex("data"));

    v1::UploadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.UploadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(FilesServiceImplUploadChunkTest, UploadChunkRejectsNotFoundSession) {
    auto session_mgr = std::make_shared<UploadSessionManager>(nullptr, nullptr, nullptr);
    FilesServiceDependencies deps{.upload_session_manager = session_mgr};
    FilesServiceImpl service(deps, "gateway");

    v1::UploadChunkRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);
    req.set_encrypted_data("data");
    req.set_chunk_size_bytes(4);
    req.set_ciphertext_sha256(compute_sha256_hex("data"));

    v1::UploadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.UploadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
}

TEST(FilesServiceImplUploadChunkTest, UploadChunkRejectsSha256Mismatch) {
    auto session_mgr = std::make_shared<UploadSessionManager>(nullptr, nullptr, nullptr);
    FilesServiceDependencies deps{.upload_session_manager = session_mgr};
    FilesServiceImpl service(deps, "gateway");

    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    init_req.set_encrypted_size_bytes(10);
    init_req.set_expected_chunk_count(1);
    auto session = session_mgr->create_session(init_req);
    ASSERT_TRUE(session.has_value());

    v1::UploadChunkRequest req;
    req.set_upload_id(session->upload_id);
    req.set_chunk_index(0);
    req.set_encrypted_data("0123456789");
    req.set_chunk_size_bytes(10);
    req.set_ciphertext_sha256("0000000000000000000000000000000000000000000000000000000000000000");

    v1::UploadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.UploadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(FilesServiceImplCancelTest, CancelFileUploadSuccess) {
    auto session_mgr = std::make_shared<UploadSessionManager>(nullptr, nullptr, nullptr);
    FilesServiceDependencies deps{.upload_session_manager = session_mgr};
    FilesServiceImpl service(deps, "gateway");

    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    init_req.set_expected_chunk_count(2);
    auto session = session_mgr->create_session(init_req);
    ASSERT_TRUE(session.has_value());

    v1::CancelFileUploadRequest req;
    req.set_upload_id(session->upload_id);
    req.set_reason("Client user aborted");

    v1::CancelFileUploadResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.CancelFileUpload(&gateway_ctx, &req, &resp);
    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(resp.upload_id(), session->upload_id);
    EXPECT_EQ(resp.status(), v1::TRANSFER_STATUS_CANCELLED);
}

TEST(FilesServiceImplCancelTest, CancelFileUploadRejectsInvalidUuid) {
    FilesServiceImpl service({}, "gateway");

    v1::CancelFileUploadRequest req;
    req.set_upload_id("bad-uuid");

    v1::CancelFileUploadResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.CancelFileUpload(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(FilesServiceImplCancelTest, CancelFileUploadNotFound) {
    auto session_mgr = std::make_shared<UploadSessionManager>(nullptr, nullptr, nullptr);
    FilesServiceDependencies deps{.upload_session_manager = session_mgr};
    FilesServiceImpl service(deps, "gateway");

    v1::CancelFileUploadRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");

    v1::CancelFileUploadResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.CancelFileUpload(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
}

// ==========================================
// FinalizeFileUpload Unit Tests (FILES-006-T05)
// ==========================================

class MockFinalizationService : public FileFinalizationService {
  public:
    MockFinalizationService() : FileFinalizationService(nullptr, nullptr) {}

    FinalizeUploadResultDto finalize_file_upload(const FinalizeUploadRequestDto& req) override {
        last_request = req;
        if (should_throw_not_found) {
            throw EntityNotFoundException("Session not found");
        }
        if (should_throw_precondition) {
            throw FinalizationPreconditionException("Missing chunk 1");
        }
        if (should_throw_integrity) {
            throw ChunkIntegrityException("SHA-256 whole-ciphertext mismatch");
        }
        return FinalizeUploadResultDto{
            .file_id = req.file_id.empty() ? "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000" : req.file_id,
            .version_number = 1,
            .total_bytes = 1024,
            .checksum_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            .available_at = std::chrono::system_clock::now(),
            .is_idempotent_replay = false,
        };
    }

    FinalizeUploadRequestDto last_request;
    bool should_throw_not_found{false};
    bool should_throw_precondition{false};
    bool should_throw_integrity{false};
};

TEST(FilesServiceImplFinalizeTest, RejectsUnauthorizedPeer) {
    FilesServiceImpl service({}, "gateway");
    v1::FinalizeFileUploadRequest req;
    v1::FinalizeFileUploadResponse resp;
    TestAuthContext untrusted_ctx(true, {{"x509_subject_alternative_name", "DNS:untrusted"}});

    auto status = service.FinalizeFileUpload(&untrusted_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST(FilesServiceImplFinalizeTest, RejectsInvalidFileIdFormat) {
    FilesServiceImpl service({}, "gateway");
    v1::FinalizeFileUploadRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_file_id("invalid-format");
    v1::FinalizeFileUploadResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.FinalizeFileUpload(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(FilesServiceImplFinalizeTest, ReturnsUnavailableWhenServiceNull) {
    FilesServiceImpl service({}, "gateway");
    v1::FinalizeFileUploadRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    v1::FinalizeFileUploadResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.FinalizeFileUpload(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAVAILABLE);
}

TEST(FilesServiceImplFinalizeTest, FinalizeSuccessSetsAvailableState) {
    auto mock_fin = std::make_shared<MockFinalizationService>();
    FilesServiceDependencies deps{.finalization_service = mock_fin};
    FilesServiceImpl service(deps, "gateway");

    v1::FinalizeFileUploadRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    req.set_expected_ciphertext_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    v1::FinalizeFileUploadResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.FinalizeFileUpload(&gateway_ctx, &req, &resp);
    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(resp.file_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    EXPECT_EQ(resp.lifecycle_state(), v1::FILE_LIFECYCLE_STATE_AVAILABLE);
    EXPECT_GT(resp.available_at_unix_ms(), 0);
}

TEST(FilesServiceImplFinalizeTest, MapsEntityNotFoundToNotFound) {
    auto mock_fin = std::make_shared<MockFinalizationService>();
    mock_fin->should_throw_not_found = true;
    FilesServiceDependencies deps{.finalization_service = mock_fin};
    FilesServiceImpl service(deps, "gateway");

    v1::FinalizeFileUploadRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");

    v1::FinalizeFileUploadResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.FinalizeFileUpload(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
}

TEST(FilesServiceImplFinalizeTest, MapsPreconditionFailureToFailedPrecondition) {
    auto mock_fin = std::make_shared<MockFinalizationService>();
    mock_fin->should_throw_precondition = true;
    FilesServiceDependencies deps{.finalization_service = mock_fin};
    FilesServiceImpl service(deps, "gateway");

    v1::FinalizeFileUploadRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");

    v1::FinalizeFileUploadResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.FinalizeFileUpload(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
}

TEST(FilesServiceImplFinalizeTest, MapsIntegrityMismatchToFailedPrecondition) {
    auto mock_fin = std::make_shared<MockFinalizationService>();
    mock_fin->should_throw_integrity = true;
    FilesServiceDependencies deps{.finalization_service = mock_fin};
    FilesServiceImpl service(deps, "gateway");

    v1::FinalizeFileUploadRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");

    v1::FinalizeFileUploadResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.FinalizeFileUpload(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
}

// ==========================================
// DownloadChunk Unit Tests (FILES-007-T05)
// ==========================================

class MockDownloadManager : public IDownloadManager {
  public:
    bool authorize_download(const std::string&, const std::string&) override { return !should_deny_permission; }

    std::optional<DownloadChunkResult> get_chunk(const std::string&, uint32_t) override { return std::nullopt; }

    DownloadChunkResult get_chunk_versioned(const std::string& file_id, int32_t version_number, uint32_t chunk_index,
                                            const std::string& caller_user_id) override {
        last_file_id = file_id;
        last_version_number = version_number;
        last_chunk_index = chunk_index;
        last_caller_user_id = caller_user_id;

        if (should_deny_permission) {
            throw UnauthorizedFileAccessException("Permission denied");
        }
        if (should_throw_not_found) {
            throw FileNotFoundException("File not found");
        }
        if (should_throw_out_of_range) {
            throw std::out_of_range("Chunk out of range");
        }
        if (should_throw_precondition) {
            throw InvalidDownloadPreconditionException("File is not available");
        }

        std::string payload = "Encrypted chunk data";
        return DownloadChunkResult{.file_id = file_id,
                                   .version_number = version_number == 0 ? 1 : version_number,
                                   .chunk_index = chunk_index,
                                   .encrypted_data = payload,
                                   .chunk_size_bytes = static_cast<uint32_t>(payload.size()),
                                   .ciphertext_sha256 = compute_sha256_hex(payload)};
    }

    DownloadResumeModel prepare_resume_session(const std::string& file_id, int32_t version_number,
                                               uint32_t starting_chunk, const std::string&) override {
        return DownloadResumeModel{.file_id = file_id,
                                   .version_number = version_number,
                                   .starting_chunk = starting_chunk,
                                   .total_chunks = 5,
                                   .total_bytes = 20 * 1024 * 1024,
                                   .ciphertext_sha256 = "dummy"};
    }

    std::string last_file_id;
    int32_t last_version_number{0};
    uint32_t last_chunk_index{0};
    std::string last_caller_user_id;

    bool should_deny_permission{false};
    bool should_throw_not_found{false};
    bool should_throw_out_of_range{false};
    bool should_throw_precondition{false};
};

TEST(FilesServiceImplDownloadTest, RejectsUnauthorizedPeer) {
    FilesServiceImpl service({}, "gateway");
    v1::DownloadChunkRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);

    v1::DownloadChunkResponse resp;
    TestAuthContext untrusted_ctx(true, {{"x509_subject_alternative_name", "DNS:untrusted"}});

    auto status = service.DownloadChunk(&untrusted_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST(FilesServiceImplDownloadTest, RejectsInvalidFileId) {
    FilesServiceImpl service({}, "gateway");
    v1::DownloadChunkRequest req;
    req.set_file_id("bad-uuid");
    req.set_chunk_index(0);

    v1::DownloadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.DownloadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(FilesServiceImplDownloadTest, ReturnsUnavailableWhenManagerNull) {
    FilesServiceDependencies deps{.download_manager = nullptr};
    FilesServiceImpl service(deps, "gateway");

    v1::DownloadChunkRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);

    v1::DownloadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.DownloadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAVAILABLE);
}

TEST(FilesServiceImplDownloadTest, DownloadChunkSuccess) {
    auto mock_mgr = std::make_shared<MockDownloadManager>();
    FilesServiceDependencies deps{.download_manager = mock_mgr};
    FilesServiceImpl service(deps, "gateway");

    v1::DownloadChunkRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(2);

    v1::DownloadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.DownloadChunk(&gateway_ctx, &req, &resp);
    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(resp.file_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    EXPECT_EQ(resp.chunk_index(), 2);
    EXPECT_EQ(resp.encrypted_data(), "Encrypted chunk data");
    EXPECT_EQ(resp.chunk_size_bytes(), 20);
    EXPECT_EQ(resp.ciphertext_sha256(), compute_sha256_hex("Encrypted chunk data"));
}

TEST(FilesServiceImplDownloadTest, MapsPermissionDenied) {
    auto mock_mgr = std::make_shared<MockDownloadManager>();
    mock_mgr->should_deny_permission = true;
    FilesServiceDependencies deps{.download_manager = mock_mgr};
    FilesServiceImpl service(deps, "gateway");

    v1::DownloadChunkRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);

    v1::DownloadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.DownloadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST(FilesServiceImplDownloadTest, MapsFileNotFound) {
    auto mock_mgr = std::make_shared<MockDownloadManager>();
    mock_mgr->should_throw_not_found = true;
    FilesServiceDependencies deps{.download_manager = mock_mgr};
    FilesServiceImpl service(deps, "gateway");

    v1::DownloadChunkRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);

    v1::DownloadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.DownloadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
}

TEST(FilesServiceImplDownloadTest, MapsOutOfRange) {
    auto mock_mgr = std::make_shared<MockDownloadManager>();
    mock_mgr->should_throw_out_of_range = true;
    FilesServiceDependencies deps{.download_manager = mock_mgr};
    FilesServiceImpl service(deps, "gateway");

    v1::DownloadChunkRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(999);

    v1::DownloadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.DownloadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::OUT_OF_RANGE);
}

TEST(FilesServiceImplDownloadTest, MapsPreconditionFailed) {
    auto mock_mgr = std::make_shared<MockDownloadManager>();
    mock_mgr->should_throw_precondition = true;
    FilesServiceDependencies deps{.download_manager = mock_mgr};
    FilesServiceImpl service(deps, "gateway");

    v1::DownloadChunkRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);

    v1::DownloadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.DownloadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
}

// ==========================================
// Capability Authorization Unit Tests (FILES-008-T05)
// ==========================================

class MockCapabilityManager : public IFileCapabilityManager {
  public:
    std::string issue_capability(const std::string&, const std::string&, const std::string&, FileCapabilityOperation,
                                 int32_t, std::chrono::seconds) override {
        return "mock.valid.token";
    }

    FileAccessCapabilityClaims authorize_capability(std::string_view token, const std::string& caller_user_id,
                                                    const std::string& caller_device_id,
                                                    const std::string& target_file_id, FileCapabilityOperation op,
                                                    int32_t version) override {
        last_token = token;
        last_caller_user_id = caller_user_id;
        last_caller_device_id = caller_device_id;
        last_target_file_id = target_file_id;

        if (should_throw_invalid) {
            throw InvalidCapabilityException("Invalid capability signature");
        }
        if (should_throw_unauthorized) {
            throw UnauthorizedFileAccessException("Unauthorized capability access");
        }

        const auto now = std::chrono::system_clock::now();
        return FileAccessCapabilityClaims{.capability_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099",
                                          .user_id = caller_user_id,
                                          .device_id = caller_device_id,
                                          .file_id = target_file_id,
                                          .file_version = version,
                                          .operation = op,
                                          .issued_at = now,
                                          .expires_at = now + std::chrono::minutes(15),
                                          .issuer = "securecloud-files"};
    }

    std::string last_token;
    std::string last_caller_user_id;
    std::string last_caller_device_id;
    std::string last_target_file_id;

    bool should_throw_invalid{false};
    bool should_throw_unauthorized{false};
};

TEST(FilesServiceImplCapabilityTest, AuthorizesValidCapabilityInMetadata) {
    auto mock_cap_mgr = std::make_shared<MockCapabilityManager>();
    auto mock_dl_mgr = std::make_shared<MockDownloadManager>();
    FilesServiceDependencies deps{.download_manager = mock_dl_mgr, .capability_manager = mock_cap_mgr};
    FilesServiceImpl service(deps, "gateway");

    v1::DownloadChunkRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);

    v1::DownloadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    std::multimap<grpc::string_ref, grpc::string_ref> metadata = {
        {"x-user-id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"},
        {"x-device-id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002"},
        {"x-file-access-capability", "valid.signed.capability"}};

    auto status = service.DownloadChunk(&gateway_ctx, &req, &resp, metadata);
    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(mock_cap_mgr->last_token, "valid.signed.capability");
    EXPECT_EQ(mock_cap_mgr->last_caller_user_id, "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    EXPECT_EQ(mock_cap_mgr->last_caller_device_id, "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    EXPECT_EQ(mock_cap_mgr->last_target_file_id, "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
}

TEST(FilesServiceImplCapabilityTest, MapsMalformedCapabilityToUnauthenticated) {
    auto mock_cap_mgr = std::make_shared<MockCapabilityManager>();
    mock_cap_mgr->should_throw_invalid = true;
    auto mock_dl_mgr = std::make_shared<MockDownloadManager>();
    FilesServiceDependencies deps{.download_manager = mock_dl_mgr, .capability_manager = mock_cap_mgr};
    FilesServiceImpl service(deps, "gateway");

    v1::DownloadChunkRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);

    v1::DownloadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    std::multimap<grpc::string_ref, grpc::string_ref> metadata = {
        {"x-user-id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"},
        {"x-device-id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002"},
        {"x-file-access-capability", "corrupted.token"}};

    auto status = service.DownloadChunk(&gateway_ctx, &req, &resp, metadata);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

TEST(FilesServiceImplCapabilityTest, MapsUnauthorizedCapabilityToPermissionDenied) {
    auto mock_cap_mgr = std::make_shared<MockCapabilityManager>();
    mock_cap_mgr->should_throw_unauthorized = true;
    auto mock_dl_mgr = std::make_shared<MockDownloadManager>();
    FilesServiceDependencies deps{.download_manager = mock_dl_mgr, .capability_manager = mock_cap_mgr};
    FilesServiceImpl service(deps, "gateway");

    v1::DownloadChunkRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);

    v1::DownloadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    std::multimap<grpc::string_ref, grpc::string_ref> metadata = {
        {"x-user-id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"},
        {"x-device-id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002"},
        {"x-file-access-capability", "valid.token.wrong.user"}};

    auto status = service.DownloadChunk(&gateway_ctx, &req, &resp, metadata);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

// ============================================================================
// FILES-009 Concurrency Bulkhead, Backpressure & Resource Bounds Unit Tests
// ============================================================================

TEST(FilesServiceImplBulkheadTest, MapsMetadataBulkheadSaturationToResourceExhausted) {
    auto mock_lifecycle = std::make_shared<TestMockLifecycleService>();
    auto metadata_bulkhead = ConcurrencyBulkhead::create("metadata", 1, std::chrono::milliseconds(20));

    FilesServiceDependencies deps{
        .lifecycle_service = mock_lifecycle,
        .metadata_bulkhead = metadata_bulkhead
    };
    FilesServiceImpl service(deps, "gateway");

    // Saturate the metadata domain with a held permit
    auto held_permit = metadata_bulkhead->try_acquire();
    ASSERT_TRUE(held_permit.holds_permit());

    v1::GetFileMetadataRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    v1::GetFileMetadataResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.GetFileMetadata(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
    EXPECT_NE(status.error_message().find("Metadata concurrency capacity exhausted"), std::string::npos);

    // Release permit and verify subsequent call proceeds past bulkhead
    held_permit.release();
    auto status2 = service.GetFileMetadata(&gateway_ctx, &req, &resp);
    EXPECT_NE(status2.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
}

TEST(FilesServiceImplBulkheadTest, MapsUploadBulkheadSaturationToResourceExhausted) {
    auto upload_bulkhead = ConcurrencyBulkhead::create("upload", 1, std::chrono::milliseconds(20));

    FilesServiceDependencies deps{
        .upload_bulkhead = upload_bulkhead
    };
    FilesServiceImpl service(deps, "gateway");

    // Hold the only permit in upload domain
    auto held_permit = upload_bulkhead->try_acquire();
    ASSERT_TRUE(held_permit.holds_permit());

    v1::UploadChunkRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);
    req.set_chunk_size_bytes(100);
    req.set_encrypted_data(std::string(100, 'X'));
    v1::UploadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.UploadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
    EXPECT_NE(status.error_message().find("Upload concurrency capacity exhausted"), std::string::npos);
}

TEST(FilesServiceImplBulkheadTest, MapsDownloadBulkheadSaturationToResourceExhausted) {
    auto download_bulkhead = ConcurrencyBulkhead::create("download", 1, std::chrono::milliseconds(20));

    FilesServiceDependencies deps{
        .download_bulkhead = download_bulkhead
    };
    FilesServiceImpl service(deps, "gateway");

    auto held_permit = download_bulkhead->try_acquire();
    ASSERT_TRUE(held_permit.holds_permit());

    v1::DownloadChunkRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);
    v1::DownloadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.DownloadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
    EXPECT_NE(status.error_message().find("Download concurrency capacity exhausted"), std::string::npos);
}

TEST(FilesServiceImplResourceTest, RejectsOversizedChunkUploadRequest) {
    FilesServiceDependencies deps{
        .max_chunk_request_bytes = 1024 // 1 KiB ceiling for testing
    };
    FilesServiceImpl service(deps, "gateway");

    v1::UploadChunkRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);
    req.set_chunk_size_bytes(2048); // Exceeds 1024
    req.set_encrypted_data(std::string(2048, 'X'));
    v1::UploadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.UploadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_NE(status.error_message().find("exceeds maximum allowed size"), std::string::npos);
}

TEST(FilesServiceImplResourceTest, RejectsOversizedFileTransferRequest) {
    FilesServiceDependencies deps{
        .max_file_transfer_bytes = 5000 // 5000 bytes ceiling
    };
    FilesServiceImpl service(deps, "gateway");

    v1::CreateFileUploadRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_owner_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    req.set_owner_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    req.set_encrypted_size_bytes(6000); // Exceeds 5000
    v1::CreateFileUploadResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.CreateFileUpload(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_NE(status.error_message().find("exceeds maximum allowed size"), std::string::npos);
}

TEST(FilesServiceImplResourceTest, MapsMemoryBudgetExhaustionToResourceExhausted) {
    auto memory_tracker = MemoryBufferTracker::create(500); // 500 bytes budget

    FilesServiceDependencies deps{
        .memory_tracker = memory_tracker,
        .max_chunk_request_bytes = 1000
    };
    FilesServiceImpl service(deps, "gateway");

    // Exhaust memory budget manually
    auto reserved = memory_tracker->try_reserve(450);
    ASSERT_TRUE(reserved.holds_reservation());

    v1::UploadChunkRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);
    req.set_chunk_size_bytes(100); // 450 + 100 > 500 => Exhausted
    req.set_encrypted_data(std::string(100, 'X'));
    v1::UploadChunkResponse resp;
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto status = service.UploadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
    EXPECT_NE(status.error_message().find("Global memory buffer budget exhausted"), std::string::npos);
}

} // namespace

} // namespace securecloud::files::service
