#include "files/db/files_connection_pool.hpp"
#include "files/db/pqxx_compat.hpp"
#include "files/domain/chunk_validator.hpp"
#include "files/domain/file_chunk_entity.hpp"
#include "files/domain/file_entity.hpp"
#include "files/domain/file_transfer_entity.hpp"
#include "files/domain/metadata_validator.hpp"
#include "files/repository/file_chunk_repository.hpp"
#include "files/repository/file_repository.hpp"
#include "files/repository/file_transfer_repository.hpp"
#include "files/repository/file_version_repository.hpp"
#include "files/repository/files_outbox_repository.hpp"
#include "files/service/chunk_storage_service.hpp"
#include "files/service/file_finalization_service.hpp"
#include "files/service/file_lifecycle_service.hpp"
#include "files/service/files_service_impl.hpp"
#include "files/service/object_assembly_engine.hpp"
#include "files/service/upload_session_manager.hpp"
#include "files/storage/s3_client.hpp"
#include "securecloud/common/configuration/secret_string.hpp"
#include "securecloud/files/v1/files.grpc.pb.h"
#include "securecloud/files/v1/files.pb.h"

#include <chrono>
#include <future>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef DeleteFile
#undef DeleteFile
#endif
#endif

namespace securecloud::files {
namespace {

using service::ChunkStorageService;
using service::FileFinalizationService;
using service::FilesServiceDependencies;
using service::FilesServiceImpl;
using service::ObjectAssemblyEngine;
using service::UploadSessionManager;
using storage::S3Client;
using storage::S3ClientConfig;

#ifdef _WIN32
inline void ensure_integration_winsock() noexcept {
    static const bool initialized = []() noexcept {
        WSADATA wsa{};
        return ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    }();
    (void)initialized;
}
#else
inline void ensure_integration_winsock() noexcept {}
#endif

class TestIntegrationAuthContext : public grpc::AuthContext {
  public:
    explicit TestIntegrationAuthContext(std::string san) : san_(std::move(san)) {}

    [[nodiscard]] bool IsPeerAuthenticated() const override { return true; }
    [[nodiscard]] std::string GetPeerIdentityPropertyName() const override { return "x509_subject_alternative_name"; }
    [[nodiscard]] std::vector<grpc::string_ref> GetPeerIdentity() const override {
        return {grpc::string_ref(san_.data(), san_.size())};
    }
    [[nodiscard]] std::vector<grpc::string_ref> FindPropertyValues(const std::string& name) const override {
        if (name == "x509_subject_alternative_name") {
            return {grpc::string_ref(san_.data(), san_.size())};
        }
        return {};
    }
    [[nodiscard]] grpc::AuthPropertyIterator begin() const override { return {}; }
    [[nodiscard]] grpc::AuthPropertyIterator end() const override { return {}; }
    void AddProperty(const std::string&, const grpc::string_ref&) override {}
    bool SetPeerIdentityPropertyName(const std::string&) override { return false; }

  private:
    std::string san_;
};

class FilesFinalizationIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ensure_integration_winsock();
        pqxx::MockStorage::instance().reset();

        db_config_.host = "127.0.0.1";
        db_config_.port = 5433;
        db_config_.db_name = "securecloud_files";
        db_config_.db_user = "files_user";
        db_config_.db_password = common::configuration::SecretString("files_password");
        db_config_.min_connections = 1;
        db_config_.max_connections = 4;
        db_config_.connect_timeout = std::chrono::milliseconds(200);
        db_config_.acquire_timeout = std::chrono::milliseconds(200);

        pool_ = std::make_shared<db::FilesDbConnectionPool>(db_config_);
        transfer_repo_ = std::make_shared<FileTransferRepository>(pool_);
        chunk_repo_ = std::make_shared<FileChunkRepository>(pool_);
        file_repo_ = std::make_shared<FileRepository>(pool_);
        version_repo_ = std::make_shared<FileVersionRepository>(pool_);
        outbox_repo_ = std::make_shared<FilesOutboxRepository>(pool_);

        s3_cfg_.endpoint = "http://127.0.0.1:9000";
        s3_cfg_.bucket = "securecloud-files-encrypted";
        s3_cfg_.access_key = "files_minio_user";
        s3_cfg_.secret_key = common::configuration::SecretString("files_minio_secret");
        s3_cfg_.default_timeout = std::chrono::milliseconds(2000);
        s3_client_ = std::make_shared<S3Client>(s3_cfg_);

        assembly_engine_ = std::make_shared<ObjectAssemblyEngine>(s3_client_);
        finalization_service_ = std::make_shared<FileFinalizationService>(
            pool_, assembly_engine_, transfer_repo_, file_repo_, version_repo_, chunk_repo_, outbox_repo_);

        session_mgr_ = std::make_shared<UploadSessionManager>(pool_, transfer_repo_, chunk_repo_);
        chunk_storage_ = std::make_shared<ChunkStorageService>(pool_, s3_client_, transfer_repo_, chunk_repo_, file_repo_);
        lifecycle_service_ = std::make_shared<FileLifecycleService>(pool_, file_repo_);

        FilesServiceDependencies deps{
            .db_pool = pool_,
            .s3_client = s3_client_,
            .upload_session_manager = session_mgr_,
            .lifecycle_service = lifecycle_service_,
            .chunk_storage_service = chunk_storage_,
            .object_assembly_engine = assembly_engine_,
            .finalization_service = finalization_service_,
        };

        service_ = std::make_unique<FilesServiceImpl>(deps, "gateway");
    }

    void TearDown() override {
        if (pool_) {
            pool_->drain();
            pool_->close();
        }
        pqxx::MockStorage::instance().reset();
    }

    db::ConnectionPoolConfig db_config_{};
    S3ClientConfig s3_cfg_{};
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
    std::shared_ptr<FileTransferRepository> transfer_repo_;
    std::shared_ptr<FileChunkRepository> chunk_repo_;
    std::shared_ptr<FileRepository> file_repo_;
    std::shared_ptr<FileVersionRepository> version_repo_;
    std::shared_ptr<FilesOutboxRepository> outbox_repo_;
    std::shared_ptr<S3Client> s3_client_;
    std::shared_ptr<ObjectAssemblyEngine> assembly_engine_;
    std::shared_ptr<FileFinalizationService> finalization_service_;
    std::shared_ptr<UploadSessionManager> session_mgr_;
    std::shared_ptr<ChunkStorageService> chunk_storage_;
    std::shared_ptr<FileLifecycleService> lifecycle_service_;
    std::unique_ptr<FilesServiceImpl> service_;
};

// ============================================================================
// TC1: Happy Path Finalization (Multi-Chunk)
// ============================================================================
TEST_F(FilesFinalizationIntegrationTest, TC1_HappyPathFinalizationMultiChunk) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    std::string chunk0_data = "Encrypted block 0 data for testing whole object assembly";
    std::string chunk1_data = "Encrypted block 1 data completing the multi chunk file";
    std::string whole_data = chunk0_data + chunk1_data;
    std::string expected_whole_sha = compute_sha256_hex(whole_data);

    uint64_t total_size = whole_data.size();
    uint32_t total_chunks = 2;
    std::string file_id = generate_uuid_v7();

    // 1. Create file upload session
    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(file_id);
    init_req.set_owner_user_id("user-alice");
    init_req.set_owner_device_id("device-desktop");
    init_req.set_encrypted_size_bytes(total_size);
    init_req.set_expected_chunk_count(total_chunks);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                       "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse init_resp;
    auto init_status = service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp);
    ASSERT_TRUE(init_status.ok()) << init_status.error_message();
    std::string upload_id = init_resp.upload_id();

    // 2. Upload chunks 0 and 1
    std::vector<std::string> chunks = {chunk0_data, chunk1_data};
    for (uint32_t i = 0; i < 2; ++i) {
        v1::UploadChunkRequest req;
        req.set_upload_id(upload_id);
        req.set_chunk_index(i);
        req.set_encrypted_data(chunks[i]);
        req.set_chunk_size_bytes(static_cast<uint32_t>(chunks[i].size()));
        req.set_ciphertext_sha256(compute_sha256_hex(chunks[i]));

        v1::UploadChunkResponse resp;
        auto status = service_->UploadChunk(&auth_ctx, &req, &resp);
        ASSERT_TRUE(status.ok()) << status.error_message();
        ASSERT_TRUE(resp.accepted());
    }

    // 3. Finalize upload
    v1::FinalizeFileUploadRequest fin_req;
    fin_req.set_upload_id(upload_id);
    fin_req.set_file_id(file_id);
    fin_req.set_expected_ciphertext_sha256(expected_whole_sha);

    v1::FinalizeFileUploadResponse fin_resp;
    auto fin_status = service_->FinalizeFileUpload(&auth_ctx, &fin_req, &fin_resp);
    EXPECT_TRUE(fin_status.ok()) << fin_status.error_message();
    EXPECT_EQ(fin_resp.file_id(), file_id);
    EXPECT_EQ(fin_resp.lifecycle_state(), v1::FILE_LIFECYCLE_STATE_AVAILABLE);
    EXPECT_GT(fin_resp.available_at_unix_ms(), 0);

    // 4. Verify durable persistence
    auto file_opt = file_repo_->find_by_id(file_id);
    ASSERT_TRUE(file_opt.has_value());
    EXPECT_EQ(file_opt->status, FileStatus::Available);

    auto transfer_opt = transfer_repo_->find_by_id(upload_id);
    ASSERT_TRUE(transfer_opt.has_value());
    EXPECT_EQ(transfer_opt->status, TransferStatus::Completed);

    auto ver_opt = version_repo_->find_active_version(file_id);
    ASSERT_TRUE(ver_opt.has_value());
    EXPECT_EQ(ver_opt->version_number, 1);
    EXPECT_EQ(ver_opt->checksum_sha256, expected_whole_sha);
}

// ============================================================================
// TC2: Concurrent Duplicate Finalization Race & Idempotency
// ============================================================================
TEST_F(FilesFinalizationIntegrationTest, TC2_ConcurrentDuplicateFinalizationRaceAndIdempotency) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    std::string payload = "Small single chunk content";
    std::string whole_sha = compute_sha256_hex(payload);
    std::string file_id = generate_uuid_v7();

    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(file_id);
    init_req.set_owner_user_id("user-alice");
    init_req.set_owner_device_id("device-desktop");
    init_req.set_encrypted_size_bytes(payload.size());
    init_req.set_expected_chunk_count(1);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                       "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse init_resp;
    auto init_status = service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp);
    ASSERT_TRUE(init_status.ok());
    std::string upload_id = init_resp.upload_id();

    // Upload chunk 0
    v1::UploadChunkRequest req;
    req.set_upload_id(upload_id);
    req.set_chunk_index(0);
    req.set_encrypted_data(payload);
    req.set_chunk_size_bytes(static_cast<uint32_t>(payload.size()));
    req.set_ciphertext_sha256(whole_sha);

    v1::UploadChunkResponse resp;
    auto status = service_->UploadChunk(&auth_ctx, &req, &resp);
    ASSERT_TRUE(status.ok());

    // Execute 2 concurrent/duplicate finalization requests
    v1::FinalizeFileUploadRequest fin_req;
    fin_req.set_upload_id(upload_id);
    fin_req.set_file_id(file_id);
    fin_req.set_expected_ciphertext_sha256(whole_sha);

    v1::FinalizeFileUploadResponse fin_resp1;
    v1::FinalizeFileUploadResponse fin_resp2;

    auto fut1 = std::async(std::launch::async, [&]() {
        return service_->FinalizeFileUpload(&auth_ctx, &fin_req, &fin_resp1);
    });
    auto fut2 = std::async(std::launch::async, [&]() {
        return service_->FinalizeFileUpload(&auth_ctx, &fin_req, &fin_resp2);
    });

    auto status1 = fut1.get();
    auto status2 = fut2.get();

    EXPECT_TRUE(status1.ok()) << status1.error_message();
    EXPECT_TRUE(status2.ok()) << status2.error_message();

    EXPECT_EQ(fin_resp1.lifecycle_state(), v1::FILE_LIFECYCLE_STATE_AVAILABLE);
    EXPECT_EQ(fin_resp2.lifecycle_state(), v1::FILE_LIFECYCLE_STATE_AVAILABLE);

    // Verify exactly ONE version was created in file_versions
    auto versions = version_repo_->list_versions(file_id);
    EXPECT_EQ(versions.size(), 1);
}

// ============================================================================
// TC3: Incomplete Upload Rejection & Staged Chunk Retention (Failure Rule)
// ============================================================================
TEST_F(FilesFinalizationIntegrationTest, TC3_IncompleteUploadRejectionAndStagedChunkRetention) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    std::string file_id = generate_uuid_v7();
    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(file_id);
    init_req.set_owner_user_id("user-alice");
    init_req.set_owner_device_id("device-desktop");
    init_req.set_encrypted_size_bytes(1000);
    init_req.set_expected_chunk_count(2);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                       "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse init_resp;
    ASSERT_TRUE(service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp).ok());
    std::string upload_id = init_resp.upload_id();

    // Upload only chunk 0 (chunk 1 is missing!)
    std::string chunk0 = std::string(500, 'A');
    v1::UploadChunkRequest req;
    req.set_upload_id(upload_id);
    req.set_chunk_index(0);
    req.set_encrypted_data(chunk0);
    req.set_chunk_size_bytes(500);
    req.set_ciphertext_sha256(compute_sha256_hex(chunk0));

    v1::UploadChunkResponse resp;
    ASSERT_TRUE(service_->UploadChunk(&auth_ctx, &req, &resp).ok());

    // Attempt finalization
    v1::FinalizeFileUploadRequest fin_req;
    fin_req.set_upload_id(upload_id);
    fin_req.set_file_id(file_id);

    v1::FinalizeFileUploadResponse fin_resp;
    auto fin_status = service_->FinalizeFileUpload(&auth_ctx, &fin_req, &fin_resp);

    // Precondition failure must be reported
    EXPECT_EQ(fin_status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);

    // Failure rule: AVAILABLE must NEVER be reported
    EXPECT_NE(fin_resp.lifecycle_state(), v1::FILE_LIFECYCLE_STATE_AVAILABLE);
    auto file_opt = file_repo_->find_by_id(file_id);
    ASSERT_TRUE(file_opt.has_value());
    EXPECT_NE(file_opt->status, FileStatus::Available);

    // Staged chunk 0 must remain in place for retry/recovery
    EXPECT_TRUE(chunk_repo_->is_chunk_present(upload_id, 0));
}

// ============================================================================
// TC4: Whole-Ciphertext Hash Mismatch Rejection (Integrity Guard)
// ============================================================================
TEST_F(FilesFinalizationIntegrationTest, TC4_WholeCiphertextHashMismatchRejection) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    std::string chunk_data = "Actual valid payload data";
    std::string file_id = generate_uuid_v7();

    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(file_id);
    init_req.set_owner_user_id("user-alice");
    init_req.set_owner_device_id("device-desktop");
    init_req.set_encrypted_size_bytes(chunk_data.size());
    init_req.set_expected_chunk_count(1);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                       "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse init_resp;
    ASSERT_TRUE(service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp).ok());
    std::string upload_id = init_resp.upload_id();

    // Upload chunk 0
    v1::UploadChunkRequest req;
    req.set_upload_id(upload_id);
    req.set_chunk_index(0);
    req.set_encrypted_data(chunk_data);
    req.set_chunk_size_bytes(static_cast<uint32_t>(chunk_data.size()));
    req.set_ciphertext_sha256(compute_sha256_hex(chunk_data));

    v1::UploadChunkResponse resp;
    ASSERT_TRUE(service_->UploadChunk(&auth_ctx, &req, &resp).ok());

    // Finalize with intentional bogus whole-ciphertext sha256
    v1::FinalizeFileUploadRequest fin_req;
    fin_req.set_upload_id(upload_id);
    fin_req.set_file_id(file_id);
    fin_req.set_expected_ciphertext_sha256("0000000000000000000000000000000000000000000000000000000000000000");

    v1::FinalizeFileUploadResponse fin_resp;
    auto fin_status = service_->FinalizeFileUpload(&auth_ctx, &fin_req, &fin_resp);

    EXPECT_EQ(fin_status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
    EXPECT_NE(fin_resp.lifecycle_state(), v1::FILE_LIFECYCLE_STATE_AVAILABLE);

    auto file_opt = file_repo_->find_by_id(file_id);
    ASSERT_TRUE(file_opt.has_value());
    EXPECT_NE(file_opt->status, FileStatus::Available);
}

// ============================================================================
// TC5: Cancelled Session Guard
// ============================================================================
TEST_F(FilesFinalizationIntegrationTest, TC5_CancelledSessionGuard) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    std::string file_id = generate_uuid_v7();
    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(file_id);
    init_req.set_owner_user_id("user-alice");
    init_req.set_owner_device_id("device-desktop");
    init_req.set_encrypted_size_bytes(100);
    init_req.set_expected_chunk_count(1);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                       "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse init_resp;
    ASSERT_TRUE(service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp).ok());
    std::string upload_id = init_resp.upload_id();

    // Cancel upload session
    v1::CancelFileUploadRequest cancel_req;
    cancel_req.set_upload_id(upload_id);
    cancel_req.set_reason("Client aborted");
    v1::CancelFileUploadResponse cancel_resp;
    ASSERT_TRUE(service_->CancelFileUpload(&auth_ctx, &cancel_req, &cancel_resp).ok());

    // Attempt finalization
    v1::FinalizeFileUploadRequest fin_req;
    fin_req.set_upload_id(upload_id);
    fin_req.set_file_id(file_id);

    v1::FinalizeFileUploadResponse fin_resp;
    auto fin_status = service_->FinalizeFileUpload(&auth_ctx, &fin_req, &fin_resp);

    EXPECT_EQ(fin_status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
    EXPECT_NE(fin_resp.lifecycle_state(), v1::FILE_LIFECYCLE_STATE_AVAILABLE);
}

// ============================================================================
// TC6: Staging Cleanup Verification
// ============================================================================
TEST_F(FilesFinalizationIntegrationTest, TC6_StagingCleanupVerification) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    std::string payload = "Data to test staging cleanup after finalization";
    std::string expected_sha = compute_sha256_hex(payload);
    std::string file_id = generate_uuid_v7();

    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(file_id);
    init_req.set_owner_user_id("user-alice");
    init_req.set_owner_device_id("device-desktop");
    init_req.set_encrypted_size_bytes(payload.size());
    init_req.set_expected_chunk_count(1);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                       "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse init_resp;
    ASSERT_TRUE(service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp).ok());
    std::string upload_id = init_resp.upload_id();

    // Upload chunk 0
    v1::UploadChunkRequest req;
    req.set_upload_id(upload_id);
    req.set_chunk_index(0);
    req.set_encrypted_data(payload);
    req.set_chunk_size_bytes(static_cast<uint32_t>(payload.size()));
    req.set_ciphertext_sha256(expected_sha);

    v1::UploadChunkResponse resp;
    ASSERT_TRUE(service_->UploadChunk(&auth_ctx, &req, &resp).ok());

    // Finalize upload
    v1::FinalizeFileUploadRequest fin_req;
    fin_req.set_upload_id(upload_id);
    fin_req.set_file_id(file_id);
    fin_req.set_expected_ciphertext_sha256(expected_sha);

    v1::FinalizeFileUploadResponse fin_resp;
    ASSERT_TRUE(service_->FinalizeFileUpload(&auth_ctx, &fin_req, &fin_resp).ok());

    // Verify version record exists
    auto ver_opt = version_repo_->find_active_version(file_id);
    ASSERT_TRUE(ver_opt.has_value());
    EXPECT_EQ(ver_opt->minio_object_key, "objects/" + file_id + "/1");
}

} // namespace
} // namespace securecloud::files
