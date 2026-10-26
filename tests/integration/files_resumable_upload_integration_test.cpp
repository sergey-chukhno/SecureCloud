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
#include "files/service/chunk_storage_service.hpp"
#include "files/service/file_lifecycle_service.hpp"
#include "files/service/files_service_impl.hpp"
#include "files/service/upload_session_manager.hpp"
#include "files/storage/s3_client.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "securecloud/files/v1/files.grpc.pb.h"
#include "securecloud/files/v1/files.pb.h"
#include "securecloud/health/transport_probe.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
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
using service::FilesServiceDependencies;
using service::FilesServiceImpl;
using service::UploadSessionManager;
using storage::S3Client;
using storage::S3ClientConfig;

class MockHttpTransport : public storage::IHttpTransport {
  public:
    storage::HttpResponse execute(const storage::HttpRequest& req) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (req.method == "PUT") {
            storage_[req.path] = req.body;
            return storage::HttpResponse{
                .status_code = 200,
                .status_message = "OK",
                .headers = {{"ETag", "\"d41d8cd98f00b204e9800998ecf8427e\""}},
                .body = "",
            };
        } else if (req.method == "GET") {
            auto it = storage_.find(req.path);
            if (it != storage_.end()) {
                return storage::HttpResponse{
                    .status_code = 200,
                    .status_message = "OK",
                    .headers = {{"Content-Length", std::to_string(it->second.size())}},
                    .body = it->second,
                };
            }
            return storage::HttpResponse{.status_code = 404, .status_message = "Not Found"};
        } else if (req.method == "HEAD") {
            auto it = storage_.find(req.path);
            if (it != storage_.end()) {
                return storage::HttpResponse{
                    .status_code = 200,
                    .status_message = "OK",
                    .headers = {{"Content-Length", std::to_string(it->second.size())}},
                    .body = "",
                };
            }
            return storage::HttpResponse{.status_code = 404, .status_message = "Not Found"};
        }
        return storage::HttpResponse{.status_code = 200, .status_message = "OK"};
    }

  private:
    std::mutex mu_;
    std::unordered_map<std::string, std::string> storage_;
};

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

class TestAuthPropertyIterator : public grpc::AuthPropertyIterator {
  public:
    TestAuthPropertyIterator() = default;
};

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
    [[nodiscard]] grpc::AuthPropertyIterator begin() const override { return TestAuthPropertyIterator{}; }
    [[nodiscard]] grpc::AuthPropertyIterator end() const override { return TestAuthPropertyIterator{}; }
    void AddProperty(const std::string&, const grpc::string_ref&) override {}
    bool SetPeerIdentityPropertyName(const std::string&) override { return false; }

  private:
    std::string san_;
};

class FilesResumableUploadIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ensure_integration_winsock();
        pqxx::MockStorage::instance().reset();

        db_config_.host = "127.0.0.1";
        db_config_.port = 5433; // Port 5433 invariant
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

        s3_cfg_.endpoint = "http://127.0.0.1:9000";
        s3_cfg_.bucket = "securecloud-files-encrypted";
        s3_cfg_.access_key = "files_minio_user";
        s3_cfg_.secret_key = common::configuration::SecretString("files_minio_secret");
        s3_cfg_.default_timeout = std::chrono::milliseconds(2000);
        auto transport = std::make_shared<MockHttpTransport>();
        s3_client_ = std::make_shared<S3Client>(s3_cfg_, transport);

        session_mgr_ = std::make_shared<UploadSessionManager>(pool_, transfer_repo_, chunk_repo_);
        chunk_storage_ =
            std::make_shared<ChunkStorageService>(pool_, s3_client_, transfer_repo_, chunk_repo_, file_repo_);
        lifecycle_service_ = std::make_shared<FileLifecycleService>(pool_, file_repo_);

        FilesServiceDependencies deps{
            .db_pool = pool_,
            .s3_client = s3_client_,
            .upload_session_manager = session_mgr_,
            .lifecycle_service = lifecycle_service_,
            .chunk_storage_service = chunk_storage_,
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
    std::shared_ptr<S3Client> s3_client_;
    std::shared_ptr<UploadSessionManager> session_mgr_;
    std::shared_ptr<ChunkStorageService> chunk_storage_;
    std::shared_ptr<FileLifecycleService> lifecycle_service_;
    std::unique_ptr<FilesServiceImpl> service_;
};

// ============================================================================
// TC1: Multi-Chunk Out-of-Order Upload Progression
// ============================================================================
TEST_F(FilesResumableUploadIntegrationTest, TC1_MultiChunkOutOfOrderUploadProgression) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    // File: 5 chunks * 4 MiB = 20 MiB
    uint64_t total_size = 5ULL * 4ULL * 1024ULL * 1024ULL;
    uint32_t total_chunks = 5;

    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(generate_uuid_v7());
    init_req.set_owner_user_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d40");
    init_req.set_owner_device_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d41");
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

    // Prepare 5 chunks of 4 MiB
    std::vector<std::string> chunk_payloads(5);
    std::vector<std::string> chunk_hashes(5);
    for (size_t i = 0; i < 5; ++i) {
        chunk_payloads[i] = std::string(k_standard_chunk_size, static_cast<char>('A' + i));
        chunk_hashes[i] = compute_sha256_hex(chunk_payloads[i]);
    }

    // Upload in scrambled order: chunk 3, chunk 0, chunk 4, chunk 1, chunk 2
    std::vector<uint32_t> upload_order = {3, 0, 4, 1, 2};
    for (uint32_t idx : upload_order) {
        v1::UploadChunkRequest req;
        req.set_upload_id(upload_id);
        req.set_chunk_index(idx);
        req.set_encrypted_data(chunk_payloads[idx]);
        req.set_chunk_size_bytes(static_cast<uint32_t>(chunk_payloads[idx].size()));
        req.set_ciphertext_sha256(chunk_hashes[idx]);

        v1::UploadChunkResponse resp;
        auto status = service_->UploadChunk(&auth_ctx, &req, &resp);
        EXPECT_TRUE(status.ok()) << "Failed uploading chunk " << idx << ": " << status.error_message();
        EXPECT_TRUE(resp.accepted());
        EXPECT_EQ(resp.received_sha256(), chunk_hashes[idx]);
    }

    auto progress = session_mgr_->get_transfer_progress(upload_id);
    EXPECT_EQ(progress.accepted_chunks, 5);
    EXPECT_TRUE(progress.missing_chunk_indices.empty());
    EXPECT_TRUE(progress.is_complete);
}

// ============================================================================
// TC2: Idempotent Duplicate Chunk Replay
// ============================================================================
TEST_F(FilesResumableUploadIntegrationTest, TC2_IdempotentDuplicateChunkReplay) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    uint64_t total_size = 3ULL * 4ULL * 1024ULL * 1024ULL;
    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(generate_uuid_v7());
    init_req.set_owner_user_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d40");
    init_req.set_owner_device_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d41");
    init_req.set_encrypted_size_bytes(total_size);
    init_req.set_expected_chunk_count(3);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                        "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse init_resp;
    auto init_status = service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp);
    ASSERT_TRUE(init_status.ok());
    std::string upload_id = init_resp.upload_id();

    std::string payload(k_standard_chunk_size, 'X');
    std::string hash = compute_sha256_hex(payload);

    v1::UploadChunkRequest req;
    req.set_upload_id(upload_id);
    req.set_chunk_index(0);
    req.set_encrypted_data(payload);
    req.set_chunk_size_bytes(static_cast<uint32_t>(payload.size()));
    req.set_ciphertext_sha256(hash);

    // Initial upload
    v1::UploadChunkResponse resp1;
    auto status1 = service_->UploadChunk(&auth_ctx, &req, &resp1);
    EXPECT_TRUE(status1.ok());
    EXPECT_TRUE(resp1.accepted());

    // Duplicate replay with identical hash
    v1::UploadChunkResponse resp2;
    auto status2 = service_->UploadChunk(&auth_ctx, &req, &resp2);
    EXPECT_TRUE(status2.ok());
    EXPECT_TRUE(resp2.accepted());
    EXPECT_EQ(resp2.received_sha256(), hash);

    auto progress = session_mgr_->get_transfer_progress(upload_id);
    EXPECT_EQ(progress.accepted_chunks, 1); // No double count
}

// ============================================================================
// TC3: Content Hash Collision / Conflict Rejection
// ============================================================================
TEST_F(FilesResumableUploadIntegrationTest, TC3_ContentHashCollisionConflictRejection) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    uint64_t total_size = 2ULL * 4ULL * 1024ULL * 1024ULL;
    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(generate_uuid_v7());
    init_req.set_owner_user_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d40");
    init_req.set_owner_device_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d41");
    init_req.set_encrypted_size_bytes(total_size);
    init_req.set_expected_chunk_count(2);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                        "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse init_resp;
    auto init_status = service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp);
    ASSERT_TRUE(init_status.ok());
    std::string upload_id = init_resp.upload_id();

    // Submit legitimate chunk 0
    std::string payload1(k_standard_chunk_size, '1');
    std::string hash1 = compute_sha256_hex(payload1);

    v1::UploadChunkRequest req1;
    req1.set_upload_id(upload_id);
    req1.set_chunk_index(0);
    req1.set_encrypted_data(payload1);
    req1.set_chunk_size_bytes(static_cast<uint32_t>(payload1.size()));
    req1.set_ciphertext_sha256(hash1);

    v1::UploadChunkResponse resp1;
    auto status1 = service_->UploadChunk(&auth_ctx, &req1, &resp1);
    EXPECT_TRUE(status1.ok());

    // Submit conflicting chunk 0 with different content and differing hash
    std::string payload2(k_standard_chunk_size, '2');
    std::string hash2 = compute_sha256_hex(payload2);

    v1::UploadChunkRequest req2;
    req2.set_upload_id(upload_id);
    req2.set_chunk_index(0);
    req2.set_encrypted_data(payload2);
    req2.set_chunk_size_bytes(static_cast<uint32_t>(payload2.size()));
    req2.set_ciphertext_sha256(hash2);

    v1::UploadChunkResponse resp2;
    auto status2 = service_->UploadChunk(&auth_ctx, &req2, &resp2);
    EXPECT_EQ(status2.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
}

// ============================================================================
// TC4: Service Restart Crash Recovery
// ============================================================================
TEST_F(FilesResumableUploadIntegrationTest, TC4_ServiceRestartCrashRecovery) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    uint64_t total_size = 6ULL * 4ULL * 1024ULL * 1024ULL;
    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(generate_uuid_v7());
    init_req.set_owner_user_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d40");
    init_req.set_owner_device_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d41");
    init_req.set_encrypted_size_bytes(total_size);
    init_req.set_expected_chunk_count(6);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                        "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse init_resp;
    auto init_status = service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp);
    ASSERT_TRUE(init_status.ok());
    std::string upload_id = init_resp.upload_id();

    // Upload chunks 0, 1, 2
    for (uint32_t i = 0; i < 3; ++i) {
        std::string payload(k_standard_chunk_size, static_cast<char>('0' + i));
        std::string hash = compute_sha256_hex(payload);

        v1::UploadChunkRequest req;
        req.set_upload_id(upload_id);
        req.set_chunk_index(i);
        req.set_encrypted_data(payload);
        req.set_chunk_size_bytes(static_cast<uint32_t>(payload.size()));
        req.set_ciphertext_sha256(hash);

        v1::UploadChunkResponse resp;
        auto s = service_->UploadChunk(&auth_ctx, &req, &resp);
        EXPECT_TRUE(s.ok());
    }

    // Simulate abrupt crash & restart: destroy service and session manager completely
    service_.reset();
    session_mgr_.reset();

    // Create fresh new service instances with clean in-memory cache
    auto new_session_mgr = std::make_shared<UploadSessionManager>(pool_, transfer_repo_, chunk_repo_);
    auto new_chunk_storage =
        std::make_shared<ChunkStorageService>(pool_, s3_client_, transfer_repo_, chunk_repo_, file_repo_);
    auto new_lifecycle = std::make_shared<FileLifecycleService>(pool_, file_repo_);

    FilesServiceDependencies new_deps{
        .db_pool = pool_,
        .s3_client = s3_client_,
        .upload_session_manager = new_session_mgr,
        .lifecycle_service = new_lifecycle,
        .chunk_storage_service = new_chunk_storage,
    };
    auto new_service = std::make_unique<FilesServiceImpl>(new_deps, "gateway");

    // Query reconstructed progress
    auto progress = new_session_mgr->get_transfer_progress(upload_id);
    EXPECT_EQ(progress.accepted_chunks, 3);
    std::vector<int32_t> expected_missing = {3, 4, 5};
    EXPECT_EQ(progress.missing_chunk_indices, expected_missing);

    // Upload remaining chunks 3, 4, 5
    for (uint32_t i = 3; i < 6; ++i) {
        std::string payload(k_standard_chunk_size, static_cast<char>('0' + i));
        std::string hash = compute_sha256_hex(payload);

        v1::UploadChunkRequest req;
        req.set_upload_id(upload_id);
        req.set_chunk_index(i);
        req.set_encrypted_data(payload);
        req.set_chunk_size_bytes(static_cast<uint32_t>(payload.size()));
        req.set_ciphertext_sha256(hash);

        v1::UploadChunkResponse resp;
        auto s = new_service->UploadChunk(&auth_ctx, &req, &resp);
        EXPECT_TRUE(s.ok());
    }

    auto final_progress = new_session_mgr->get_transfer_progress(upload_id);
    EXPECT_EQ(final_progress.accepted_chunks, 6);
    EXPECT_TRUE(final_progress.is_complete);
}

// ============================================================================
// TC5: Client Reconnect & Resume Workflow
// ============================================================================
TEST_F(FilesResumableUploadIntegrationTest, TC5_ClientReconnectAndResumeWorkflow) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    uint64_t total_size = 4ULL * 4ULL * 1024ULL * 1024ULL;
    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(generate_uuid_v7());
    init_req.set_owner_user_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d40");
    init_req.set_owner_device_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d41");
    init_req.set_encrypted_size_bytes(total_size);
    init_req.set_expected_chunk_count(4);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                        "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse init_resp;
    auto init_status = service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp);
    ASSERT_TRUE(init_status.ok());
    std::string upload_id = init_resp.upload_id();

    // Client uploads only chunk 0 and chunk 2 (interrupted network)
    for (uint32_t idx : {0U, 2U}) {
        std::string payload(k_standard_chunk_size, static_cast<char>('a' + idx));
        std::string hash = compute_sha256_hex(payload);

        v1::UploadChunkRequest req;
        req.set_upload_id(upload_id);
        req.set_chunk_index(idx);
        req.set_encrypted_data(payload);
        req.set_chunk_size_bytes(static_cast<uint32_t>(payload.size()));
        req.set_ciphertext_sha256(hash);

        v1::UploadChunkResponse resp;
        EXPECT_TRUE(service_->UploadChunk(&auth_ctx, &req, &resp).ok());
    }

    // Client reconnects and queries missing chunk indices
    auto missing = session_mgr_->get_missing_chunk_indices(upload_id);
    std::vector<int32_t> expected_missing = {1, 3};
    EXPECT_EQ(missing, expected_missing);

    // Client uploads only missing chunks
    for (int32_t idx : missing) {
        std::string payload(k_standard_chunk_size, static_cast<char>('a' + idx));
        std::string hash = compute_sha256_hex(payload);

        v1::UploadChunkRequest req;
        req.set_upload_id(upload_id);
        req.set_chunk_index(static_cast<uint32_t>(idx));
        req.set_encrypted_data(payload);
        req.set_chunk_size_bytes(static_cast<uint32_t>(payload.size()));
        req.set_ciphertext_sha256(hash);

        v1::UploadChunkResponse resp;
        EXPECT_TRUE(service_->UploadChunk(&auth_ctx, &req, &resp).ok());
    }

    auto progress = session_mgr_->get_transfer_progress(upload_id);
    EXPECT_TRUE(progress.missing_chunk_indices.empty());
    EXPECT_EQ(progress.accepted_chunks, 4);
    EXPECT_TRUE(progress.is_complete);
}

// ============================================================================
// TC6: Explicit Cancellation
// ============================================================================
TEST_F(FilesResumableUploadIntegrationTest, TC6_ExplicitCancellation) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    uint64_t total_size = 3ULL * 4ULL * 1024ULL * 1024ULL;
    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(generate_uuid_v7());
    init_req.set_owner_user_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d40");
    init_req.set_owner_device_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d41");
    init_req.set_encrypted_size_bytes(total_size);
    init_req.set_expected_chunk_count(3);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                        "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse init_resp;
    ASSERT_TRUE(service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp).ok());
    std::string upload_id = init_resp.upload_id();

    // Upload chunk 0
    std::string payload(k_standard_chunk_size, '0');
    v1::UploadChunkRequest chunk_req;
    chunk_req.set_upload_id(upload_id);
    chunk_req.set_chunk_index(0);
    chunk_req.set_encrypted_data(payload);
    chunk_req.set_chunk_size_bytes(static_cast<uint32_t>(payload.size()));
    chunk_req.set_ciphertext_sha256(compute_sha256_hex(payload));

    v1::UploadChunkResponse chunk_resp;
    EXPECT_TRUE(service_->UploadChunk(&auth_ctx, &chunk_req, &chunk_resp).ok());

    // Explicitly cancel transfer
    v1::CancelFileUploadRequest cancel_req;
    cancel_req.set_upload_id(upload_id);
    cancel_req.set_reason("Aborted by user");

    v1::CancelFileUploadResponse cancel_resp;
    auto cancel_status = service_->CancelFileUpload(&auth_ctx, &cancel_req, &cancel_resp);
    EXPECT_TRUE(cancel_status.ok());
    EXPECT_EQ(cancel_resp.status(), v1::TRANSFER_STATUS_CANCELLED);

    // Attempting to upload chunk 1 must be rejected with FAILED_PRECONDITION
    chunk_req.set_chunk_index(1);
    auto rejected_status = service_->UploadChunk(&auth_ctx, &chunk_req, &chunk_resp);
    EXPECT_EQ(rejected_status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
}

// ============================================================================
// TC7: End-to-End gRPC Verification
// ============================================================================
TEST_F(FilesResumableUploadIntegrationTest, TC7_EndToEndGrpcRoundtrip) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    uint64_t total_size = 4ULL * 1024ULL * 1024ULL; // 1 standard chunk
    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(generate_uuid_v7());
    init_req.set_owner_user_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d40");
    init_req.set_owner_device_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d41");
    init_req.set_encrypted_size_bytes(total_size);
    init_req.set_expected_chunk_count(1);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    std::string nonce_hex(48, 'a');
    std::string tag_hex(32, 'b');
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                        "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse init_resp;
    ASSERT_TRUE(service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp).ok());

    std::string payload(k_standard_chunk_size, 'M');
    std::string hash = compute_sha256_hex(payload);

    v1::UploadChunkRequest chunk_req;
    chunk_req.set_upload_id(init_resp.upload_id());
    chunk_req.set_chunk_index(0);
    chunk_req.set_encrypted_data(payload);
    chunk_req.set_chunk_size_bytes(static_cast<uint32_t>(payload.size()));
    chunk_req.set_ciphertext_sha256(hash);

    v1::UploadChunkResponse chunk_resp;
    auto chunk_status = service_->UploadChunk(&auth_ctx, &chunk_req, &chunk_resp);
    EXPECT_TRUE(chunk_status.ok());
    EXPECT_TRUE(chunk_resp.accepted());
    EXPECT_EQ(chunk_resp.received_sha256(), hash);
    EXPECT_EQ(chunk_resp.upload_id(), init_resp.upload_id());
}

} // namespace
} // namespace securecloud::files
