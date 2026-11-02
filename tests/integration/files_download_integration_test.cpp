#include "files/db/files_connection_pool.hpp"
#include "files/db/pqxx_compat.hpp"
#include "files/domain/chunk_validator.hpp"
#include "files/domain/file_chunk_entity.hpp"
#include "files/domain/file_entity.hpp"
#include "files/domain/file_transfer_entity.hpp"
#include "files/domain/metadata_validator.hpp"
#include "files/repository/file_access_repository.hpp"
#include "files/repository/file_chunk_repository.hpp"
#include "files/repository/file_repository.hpp"
#include "files/repository/file_transfer_repository.hpp"
#include "files/repository/file_version_repository.hpp"
#include "files/repository/files_outbox_repository.hpp"
#include "files/service/chunk_download_engine.hpp"
#include "files/service/chunk_storage_service.hpp"
#include "files/service/download_manager.hpp"
#include "files/service/file_finalization_service.hpp"
#include "files/service/file_lifecycle_service.hpp"
#include "files/service/files_service_impl.hpp"
#include "files/service/object_assembly_engine.hpp"
#include "files/service/upload_session_manager.hpp"
#include "files/storage/s3_client.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "securecloud/files/v1/files.grpc.pb.h"
#include "securecloud/files/v1/files.pb.h"

#include <chrono>
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

using service::ChunkDownloadEngine;
using service::ChunkStorageService;
using service::DownloadManager;
using service::FileFinalizationService;
using service::FilesServiceDependencies;
using service::FilesServiceImpl;
using service::ObjectAssemblyEngine;
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
                auto r_it = req.headers.find("range");
                if (r_it != req.headers.end() && r_it->second.rfind("bytes=", 0) == 0) {
                    std::string spec = r_it->second.substr(6);
                    auto dash = spec.find('-');
                    if (dash != std::string::npos) {
                        size_t start = std::stoull(spec.substr(0, dash));
                        size_t end = std::stoull(spec.substr(dash + 1));
                        if (start < it->second.size() && end >= start) {
                            size_t len = std::min(end - start + 1, it->second.size() - start);
                            std::string slice = it->second.substr(start, len);
                            return storage::HttpResponse{
                                .status_code = 206,
                                .status_message = "Partial Content",
                                .headers = {{"Content-Length", std::to_string(slice.size())}},
                                .body = slice,
                            };
                        }
                    }
                }
                return storage::HttpResponse{
                    .status_code = 200,
                    .status_message = "OK",
                    .headers = {{"Content-Length", std::to_string(it->second.size())}},
                    .body = it->second,
                };
            }
            return storage::HttpResponse{.status_code = 404, .status_message = "Not Found", .headers = {}, .body = ""};
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
            return storage::HttpResponse{.status_code = 404, .status_message = "Not Found", .headers = {}, .body = ""};
        } else if (req.method == "DELETE") {
            storage_.erase(req.path);
            return storage::HttpResponse{.status_code = 204, .status_message = "No Content", .headers = {}, .body = ""};
        }
        return storage::HttpResponse{.status_code = 200, .status_message = "OK", .headers = {}, .body = ""};
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

constexpr const char* k_test_owner_user_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d40";
constexpr const char* k_test_owner_device_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d41";
constexpr const char* k_test_other_user_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d42";

class FilesDownloadIntegrationTest : public ::testing::Test {
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
        access_repo_ = std::make_shared<FileAccessRepository>(pool_);
        outbox_repo_ = std::make_shared<FilesOutboxRepository>(pool_);

        s3_cfg_.endpoint = "http://127.0.0.1:9000";
        s3_cfg_.bucket = "securecloud-files-encrypted";
        s3_cfg_.access_key = "files_minio_user";
        s3_cfg_.secret_key = common::configuration::SecretString("files_minio_secret");
        s3_cfg_.default_timeout = std::chrono::milliseconds(2000);

        mock_transport_ = std::make_shared<MockHttpTransport>();
        s3_client_ = std::make_shared<S3Client>(s3_cfg_, mock_transport_);

        assembly_engine_ = std::make_shared<ObjectAssemblyEngine>(s3_client_);
        finalization_service_ = std::make_shared<FileFinalizationService>(
            pool_, assembly_engine_, transfer_repo_, file_repo_, version_repo_, chunk_repo_, outbox_repo_);

        download_engine_ = std::make_shared<ChunkDownloadEngine>(s3_client_);
        download_mgr_ =
            std::make_shared<DownloadManager>(pool_, download_engine_, file_repo_, version_repo_, access_repo_);

        session_mgr_ = std::make_shared<UploadSessionManager>(pool_, transfer_repo_, chunk_repo_);
        chunk_storage_ =
            std::make_shared<ChunkStorageService>(pool_, s3_client_, transfer_repo_, chunk_repo_, file_repo_);
        lifecycle_service_ = std::make_shared<FileLifecycleService>(pool_, file_repo_);

        FilesServiceDependencies deps{
            .db_pool = pool_,
            .s3_client = s3_client_,
            .upload_session_manager = session_mgr_,
            .download_manager = download_mgr_,
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

    std::string upload_and_finalize_file(const std::vector<std::string>& chunks,
                                         const std::string& owner_user_id = k_test_owner_user_id) {
        TestIntegrationAuthContext auth_ctx("DNS:gateway");

        uint64_t total_size = 0;
        for (const auto& c : chunks) {
            total_size += c.size();
        }

        std::string file_id = generate_uuid_v7();
        v1::CreateFileUploadRequest init_req;
        init_req.set_file_id(file_id);
        init_req.set_owner_user_id(owner_user_id);
        init_req.set_owner_device_id(k_test_owner_device_id);
        init_req.set_encrypted_size_bytes(total_size);
        init_req.set_expected_chunk_count(static_cast<uint32_t>(chunks.size()));
        init_req.set_encryption_version("XChaCha20-Poly1305");
        init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" +
                                            std::string(48, 'a') + "\",\"metadata_tag_hex\":\"" + std::string(32, 'b') +
                                            "\"}");

        v1::CreateFileUploadResponse init_resp;
        auto init_stat = service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp);
        EXPECT_TRUE(init_stat.ok()) << init_stat.error_message();
        std::string upload_id = init_resp.upload_id();

        std::string concatenated_payload;
        for (uint32_t i = 0; i < chunks.size(); ++i) {
            concatenated_payload += chunks[i];
            v1::UploadChunkRequest req;
            req.set_upload_id(upload_id);
            req.set_chunk_index(i);
            req.set_encrypted_data(chunks[i]);
            req.set_chunk_size_bytes(static_cast<uint32_t>(chunks[i].size()));
            req.set_ciphertext_sha256(compute_sha256_hex(chunks[i]));

            v1::UploadChunkResponse resp;
            auto up_stat = service_->UploadChunk(&auth_ctx, &req, &resp);
            EXPECT_TRUE(up_stat.ok()) << up_stat.error_message();
        }

        v1::FinalizeFileUploadRequest fin_req;
        fin_req.set_upload_id(upload_id);
        fin_req.set_file_id(file_id);
        fin_req.set_expected_ciphertext_sha256(compute_sha256_hex(concatenated_payload));

        v1::FinalizeFileUploadResponse fin_resp;
        auto fin_stat = service_->FinalizeFileUpload(&auth_ctx, &fin_req, &fin_resp);
        EXPECT_TRUE(fin_stat.ok()) << fin_stat.error_message();
        EXPECT_EQ(fin_resp.lifecycle_state(), v1::FILE_LIFECYCLE_STATE_AVAILABLE);

        return file_id;
    }

    db::ConnectionPoolConfig db_config_{};
    S3ClientConfig s3_cfg_{};
    std::shared_ptr<MockHttpTransport> mock_transport_;
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
    std::shared_ptr<FileTransferRepository> transfer_repo_;
    std::shared_ptr<FileChunkRepository> chunk_repo_;
    std::shared_ptr<FileRepository> file_repo_;
    std::shared_ptr<FileVersionRepository> version_repo_;
    std::shared_ptr<FileAccessRepository> access_repo_;
    std::shared_ptr<FilesOutboxRepository> outbox_repo_;
    std::shared_ptr<S3Client> s3_client_;
    std::shared_ptr<ObjectAssemblyEngine> assembly_engine_;
    std::shared_ptr<FileFinalizationService> finalization_service_;
    std::shared_ptr<ChunkDownloadEngine> download_engine_;
    std::shared_ptr<DownloadManager> download_mgr_;
    std::shared_ptr<UploadSessionManager> session_mgr_;
    std::shared_ptr<ChunkStorageService> chunk_storage_;
    std::shared_ptr<FileLifecycleService> lifecycle_service_;
    std::unique_ptr<FilesServiceImpl> service_;
};

// ============================================================================
// TC1: Happy Path Full-File Chunked Download
// ============================================================================
TEST_F(FilesDownloadIntegrationTest, TC1_HappyPathFullFileChunkedDownload) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    std::string chunk0 = std::string(k_standard_chunk_size, 'A');
    std::string chunk1 = std::string(1024, 'B');
    std::string file_id = upload_and_finalize_file({chunk0, chunk1}, k_test_owner_user_id);

    // Download chunk 0
    v1::DownloadChunkRequest req0;
    req0.set_file_id(file_id);
    req0.set_chunk_index(0);

    v1::DownloadChunkResponse resp0;
    auto status0 = service_->DownloadChunk(&auth_ctx, &req0, &resp0);
    EXPECT_TRUE(status0.ok()) << status0.error_message();
    EXPECT_EQ(resp0.file_id(), file_id);
    EXPECT_EQ(resp0.chunk_index(), 0);
    EXPECT_EQ(resp0.encrypted_data(), chunk0);
    EXPECT_EQ(resp0.chunk_size_bytes(), chunk0.size());
    EXPECT_EQ(resp0.ciphertext_sha256(), compute_sha256_hex(chunk0));

    // Download chunk 1
    v1::DownloadChunkRequest req1;
    req1.set_file_id(file_id);
    req1.set_chunk_index(1);

    v1::DownloadChunkResponse resp1;
    auto status1 = service_->DownloadChunk(&auth_ctx, &req1, &resp1);
    EXPECT_TRUE(status1.ok()) << status1.error_message();
    EXPECT_EQ(resp1.chunk_index(), 1);
    EXPECT_EQ(resp1.encrypted_data(), chunk1);
    EXPECT_EQ(resp1.chunk_size_bytes(), chunk1.size());
    EXPECT_EQ(resp1.ciphertext_sha256(), compute_sha256_hex(chunk1));

    // Reassembled ciphertext verification
    std::string reassembled = resp0.encrypted_data() + resp1.encrypted_data();
    auto ver_opt = version_repo_->find_active_version(file_id);
    ASSERT_TRUE(ver_opt.has_value());
    EXPECT_EQ(compute_sha256_hex(reassembled), ver_opt->checksum_sha256);
}

// ============================================================================
// TC2: Canonical Resume from starting_chunk = N
// ============================================================================
TEST_F(FilesDownloadIntegrationTest, TC2_CanonicalResumeFromStartingChunk) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    // Create 4-chunk file (each non-terminal chunk exactly 4 MiB)
    std::vector<std::string> chunks = {
        std::string(k_standard_chunk_size, 'A'), std::string(k_standard_chunk_size, 'B'),
        std::string(k_standard_chunk_size, 'C'), std::string(1024, 'D') // partial last chunk
    };
    std::string file_id = upload_and_finalize_file(chunks, k_test_owner_user_id);

    // Prepare resume session starting from chunk 2
    auto resume_model = download_mgr_->prepare_resume_session(file_id, 1, 2, k_test_owner_user_id);
    EXPECT_EQ(resume_model.starting_chunk, 2);
    EXPECT_EQ(resume_model.total_chunks, 4);

    // Download only chunk 2 and chunk 3 (chunks 0 and 1 skipped)
    v1::DownloadChunkRequest req2;
    req2.set_file_id(file_id);
    req2.set_chunk_index(2);
    v1::DownloadChunkResponse resp2;
    EXPECT_TRUE(service_->DownloadChunk(&auth_ctx, &req2, &resp2).ok());
    EXPECT_EQ(resp2.encrypted_data(), chunks[2]);

    v1::DownloadChunkRequest req3;
    req3.set_file_id(file_id);
    req3.set_chunk_index(3);
    v1::DownloadChunkResponse resp3;
    EXPECT_TRUE(service_->DownloadChunk(&auth_ctx, &req3, &resp3).ok());
    EXPECT_EQ(resp3.encrypted_data(), chunks[3]);
}

// ============================================================================
// TC3: Authorization Guard (Unauthorized Access Denied)
// ============================================================================
TEST_F(FilesDownloadIntegrationTest, TC3_AuthorizationGuardUnauthorizedAccessDenied) {
    // File owned by k_test_owner_user_id
    std::string chunk = std::string(1024, 'C');
    std::string file_id = upload_and_finalize_file({chunk}, k_test_owner_user_id);

    // Attempt download by unauthorized other user via download_mgr_
    EXPECT_THROW(download_mgr_->get_chunk_versioned(file_id, 1, 0, k_test_other_user_id),
                 UnauthorizedFileAccessException);

    // Grant READ access to k_test_other_user_id
    FileAccessEntity grant{.access_id = generate_uuid_v7(),
                           .file_id = file_id,
                           .grantee_user_id = k_test_other_user_id,
                           .permission = FilePermission::Read,
                           .granted_by = k_test_owner_user_id,
                           .granted_at = std::chrono::system_clock::now()};
    access_repo_->grant_access(grant);

    // Now other user download succeeds!
    auto result = download_mgr_->get_chunk_versioned(file_id, 1, 0, k_test_other_user_id);
    EXPECT_EQ(result.encrypted_data, chunk);
}

// ============================================================================
// TC4: Lifecycle State Guard (Not Available)
// ============================================================================
TEST_F(FilesDownloadIntegrationTest, TC4_LifecycleStateGuardNotAvailable) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    std::string file_id = generate_uuid_v7();
    v1::CreateFileUploadRequest init_req;
    init_req.set_file_id(file_id);
    init_req.set_owner_user_id(k_test_owner_user_id);
    init_req.set_owner_device_id(k_test_owner_device_id);
    init_req.set_encrypted_size_bytes(1000);
    init_req.set_expected_chunk_count(1);
    init_req.set_encryption_version("XChaCha20-Poly1305");
    init_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" +
                                        std::string(48, 'a') + "\",\"metadata_tag_hex\":\"" + std::string(32, 'b') +
                                        "\"}");

    v1::CreateFileUploadResponse init_resp;
    EXPECT_TRUE(service_->CreateFileUpload(&auth_ctx, &init_req, &init_resp).ok());

    // File is in UPLOADING state, not AVAILABLE
    v1::DownloadChunkRequest req;
    req.set_file_id(file_id);
    req.set_chunk_index(0);

    v1::DownloadChunkResponse resp;
    auto status = service_->DownloadChunk(&auth_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
}

// ============================================================================
// TC5: Out of Bounds Chunk Index
// ============================================================================
TEST_F(FilesDownloadIntegrationTest, TC5_OutOfBoundsChunkIndex) {
    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    std::string chunk = std::string(1024, 'D');
    std::string file_id = upload_and_finalize_file({chunk}, k_test_owner_user_id);

    v1::DownloadChunkRequest req;
    req.set_file_id(file_id);
    req.set_chunk_index(99); // only chunk 0 exists

    v1::DownloadChunkResponse resp;
    auto status = service_->DownloadChunk(&auth_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::OUT_OF_RANGE);
}

// ============================================================================
// TC6: Resume Model Validation
// ============================================================================
TEST_F(FilesDownloadIntegrationTest, TC6_ResumeModelValidation) {
    std::string chunk0 = std::string(k_standard_chunk_size, 'X');
    std::string chunk1 = std::string(k_standard_chunk_size, 'Y');
    std::string file_id = upload_and_finalize_file({chunk0, chunk1}, k_test_owner_user_id);

    // Invalid starting chunk beyond total chunks
    EXPECT_THROW(download_mgr_->prepare_resume_session(file_id, 1, 10, k_test_owner_user_id), std::out_of_range);

    // Valid starting chunk 0 and 1
    auto s0 = download_mgr_->prepare_resume_session(file_id, 1, 0, k_test_owner_user_id);
    EXPECT_EQ(s0.starting_chunk, 0);
    EXPECT_EQ(s0.total_chunks, 2);

    auto s1 = download_mgr_->prepare_resume_session(file_id, 1, 1, k_test_owner_user_id);
    EXPECT_EQ(s1.starting_chunk, 1);
    EXPECT_EQ(s1.total_chunks, 2);
}

} // namespace
} // namespace securecloud::files
