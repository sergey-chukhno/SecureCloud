#include "files/db/files_connection_pool.hpp"
#include "files/db/pqxx_compat.hpp"
#include "files/domain/encrypted_file_metadata_entity.hpp"
#include "files/domain/file_access_entity.hpp"
#include "files/domain/file_entity.hpp"
#include "files/domain/file_version_entity.hpp"
#include "files/domain/files_outbox_entity.hpp"
#include "files/domain/lifecycle_state_machine.hpp"
#include "files/domain/metadata_validator.hpp"
#include "files/repository/file_access_repository.hpp"
#include "files/repository/file_repository.hpp"
#include "files/repository/file_version_repository.hpp"
#include "files/repository/files_outbox_repository.hpp"
#include "files/service/file_lifecycle_service.hpp"
#include "files/service/files_service_impl.hpp"
#include "securecloud/common/configuration/secret_string.hpp"
#include "securecloud/files/v1/files.grpc.pb.h"
#include "securecloud/files/v1/files.pb.h"
#include "securecloud/health/transport_probe.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
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

// Mock AuthContext for gRPC testing
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

class FilesLifecycleIntegrationTest : public ::testing::Test {
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
        file_repo_ = std::make_shared<FileRepository>(pool_);
        version_repo_ = std::make_shared<FileVersionRepository>(pool_);
        access_repo_ = std::make_shared<FileAccessRepository>(pool_);
        outbox_repo_ = std::make_shared<FilesOutboxRepository>(pool_);

        lifecycle_service_ = std::make_shared<FileLifecycleService>(
            pool_, file_repo_, version_repo_, access_repo_, outbox_repo_);
    }

    void TearDown() override {
        if (pool_) {
            pool_->drain();
            pool_->close();
        }
        pqxx::MockStorage::instance().reset();
    }

    db::ConnectionPoolConfig db_config_;
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
    std::shared_ptr<FileRepository> file_repo_;
    std::shared_ptr<FileVersionRepository> version_repo_;
    std::shared_ptr<FileAccessRepository> access_repo_;
    std::shared_ptr<FilesOutboxRepository> outbox_repo_;
    std::shared_ptr<FileLifecycleService> lifecycle_service_;
};

// ============================================================================
// TC1: Full Lifecycle Progression (CREATED -> UPLOADING -> FINALIZING -> AVAILABLE)
// ============================================================================
TEST_F(FilesLifecycleIntegrationTest, TC1_FullLifecycleProgressionAndOutbox) {
    const std::string file_id = generate_uuid_v7();
    const std::string user_id = generate_uuid_v7();
    const std::string device_id = generate_uuid_v7();
    const auto now = std::chrono::system_clock::now();

    CreateFileRequestDto dto{
        .file_id = file_id,
        .owner_user_id = user_id,
        .owner_device_id = device_id,
        .conversation_id = std::nullopt,
        .encrypted_size_bytes = 4 * 1024 * 1024,
        .expected_chunk_count = 1,
        .encryption_algorithm = std::string(k_approved_encryption_algorithm),
        .encrypted_filename = {0x11, 0x22, 0x33, 0x44},
        .metadata_nonce = std::vector<uint8_t>(24, 0xAA),
        .metadata_tag = std::vector<uint8_t>(16, 0xBB),
        .client_encryption_metadata_json = "{}",
    };

    // 1. Create file -> initial status CREATED
    std::string created_id = lifecycle_service_->create_file(dto, now);
    EXPECT_EQ(created_id, file_id);

    auto meta = lifecycle_service_->get_file_metadata(file_id, user_id);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->file.status, FileStatus::Created);

    // Verify outbox contains FILE_CREATED event
    {
        pqxx::work tx;
        auto pending = outbox_repo_->fetch_pending_events(10, tx);
        ASSERT_FALSE(pending.empty());
        EXPECT_EQ(pending[0].event_type, "FILE_CREATED");
        EXPECT_EQ(pending[0].aggregate_id, file_id);
    }

    // 2. Transition CREATED -> UPLOADING
    bool ok = lifecycle_service_->transition_lifecycle(file_id, FileStatus::Created, FileStatus::Uploading, user_id);
    EXPECT_TRUE(ok);
    meta = lifecycle_service_->get_file_metadata(file_id, user_id);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->file.status, FileStatus::Uploading);

    // 3. Transition UPLOADING -> FINALIZING
    ok = lifecycle_service_->transition_lifecycle(file_id, FileStatus::Uploading, FileStatus::Finalizing, user_id);
    EXPECT_TRUE(ok);
    meta = lifecycle_service_->get_file_metadata(file_id, user_id);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->file.status, FileStatus::Finalizing);

    // 4. Transition FINALIZING -> AVAILABLE
    ok = lifecycle_service_->transition_lifecycle(file_id, FileStatus::Finalizing, FileStatus::Available, user_id);
    EXPECT_TRUE(ok);
    meta = lifecycle_service_->get_file_metadata(file_id, user_id);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->file.status, FileStatus::Available);

    // Verify outbox contains FILE_AVAILABLE event
    {
        pqxx::work tx;
        auto pending = outbox_repo_->fetch_pending_events(10, tx);
        bool found_available = false;
        for (const auto& ev : pending) {
            if (ev.aggregate_id == file_id && ev.event_type == "FILE_AVAILABLE") {
                found_available = true;
                break;
            }
        }
        EXPECT_TRUE(found_available);
    }
}

// ============================================================================
// TC2: Immutable Versioning & Multi-Version Creation
// ============================================================================
TEST_F(FilesLifecycleIntegrationTest, TC2_ImmutableVersioningAndMultiVersion) {
    const std::string file_id = generate_uuid_v7();
    const std::string user_id = generate_uuid_v7();
    const std::string device_id = generate_uuid_v7();
    const auto now = std::chrono::system_clock::now();

    CreateFileRequestDto dto{
        .file_id = file_id,
        .owner_user_id = user_id,
        .owner_device_id = device_id,
        .encrypted_size_bytes = 1024,
        .expected_chunk_count = 1,
        .encryption_algorithm = std::string(k_approved_encryption_algorithm),
        .encrypted_filename = {0xDE, 0xAD},
        .metadata_nonce = std::vector<uint8_t>(24, 0x01),
        .metadata_tag = std::vector<uint8_t>(16, 0x02),
        .client_encryption_metadata_json = "{}",
    };
    lifecycle_service_->create_file(dto, now);

    // Create Version 1
    const std::string sha256_v1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    CreateFileVersionRequestDto v1_dto{
        .file_id = file_id,
        .version_number = 1,
        .encrypted_size_bytes = 1024,
        .minio_object_key = "objects/" + file_id + "/1",
        .checksum_sha256 = sha256_v1,
    };
    auto v1_entity = lifecycle_service_->create_file_version(v1_dto, user_id);
    EXPECT_EQ(v1_entity.version_number, 1);
    EXPECT_EQ(v1_entity.minio_object_key, "objects/" + file_id + "/1");
    EXPECT_EQ(v1_entity.checksum_sha256, sha256_v1);

    // Transition file to AVAILABLE
    lifecycle_service_->transition_lifecycle(file_id, FileStatus::Created, FileStatus::Uploading, user_id);
    lifecycle_service_->transition_lifecycle(file_id, FileStatus::Uploading, FileStatus::Finalizing, user_id);
    lifecycle_service_->transition_lifecycle(file_id, FileStatus::Finalizing, FileStatus::Available, user_id);

    // Now create Version 2 (Immutable versioning invariant: v1 remains intact)
    const std::string sha256_v2 = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";
    CreateFileVersionRequestDto v2_dto{
        .file_id = file_id,
        .version_number = 2,
        .encrypted_size_bytes = 2048,
        .minio_object_key = "objects/" + file_id + "/2",
        .checksum_sha256 = sha256_v2,
    };
    auto v2_entity = lifecycle_service_->create_file_version(v2_dto, user_id);
    EXPECT_EQ(v2_entity.version_number, 2);
    EXPECT_EQ(v2_entity.minio_object_key, "objects/" + file_id + "/2");
    EXPECT_EQ(v2_entity.checksum_sha256, sha256_v2);

    // Verify v1 record in DB is completely untouched
    {
        pqxx::work tx;
        auto stored_v1 = version_repo_->find_by_version(file_id, 1, tx);
        ASSERT_TRUE(stored_v1.has_value());
        EXPECT_EQ(stored_v1->minio_object_key, "objects/" + file_id + "/1");
        EXPECT_EQ(stored_v1->checksum_sha256, sha256_v1);
        EXPECT_EQ(stored_v1->encrypted_size_bytes, 1024);

        auto stored_v2 = version_repo_->find_by_version(file_id, 2, tx);
        ASSERT_TRUE(stored_v2.has_value());
        EXPECT_EQ(stored_v2->minio_object_key, "objects/" + file_id + "/2");
        EXPECT_EQ(stored_v2->checksum_sha256, sha256_v2);
    }
}

// ============================================================================
// TC3: Invalid State Transition Rejection
// ============================================================================
TEST_F(FilesLifecycleIntegrationTest, TC3_InvalidStateTransitionRejection) {
    const std::string file_id = generate_uuid_v7();
    const std::string user_id = generate_uuid_v7();
    const auto now = std::chrono::system_clock::now();

    CreateFileRequestDto dto{
        .file_id = file_id,
        .owner_user_id = user_id,
        .owner_device_id = generate_uuid_v7(),
        .encrypted_size_bytes = 1024,
        .expected_chunk_count = 1,
        .encryption_algorithm = std::string(k_approved_encryption_algorithm),
        .encrypted_filename = {0x01},
        .metadata_nonce = std::vector<uint8_t>(24, 0x01),
        .metadata_tag = std::vector<uint8_t>(16, 0x01),
        .client_encryption_metadata_json = "{}",
    };
    lifecycle_service_->create_file(dto, now);

    // CREATED -> AVAILABLE directly is illegal (must go through UPLOADING -> FINALIZING)
    EXPECT_THROW(lifecycle_service_->transition_lifecycle(file_id, FileStatus::Created, FileStatus::Available, user_id),
                 InvalidLifecycleTransitionException);

    // Verify DB status is still CREATED
    auto meta = lifecycle_service_->get_file_metadata(file_id, user_id);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->file.status, FileStatus::Created);

    // Fail the file (terminal state)
    lifecycle_service_->transition_lifecycle(file_id, FileStatus::Created, FileStatus::Failed, user_id);
    meta = lifecycle_service_->get_file_metadata(file_id, user_id);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->file.status, FileStatus::Failed);

    // Attempt to revive failed file -> illegal
    EXPECT_THROW(lifecycle_service_->transition_lifecycle(file_id, FileStatus::Failed, FileStatus::Uploading, user_id),
                 InvalidLifecycleTransitionException);
}

// ============================================================================
// TC4: Retention Expiration Workflow
// ============================================================================
TEST_F(FilesLifecycleIntegrationTest, TC4_ExpirationWorkflow) {
    const std::string file_id = generate_uuid_v7();
    const std::string user_id = generate_uuid_v7();
    const auto now = std::chrono::system_clock::now();
    const auto expire_at = now + std::chrono::seconds(10);

    CreateFileRequestDto dto{
        .file_id = file_id,
        .owner_user_id = user_id,
        .owner_device_id = generate_uuid_v7(),
        .encrypted_size_bytes = 1024,
        .expected_chunk_count = 1,
        .encryption_algorithm = std::string(k_approved_encryption_algorithm),
        .encrypted_filename = {0x01},
        .metadata_nonce = std::vector<uint8_t>(24, 0x01),
        .metadata_tag = std::vector<uint8_t>(16, 0x01),
        .client_encryption_metadata_json = "{}",
        .retention_until = expire_at,
    };
    lifecycle_service_->create_file(dto, now);

    // Transition to AVAILABLE
    lifecycle_service_->transition_lifecycle(file_id, FileStatus::Created, FileStatus::Uploading, user_id);
    lifecycle_service_->transition_lifecycle(file_id, FileStatus::Uploading, FileStatus::Finalizing, user_id);
    lifecycle_service_->transition_lifecycle(file_id, FileStatus::Finalizing, FileStatus::Available, user_id);

    // Scan at current time -> not expired yet
    size_t expired_now = lifecycle_service_->evaluate_and_expire_files(now);
    EXPECT_EQ(expired_now, 0);

    // Fast-forward scan to after expiration deadline
    size_t expired_later = lifecycle_service_->evaluate_and_expire_files(now + std::chrono::hours(1));
    EXPECT_GE(expired_later, 1);

    auto meta = lifecycle_service_->get_file_metadata(file_id, user_id);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->file.status, FileStatus::Expired);

    // Check that FILE_EXPIRED event was written to outbox
    {
        pqxx::work tx;
        auto pending = outbox_repo_->fetch_pending_events(10, tx);
        bool found_expired = false;
        for (const auto& ev : pending) {
            if (ev.aggregate_id == file_id && ev.event_type == "FILE_EXPIRED") {
                found_expired = true;
                break;
            }
        }
        EXPECT_TRUE(found_expired);
    }
}

// ============================================================================
// TC5: Logical Deletion
// ============================================================================
TEST_F(FilesLifecycleIntegrationTest, TC5_LogicalDeletion) {
    const std::string file_id = generate_uuid_v7();
    const std::string user_id = generate_uuid_v7();
    const auto now = std::chrono::system_clock::now();

    CreateFileRequestDto dto{
        .file_id = file_id,
        .owner_user_id = user_id,
        .owner_device_id = generate_uuid_v7(),
        .encrypted_size_bytes = 1024,
        .expected_chunk_count = 1,
        .encryption_algorithm = std::string(k_approved_encryption_algorithm),
        .encrypted_filename = {0x01},
        .metadata_nonce = std::vector<uint8_t>(24, 0x01),
        .metadata_tag = std::vector<uint8_t>(16, 0x01),
        .client_encryption_metadata_json = "{}",
    };
    lifecycle_service_->create_file(dto, now);

    // Delete file
    bool deleted = lifecycle_service_->delete_file(file_id, user_id, "User requested purge");
    EXPECT_TRUE(deleted);

    auto meta = lifecycle_service_->get_file_metadata(file_id, user_id);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->file.status, FileStatus::Deleted);

    // Terminal state: attempt transition -> throws InvalidLifecycleTransitionException
    EXPECT_THROW(lifecycle_service_->transition_lifecycle(file_id, FileStatus::Deleted, FileStatus::Available, user_id),
                 InvalidLifecycleTransitionException);
}

// ============================================================================
// TC6: Ownership & Access Control Isolation
// ============================================================================
TEST_F(FilesLifecycleIntegrationTest, TC6_OwnershipAndAccessControl) {
    const std::string file_id = generate_uuid_v7();
    const std::string user_a = generate_uuid_v7();
    const std::string user_b = generate_uuid_v7();
    const auto now = std::chrono::system_clock::now();

    CreateFileRequestDto dto{
        .file_id = file_id,
        .owner_user_id = user_a,
        .owner_device_id = generate_uuid_v7(),
        .encrypted_size_bytes = 1024,
        .expected_chunk_count = 1,
        .encryption_algorithm = std::string(k_approved_encryption_algorithm),
        .encrypted_filename = {0x01},
        .metadata_nonce = std::vector<uint8_t>(24, 0x01),
        .metadata_tag = std::vector<uint8_t>(16, 0x01),
        .client_encryption_metadata_json = "{}",
    };
    lifecycle_service_->create_file(dto, now);

    // User B attempts to read User A's file -> rejected
    EXPECT_THROW(lifecycle_service_->get_file_metadata(file_id, user_b), UnauthorizedFileAccessException);

    // User B attempts to delete User A's file -> rejected
    EXPECT_THROW(lifecycle_service_->delete_file(file_id, user_b), UnauthorizedFileAccessException);

    // User A grants READ access to User B
    {
        pqxx::work tx;
        FileAccessEntity grant{
            .file_id = file_id,
            .grantee_user_id = user_b,
            .permission = FilePermission::Read,
            .granted_by_user_id = user_a,
            .granted_at = now,
        };
        access_repo_->create_grant(grant, tx);
        tx.commit();
    }

    // User B can now inspect metadata
    auto meta_b = lifecycle_service_->get_file_metadata(file_id, user_b);
    ASSERT_TRUE(meta_b.has_value());
    EXPECT_EQ(meta_b->file.file_id, file_id);

    // User B still cannot delete User A's file (needs WRITE/OWNER)
    EXPECT_THROW(lifecycle_service_->delete_file(file_id, user_b), UnauthorizedFileAccessException);
}

// ============================================================================
// TC7: End-to-End gRPC Service Integration Test
// ============================================================================
TEST_F(FilesLifecycleIntegrationTest, TC7_EndToEndGrpcServiceCalls) {
    service::FilesServiceDependencies deps{
        .db_pool = pool_,
        .lifecycle_service = lifecycle_service_,
    };
    service::FilesServiceImpl files_service(deps, "gateway");

    TestIntegrationAuthContext auth_ctx("DNS:gateway");

    const std::string file_id = generate_uuid_v7();
    const std::string owner_id = generate_uuid_v7();

    // 1. CreateFileUpload
    v1::CreateFileUploadRequest create_req;
    create_req.set_file_id(file_id);
    create_req.set_owner_user_id(owner_id);
    create_req.set_owner_device_id(generate_uuid_v7());
    create_req.set_encrypted_size_bytes(4 * 1024 * 1024);
    create_req.set_expected_chunk_count(1);
    create_req.set_encryption_version("XChaCha20-Poly1305");

    std::string nonce_hex(48, '0');
    std::string tag_hex(32, '1');
    create_req.set_client_crypto_metadata("{\"encrypted_filename_hex\":\"0102\",\"metadata_nonce_hex\":\"" + nonce_hex +
                                          "\",\"metadata_tag_hex\":\"" + tag_hex + "\"}");

    v1::CreateFileUploadResponse create_resp;
    auto status = files_service.CreateFileUpload(&auth_ctx, &create_req, &create_resp);
    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_FALSE(create_resp.upload_id().empty());
    EXPECT_EQ(create_resp.file_id(), file_id);
    EXPECT_EQ(create_resp.status(), v1::TRANSFER_STATUS_PENDING);

    // 2. GetFileMetadata
    v1::GetFileMetadataRequest meta_req;
    meta_req.set_file_id(file_id);

    v1::GetFileMetadataResponse meta_resp;
    status = files_service.GetFileMetadata(&auth_ctx, &meta_req, &meta_resp);
    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(meta_resp.lifecycle_state(), v1::FILE_LIFECYCLE_STATE_CREATED);
    EXPECT_EQ(meta_resp.encrypted_size_bytes(), 4 * 1024 * 1024);

    // 3. DeleteFile
    v1::DeleteFileRequest del_req;
    del_req.set_file_id(file_id);

    v1::DeleteFileResponse del_resp;
    status = files_service.DeleteFile(&auth_ctx, &del_req, &del_resp);
    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(del_resp.file_id(), file_id);
    EXPECT_EQ(del_resp.state(), v1::FILE_LIFECYCLE_STATE_DELETED);
    EXPECT_TRUE(del_resp.deleted());
}

} // namespace
} // namespace securecloud::files
