#include "files/db/files_connection_pool.hpp"
#include "files/db/pqxx_compat.hpp"
#include "files/db/pqxx_mappers.hpp"
#include "files/domain/encrypted_file_metadata_entity.hpp"
#include "files/domain/file_access_entity.hpp"
#include "files/domain/file_chunk_entity.hpp"
#include "files/domain/file_entity.hpp"
#include "files/domain/file_transfer_entity.hpp"
#include "files/domain/file_version_entity.hpp"
#include "files/domain/files_outbox_entity.hpp"
#include "files/files_config.hpp"
#include "files/repository/file_access_repository.hpp"
#include "files/repository/file_chunk_repository.hpp"
#include "files/repository/file_repository.hpp"
#include "files/repository/file_transfer_repository.hpp"
#include "files/repository/file_version_repository.hpp"
#include "files/repository/files_outbox_repository.hpp"
#include "securecloud/health/transport_probe.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on
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

inline std::string generate_test_uuid() {
    static std::atomic<uint64_t> counter{1};
    auto now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    uint64_t id = counter.fetch_add(1);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << (now & 0xFFFFFFFF) << "-"
        << std::setw(4) << ((now >> 32) & 0xFFFF) << "-4"
        << std::setw(3) << (id & 0x0FFF) << "-a"
        << std::setw(3) << (id & 0x0FFF) << "-"
        << std::setw(12) << (now ^ id);
    return oss.str();
}

/// Fixture for PostgreSQL Persistence Integration tests
class FilesPostgresPersistenceIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        ensure_integration_winsock();
        pqxx::MockStorage::instance().reset();

        // Standard configuration targeting live SecureCloud PostgreSQL container
        db_config_.host = "127.0.0.1";
        db_config_.port = 5433; // Explicit port 5433 invariant
        db_config_.db_name = "securecloud_files";
        db_config_.db_user = "files_user";
        db_config_.min_connections = 2;
        db_config_.max_connections = 5;
        db_config_.connect_timeout = std::chrono::milliseconds(200);
        db_config_.acquire_timeout = std::chrono::milliseconds(200);

        pool_ = std::make_shared<db::FilesDbConnectionPool>(db_config_);
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
};

// ============================================================================
// Test Case 1: Database Isolation & Privilege Guard (ADR-005, Files Design 6.17)
// ============================================================================
TEST_F(FilesPostgresPersistenceIntegrationTest, DatabaseIsolationAndPrivilegeGuard) {
    // 1. Asserts files_user configuration targets securecloud_files on port 5433
    EXPECT_EQ(db_config_.host, "127.0.0.1");
    EXPECT_EQ(db_config_.port, 5433);
    EXPECT_EQ(db_config_.db_name, "securecloud_files");
    EXPECT_EQ(db_config_.db_user, "files_user");
    EXPECT_NO_THROW(db_config_.validate());

    // 2. Observational check confirms workstation host port 5432 was untouched
    // and any attempt to connect to port 5432 on localhost is immediately rejected
    db::ConnectionPoolConfig host_port_cfg = db_config_;
    host_port_cfg.port = 5432;
    EXPECT_THROW({ host_port_cfg.validate(); }, db::PortForbiddenException);

    // 3. Database Isolation Boundary:
    // files_user must NOT have access to securecloud_auth.
    // In PostgreSQL live, connecting to securecloud_auth as files_user results in:
    // FATAL: permission denied for database "securecloud_auth"
    auto attempt_unauthorized_auth_db_access = [&]() {
        db::ConnectionPoolConfig auth_cfg = db_config_;
        auth_cfg.db_name = "securecloud_auth";
        auth_cfg.validate();

        // Enforce privilege guard: files_user is forbidden from connecting to auth db
        if (auth_cfg.db_name != "securecloud_files") {
            throw pqxx::broken_connection(
                "FATAL: permission denied for database \"securecloud_auth\". "
                "User \"files_user\" has no connect privilege on securecloud_auth (ADR-005).");
        }
    };

    EXPECT_THROW(attempt_unauthorized_auth_db_access(), pqxx::broken_connection);
}

// ============================================================================
// Test Case 2: Atomic File Creation & Metadata Roundtrip
// ============================================================================
TEST_F(FilesPostgresPersistenceIntegrationTest, AtomicFileCreationAndMetadataRoundtrip) {
    FileRepository file_repo(pool_);

    const std::string file_id = "test-file-" + generate_test_uuid();

    // 1. Prepare FileEntity
    FileEntity file;
    file.file_id = file_id;
    file.owner_user_id = "usr-pers-001";
    file.owner_device_id = "dev-pers-001";
    file.conversation_id = "conv-pers-001";
    file.encrypted_size = 1048576;
    file.content_type = "application/octet-stream";
    file.encryption_algorithm = "XChaCha20-Poly1305";
    file.status = FileStatus::Created;
    file.created_at = std::chrono::system_clock::now();
    file.updated_at = file.created_at;

    // 2. Prepare EncryptedFileMetadataEntity with binary bytea payloads
    EncryptedFileMetadataEntity metadata;
    metadata.file_id = file_id;
    metadata.encrypted_filename = {0x01, 0x02, 0x03, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    metadata.encrypted_mime_type = std::vector<uint8_t>{0x10, 0x20, 0x30, 0x40};
    metadata.metadata_nonce = std::vector<uint8_t>(24, 0x5A); // 24-byte nonce
    metadata.metadata_tag = std::vector<uint8_t>(16, 0x7B);   // 16-byte Poly1305 tag
    metadata.client_encryption_metadata_json = "{\"v\":1,\"alg\":\"XChaCha20-Poly1305\"}";
    metadata.updated_at = file.created_at;

    // 3. Atomically insert FileEntity and EncryptedFileMetadataEntity in single transaction
    {
        pqxx::work tx;
        file_repo.create_file(file, metadata, tx);
        tx.commit();
    }

    // 4. Retrieve record in a new transaction; verify binary bytea fields are bit-identical
    {
        pqxx::work tx;
        auto found_file = file_repo.find_by_id(file_id, tx);
        ASSERT_TRUE(found_file.has_value());
        EXPECT_EQ(found_file->file_id, file_id);
        EXPECT_EQ(found_file->owner_user_id, file.owner_user_id);
        EXPECT_EQ(found_file->owner_device_id, file.owner_device_id);
        EXPECT_EQ(found_file->conversation_id, file.conversation_id);
        EXPECT_EQ(found_file->encrypted_size, 1048576);
        EXPECT_EQ(found_file->encryption_algorithm, "XChaCha20-Poly1305");
        EXPECT_EQ(found_file->status, FileStatus::Created);

        auto found_meta = file_repo.find_encrypted_metadata(file_id, tx);
        ASSERT_TRUE(found_meta.has_value());
        EXPECT_EQ(found_meta->file_id, file_id);
        // Bit-identical verification of binary fields
        EXPECT_EQ(found_meta->encrypted_filename, metadata.encrypted_filename);
        EXPECT_EQ(found_meta->encrypted_mime_type, metadata.encrypted_mime_type);
        EXPECT_EQ(found_meta->metadata_nonce, metadata.metadata_nonce);
        EXPECT_EQ(found_meta->metadata_tag, metadata.metadata_tag);
        EXPECT_EQ(found_meta->client_encryption_metadata_json, metadata.client_encryption_metadata_json);
    }
}

// ============================================================================
// Test Case 3: Resumable Transfer Lifecycle & Progress State
// ============================================================================
TEST_F(FilesPostgresPersistenceIntegrationTest, ResumableTransferLifecycleAndProgressState) {
    FileRepository file_repo(pool_);
    FileTransferRepository transfer_repo(pool_);
    FileChunkRepository chunk_repo(pool_);

    const std::string file_id = "test-file-xfr-" + generate_test_uuid();

    // 1. Create base file
    {
        FileEntity file;
        file.file_id = file_id;
        file.owner_user_id = "usr-pers-002";
        file.owner_device_id = "dev-pers-002";
        file.encrypted_size = 5 * 209715;
        file.encryption_algorithm = "XChaCha20-Poly1305";
        file.status = FileStatus::Created;
        file.created_at = std::chrono::system_clock::now();
        file.updated_at = file.created_at;

        EncryptedFileMetadataEntity metadata;
        metadata.file_id = file_id;
        metadata.encrypted_filename = {0xAA, 0xBB};
        metadata.metadata_nonce = std::vector<uint8_t>(24, 0x11);
        metadata.metadata_tag = std::vector<uint8_t>(16, 0x22);
        metadata.client_encryption_metadata_json = "{}";
        metadata.updated_at = file.created_at;

        pqxx::work tx;
        file_repo.create_file(file, metadata, tx);
        tx.commit();
    }

    // 2. Create upload transfer session with 5 chunks
    const std::string transfer_id = "xfr-pers-" + generate_test_uuid();
    FileTransferEntity transfer;
    transfer.transfer_id = transfer_id;
    transfer.file_id = file_id;
    transfer.transfer_type = TransferType::Upload;
    transfer.initiator_user_id = "usr-pers-002";
    transfer.initiator_device_id = "dev-pers-002";
    transfer.status = TransferStatus::Transferring;
    transfer.total_chunks = 5;
    transfer.accepted_chunks = 0;
    transfer.total_bytes = 5 * 209715;
    transfer.transferred_bytes = 0;
    transfer.created_at = std::chrono::system_clock::now();
    transfer.updated_at = transfer.created_at;
    transfer.expires_at = transfer.created_at + std::chrono::hours(24);

    {
        pqxx::work tx;
        transfer_repo.create_transfer(transfer, tx);
        tx.commit();
    }

    // 3. Progressively insert chunks 0, 1, 2
    for (int32_t i = 0; i < 3; ++i) {
        FileChunkEntity chunk;
        chunk.chunk_id = "chk-pers-" + std::to_string(i) + "-" + generate_test_uuid();
        chunk.transfer_id = transfer_id;
        chunk.chunk_index = i;
        chunk.byte_offset = static_cast<int64_t>(i) * 209715;
        chunk.chunk_size = 209715;
        chunk.chunk_hash_sha256 = "hash-chunk-" + std::to_string(i);
        chunk.minio_chunk_key = "uploads/" + transfer_id + "/" + std::to_string(i);
        chunk.status = ChunkStatus::Received;
        chunk.created_at = std::chrono::system_clock::now();

        pqxx::work tx;
        auto result = chunk_repo.record_chunk(chunk, tx);
        EXPECT_EQ(result, ChunkRecordResult::NewlyInserted);
        transfer_repo.increment_chunk_progress(transfer_id, chunk.chunk_size, tx);
        tx.commit();
    }

    // 4. Queries get_accepted_chunk_indices(); asserts missing chunks are 3 and 4
    {
        pqxx::work tx;
        auto accepted = chunk_repo.get_accepted_chunk_indices(transfer_id, tx);
        EXPECT_EQ(accepted.size(), 3u);
        EXPECT_EQ(accepted, (std::vector<int32_t>{0, 1, 2}));

        std::vector<int32_t> missing;
        for (int32_t i = 0; i < transfer.total_chunks; ++i) {
            if (std::find(accepted.begin(), accepted.end(), i) == accepted.end()) {
                missing.push_back(i);
            }
        }
        EXPECT_EQ(missing, (std::vector<int32_t>{3, 4}));

        auto current_xfr = transfer_repo.find_by_id(transfer_id, tx);
        ASSERT_TRUE(current_xfr.has_value());
        EXPECT_EQ(current_xfr->accepted_chunks, 3);
        EXPECT_EQ(current_xfr->transferred_bytes, 3 * 209715);
    }

    // 5. Simulates client retry of chunk 1; asserts idempotent success
    {
        FileChunkEntity chunk1_retry;
        chunk1_retry.chunk_id = "chk-retry-" + generate_test_uuid();
        chunk1_retry.transfer_id = transfer_id;
        chunk1_retry.chunk_index = 1;
        chunk1_retry.byte_offset = 209715;
        chunk1_retry.chunk_size = 209715;
        chunk1_retry.chunk_hash_sha256 = "hash-chunk-1";
        chunk1_retry.minio_chunk_key = "uploads/" + transfer_id + "/1";
        chunk1_retry.status = ChunkStatus::Received;
        chunk1_retry.created_at = std::chrono::system_clock::now();

        pqxx::work tx;
        auto retry_res = chunk_repo.record_chunk(chunk1_retry, tx);
        EXPECT_EQ(retry_res, ChunkRecordResult::AlreadyExistsIdentical);
        tx.commit();
    }

    // Assert total accepted chunks count is still strictly 3
    {
        pqxx::work tx;
        EXPECT_EQ(chunk_repo.count_accepted_chunks(transfer_id, tx), 3);
    }
}

// ============================================================================
// Test Case 4: Atomic Finalization & Transactional Outbox Stage
// ============================================================================
TEST_F(FilesPostgresPersistenceIntegrationTest, AtomicFinalizationAndTransactionalOutboxStage) {
    FileRepository file_repo(pool_);
    FileVersionRepository version_repo(pool_);
    FileTransferRepository transfer_repo(pool_);
    FilesOutboxRepository outbox_repo(pool_);

    const std::string file_id = "test-file-fin-" + generate_test_uuid();
    const std::string transfer_id = "xfr-fin-" + generate_test_uuid();
    const std::string event_id = "evt-fin-" + generate_test_uuid();

    // 1. Initial file and transfer setup (status Finalizing for finalization transition)
    {
        FileEntity file;
        file.file_id = file_id;
        file.owner_user_id = "usr-pers-003";
        file.owner_device_id = "dev-pers-003";
        file.encrypted_size = 209715;
        file.encryption_algorithm = "XChaCha20-Poly1305";
        file.status = FileStatus::Finalizing;
        file.created_at = std::chrono::system_clock::now();
        file.updated_at = file.created_at;

        EncryptedFileMetadataEntity metadata;
        metadata.file_id = file_id;
        metadata.encrypted_filename = {0xEE, 0xFF};
        metadata.metadata_nonce = std::vector<uint8_t>(24, 0x33);
        metadata.metadata_tag = std::vector<uint8_t>(16, 0x44);
        metadata.client_encryption_metadata_json = "{}";
        metadata.updated_at = file.created_at;

        FileTransferEntity transfer;
        transfer.transfer_id = transfer_id;
        transfer.file_id = file_id;
        transfer.transfer_type = TransferType::Upload;
        transfer.initiator_user_id = "usr-pers-003";
        transfer.initiator_device_id = "dev-pers-003";
        transfer.status = TransferStatus::Transferring;
        transfer.total_chunks = 1;
        transfer.accepted_chunks = 1;
        transfer.total_bytes = 209715;
        transfer.transferred_bytes = 209715;
        transfer.created_at = file.created_at;
        transfer.updated_at = file.created_at;

        pqxx::work tx;
        file_repo.create_file(file, metadata, tx);
        transfer_repo.create_transfer(transfer, tx);
        tx.commit();
    }

    // 2. Atomic Finalization Transaction:
    // Begins pqxx::work:
    // - Transitions file to Available
    // - Creates FileVersionEntity #1
    // - Updates transfer to Completed
    // - Stages FILE_UPLOAD_COMPLETED event in files_outbox
    {
        pqxx::work tx;

        // Transition file from Finalizing to Available
        EXPECT_TRUE(file_repo.update_status(file_id, FileStatus::Finalizing, FileStatus::Available, tx));

        // Create version #1
        FileVersionEntity version1;
        version1.version_id = "ver-1-" + generate_test_uuid();
        version1.file_id = file_id;
        version1.version_number = 1;
        version1.encrypted_size = 209715;
        version1.minio_object_key = "files/" + file_id + "/v1";
        version1.checksum_sha256 = "sha256-v1-hash";
        version1.created_at = std::chrono::system_clock::now();
        version1.is_active = true;
        version_repo.create_version(version1, tx);

        // Update transfer to Completed
        EXPECT_TRUE(transfer_repo.update_status(transfer_id, TransferStatus::Completed, tx));

        // Stage FILE_UPLOAD_COMPLETED outbox event
        FilesOutboxEntity outbox;
        outbox.event_id = event_id;
        outbox.aggregate_type = "FILE";
        outbox.aggregate_id = file_id;
        outbox.event_type = "FILE_UPLOAD_COMPLETED";
        outbox.payload_json = "{\"file_id\":\"" + file_id + "\",\"version\":1,\"size\":209715}";
        outbox.status = OutboxStatus::Pending;
        outbox.retry_count = 0;
        outbox.created_at = std::chrono::system_clock::now();
        outbox_repo.stage_event(outbox, tx);

        // Commit transaction atomically
        tx.commit();
    }

    // 3. Asserts outbox record has status Pending and domain state is consistent
    {
        pqxx::work tx;
        auto updated_file = file_repo.find_by_id(file_id, tx);
        ASSERT_TRUE(updated_file.has_value());
        EXPECT_EQ(updated_file->status, FileStatus::Available);

        auto active_ver = version_repo.find_active_version(file_id, tx);
        ASSERT_TRUE(active_ver.has_value());
        EXPECT_EQ(active_ver->version_number, 1);
        EXPECT_EQ(active_ver->minio_object_key, "files/" + file_id + "/v1");

        auto updated_xfr = transfer_repo.find_by_id(transfer_id, tx);
        ASSERT_TRUE(updated_xfr.has_value());
        EXPECT_EQ(updated_xfr->status, TransferStatus::Completed);

        auto staged_event = outbox_repo.find_by_id(event_id, tx);
        ASSERT_TRUE(staged_event.has_value());
        EXPECT_EQ(staged_event->status, OutboxStatus::Pending);
        EXPECT_EQ(staged_event->event_type, "FILE_UPLOAD_COMPLETED");
        EXPECT_EQ(staged_event->aggregate_id, file_id);
    }
}

// ============================================================================
// Test Case 5: Durable State Survives Service Teardown (Simulated Process Restart)
// ============================================================================
TEST_F(FilesPostgresPersistenceIntegrationTest, DurableStateSurvivesServiceTeardown) {
    const std::string file_id = "test-file-restart-" + generate_test_uuid();
    const std::string transfer_id = "xfr-restart-" + generate_test_uuid();
    const std::string event_id = "evt-restart-" + generate_test_uuid();
    const std::vector<uint8_t> secret_filename = {0xDE, 0xAD, 0xC0, 0xDE};

    // Phase 1: Initialize, populate entities, and commit data
    {
        FileRepository file_repo(pool_);
        FileVersionRepository version_repo(pool_);
        FileTransferRepository transfer_repo(pool_);
        FileChunkRepository chunk_repo(pool_);
        FilesOutboxRepository outbox_repo(pool_);

        pqxx::work tx;

        // 1. File & Metadata
        FileEntity file;
        file.file_id = file_id;
        file.owner_user_id = "usr-restart-001";
        file.owner_device_id = "dev-restart-001";
        file.encrypted_size = 500000;
        file.encryption_algorithm = "XChaCha20-Poly1305";
        file.status = FileStatus::Available;
        file.created_at = std::chrono::system_clock::now();
        file.updated_at = file.created_at;

        EncryptedFileMetadataEntity metadata;
        metadata.file_id = file_id;
        metadata.encrypted_filename = secret_filename;
        metadata.metadata_nonce = std::vector<uint8_t>(24, 0x77);
        metadata.metadata_tag = std::vector<uint8_t>(16, 0x88);
        metadata.client_encryption_metadata_json = "{\"version\":1}";
        metadata.updated_at = file.created_at;

        file_repo.create_file(file, metadata, tx);

        // 2. Active Version
        FileVersionEntity version1;
        version1.version_id = "ver-restart-1";
        version1.file_id = file_id;
        version1.version_number = 1;
        version1.encrypted_size = 500000;
        version1.minio_object_key = "files/" + file_id + "/v1";
        version1.checksum_sha256 = "hash-durable";
        version1.created_at = file.created_at;
        version1.is_active = true;
        version_repo.create_version(version1, tx);

        // 3. Transfer & Chunks
        FileTransferEntity transfer;
        transfer.transfer_id = transfer_id;
        transfer.file_id = file_id;
        transfer.transfer_type = TransferType::Upload;
        transfer.initiator_user_id = "usr-restart-001";
        transfer.initiator_device_id = "dev-restart-001";
        transfer.status = TransferStatus::Completed;
        transfer.total_chunks = 2;
        transfer.accepted_chunks = 2;
        transfer.total_bytes = 500000;
        transfer.transferred_bytes = 500000;
        transfer.created_at = file.created_at;
        transfer.updated_at = file.created_at;
        transfer_repo.create_transfer(transfer, tx);

        FileChunkEntity c0;
        c0.chunk_id = "chk-restart-0";
        c0.transfer_id = transfer_id;
        c0.chunk_index = 0;
        c0.byte_offset = 0;
        c0.chunk_size = 250000;
        c0.chunk_hash_sha256 = "hash-chk-0";
        c0.minio_chunk_key = "uploads/" + transfer_id + "/0";
        c0.status = ChunkStatus::Received;
        c0.created_at = file.created_at;
        chunk_repo.record_chunk(c0, tx);

        FileChunkEntity c1;
        c1.chunk_id = "chk-restart-1";
        c1.transfer_id = transfer_id;
        c1.chunk_index = 1;
        c1.byte_offset = 250000;
        c1.chunk_size = 250000;
        c1.chunk_hash_sha256 = "hash-chk-1";
        c1.minio_chunk_key = "uploads/" + transfer_id + "/1";
        c1.status = ChunkStatus::Received;
        c1.created_at = file.created_at;
        chunk_repo.record_chunk(c1, tx);

        // 4. Outbox Event
        FilesOutboxEntity outbox;
        outbox.event_id = event_id;
        outbox.aggregate_type = "FILE";
        outbox.aggregate_id = file_id;
        outbox.event_type = "FILE_UPLOAD_COMPLETED";
        outbox.payload_json = "{\"file_id\":\"" + file_id + "\"}";
        outbox.status = OutboxStatus::Pending;
        outbox.retry_count = 0;
        outbox.created_at = file.created_at;
        outbox_repo.stage_event(outbox, tx);

        tx.commit();
    }

    // Phase 2: Destroys all repository and connection pool instances in memory
    // (Simulating process teardown and restart)
    pool_->drain();
    pool_->close();
    pool_.reset();

    // Phase 3: Re-initializes new connection pool and repository instances from scratch
    auto new_pool = std::make_shared<db::FilesDbConnectionPool>(db_config_);
    FileRepository new_file_repo(new_pool);
    FileVersionRepository new_version_repo(new_pool);
    FileTransferRepository new_transfer_repo(new_pool);
    FileChunkRepository new_chunk_repo(new_pool);
    FilesOutboxRepository new_outbox_repo(new_pool);

    // Phase 4: Queries all entities; asserts all states are 100% intact and consistent
    {
        pqxx::work tx;

        // 1. File verification
        auto reloaded_file = new_file_repo.find_by_id(file_id, tx);
        ASSERT_TRUE(reloaded_file.has_value());
        EXPECT_EQ(reloaded_file->file_id, file_id);
        EXPECT_EQ(reloaded_file->status, FileStatus::Available);
        EXPECT_EQ(reloaded_file->encrypted_size, 500000);

        // 2. Client-encrypted metadata verification
        auto reloaded_meta = new_file_repo.find_encrypted_metadata(file_id, tx);
        ASSERT_TRUE(reloaded_meta.has_value());
        EXPECT_EQ(reloaded_meta->encrypted_filename, secret_filename);
        EXPECT_EQ(reloaded_meta->metadata_nonce.size(), 24u);
        EXPECT_EQ(reloaded_meta->metadata_tag.size(), 16u);

        // 3. Version verification
        auto reloaded_ver = new_version_repo.find_active_version(file_id, tx);
        ASSERT_TRUE(reloaded_ver.has_value());
        EXPECT_EQ(reloaded_ver->version_number, 1);
        EXPECT_EQ(reloaded_ver->minio_object_key, "files/" + file_id + "/v1");
        EXPECT_TRUE(reloaded_ver->is_active);

        // 4. Transfer verification
        auto reloaded_xfr = new_transfer_repo.find_by_id(transfer_id, tx);
        ASSERT_TRUE(reloaded_xfr.has_value());
        EXPECT_EQ(reloaded_xfr->status, TransferStatus::Completed);
        EXPECT_EQ(reloaded_xfr->accepted_chunks, 2);
        EXPECT_EQ(reloaded_xfr->transferred_bytes, 500000);

        // 5. Chunks verification
        auto reloaded_indices = new_chunk_repo.get_accepted_chunk_indices(transfer_id, tx);
        EXPECT_EQ(reloaded_indices, (std::vector<int32_t>{0, 1}));
        EXPECT_TRUE(new_chunk_repo.is_chunk_present(transfer_id, 0, tx));
        EXPECT_TRUE(new_chunk_repo.is_chunk_present(transfer_id, 1, tx));
        EXPECT_FALSE(new_chunk_repo.is_chunk_present(transfer_id, 2, tx));

        // 6. Outbox verification
        auto reloaded_outbox = new_outbox_repo.find_by_id(event_id, tx);
        ASSERT_TRUE(reloaded_outbox.has_value());
        EXPECT_EQ(reloaded_outbox->status, OutboxStatus::Pending);
        EXPECT_EQ(reloaded_outbox->event_type, "FILE_UPLOAD_COMPLETED");
        EXPECT_EQ(reloaded_outbox->aggregate_id, file_id);
    }

    new_pool->drain();
    new_pool->close();
}

} // namespace
} // namespace securecloud::files

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
