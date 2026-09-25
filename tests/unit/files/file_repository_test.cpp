#include "files/db/pqxx_compat.hpp"
#include "files/domain/encrypted_file_metadata_entity.hpp"
#include "files/domain/file_entity.hpp"
#include "files/domain/file_version_entity.hpp"
#include "files/repository/file_repository.hpp"
#include "files/repository/file_version_repository.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <vector>

namespace securecloud::files {
namespace {

class FileRepositoryTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Reset mock in-memory storage before each test
        pqxx::MockStorage::instance().reset();
    }
};

FileEntity make_sample_file(std::string id = "file-uuid-1") {
    FileEntity f;
    f.file_id = std::move(id);
    f.owner_user_id = "user-uuid-1";
    f.owner_device_id = "device-uuid-1";
    f.conversation_id = "conv-uuid-1";
    f.encrypted_size = 1048576;
    f.content_type = "application/octet-stream";
    f.encryption_algorithm = "XChaCha20-Poly1305";
    f.status = FileStatus::Created;
    f.created_at = std::chrono::system_clock::now();
    f.updated_at = f.created_at;
    return f;
}

EncryptedFileMetadataEntity make_sample_metadata(std::string id = "file-uuid-1") {
    EncryptedFileMetadataEntity m;
    m.file_id = std::move(id);
    m.encrypted_filename = {0x01, 0x02, 0x03, 0x04};
    m.encrypted_mime_type = std::vector<uint8_t>{0xAA, 0xBB};
    m.metadata_nonce = {0x11, 0x22, 0x33, 0x44};
    m.metadata_tag = {0x55, 0x66, 0x77, 0x88};
    m.client_encryption_metadata_json = "{\"version\":1}";
    m.updated_at = std::chrono::system_clock::now();
    return m;
}

// --- 1. Atomic File & Metadata Creation Tests ---

TEST_F(FileRepositoryTest, AtomicCreateAndRetrieveFileAndMetadata) {
    FileRepository repo;

    auto file = make_sample_file("file-100");
    auto meta = make_sample_metadata("file-100");

    {
        pqxx::work tx;
        repo.create_file(file, meta, tx);
        tx.commit();
    }

    auto retrieved_file = repo.find_by_id("file-100");
    ASSERT_TRUE(retrieved_file.has_value());
    EXPECT_EQ(retrieved_file->file_id, "file-100");
    EXPECT_EQ(retrieved_file->owner_user_id, "user-uuid-1");
    EXPECT_EQ(retrieved_file->status, FileStatus::Created);
    EXPECT_EQ(retrieved_file->encrypted_size, 1048576);

    auto retrieved_meta = repo.find_encrypted_metadata("file-100");
    ASSERT_TRUE(retrieved_meta.has_value());
    EXPECT_EQ(retrieved_meta->file_id, "file-100");
    EXPECT_EQ(retrieved_meta->encrypted_filename, meta.encrypted_filename);
    ASSERT_TRUE(retrieved_meta->encrypted_mime_type.has_value());
    EXPECT_EQ(*retrieved_meta->encrypted_mime_type, *meta.encrypted_mime_type);
    EXPECT_EQ(retrieved_meta->metadata_nonce, meta.metadata_nonce);
    EXPECT_EQ(retrieved_meta->metadata_tag, meta.metadata_tag);
    EXPECT_EQ(retrieved_meta->client_encryption_metadata_json, "{\"version\":1}");
}

TEST_F(FileRepositoryTest, CreateFileRejectsIdMismatch) {
    FileRepository repo;
    auto file = make_sample_file("file-1");
    auto meta = make_sample_metadata("file-2"); // Mismatch

    pqxx::work tx;
    EXPECT_THROW(repo.create_file(file, meta, tx), RepositoryException);
}

TEST_F(FileRepositoryTest, TransactionAbortRollsBackCreation) {
    FileRepository repo;
    auto file = make_sample_file("file-aborted");
    auto meta = make_sample_metadata("file-aborted");

    {
        pqxx::work tx;
        repo.create_file(file, meta, tx);
        // Exiting without commit() -> automatic abort
    }

    auto retrieved = repo.find_by_id("file-aborted");
    EXPECT_FALSE(retrieved.has_value());

    auto retrieved_meta = repo.find_encrypted_metadata("file-aborted");
    EXPECT_FALSE(retrieved_meta.has_value());
}

TEST_F(FileRepositoryTest, FindByIdReturnsNulloptForMissing) {
    FileRepository repo;
    EXPECT_FALSE(repo.find_by_id("non-existent-id").has_value());
    EXPECT_FALSE(repo.find_by_id("").has_value());
    EXPECT_FALSE(repo.find_encrypted_metadata("non-existent-id").has_value());
}

// --- 2. State Transition & Concurrency Tests ---

TEST_F(FileRepositoryTest, ValidLifecycleTransitionsSucceed) {
    FileRepository repo;
    auto file = make_sample_file("file-lifecycle");
    auto meta = make_sample_metadata("file-lifecycle");

    {
        pqxx::work tx;
        repo.create_file(file, meta, tx);
        tx.commit();
    }

    // CREATED -> UPLOADING
    {
        pqxx::work tx;
        EXPECT_TRUE(repo.update_status("file-lifecycle", FileStatus::Created, FileStatus::Uploading, tx));
        tx.commit();
    }
    EXPECT_EQ(repo.find_by_id("file-lifecycle")->status, FileStatus::Uploading);

    // UPLOADING -> FINALIZING
    {
        pqxx::work tx;
        EXPECT_TRUE(repo.update_status("file-lifecycle", FileStatus::Uploading, FileStatus::Finalizing, tx));
        tx.commit();
    }
    EXPECT_EQ(repo.find_by_id("file-lifecycle")->status, FileStatus::Finalizing);

    // FINALIZING -> AVAILABLE
    {
        pqxx::work tx;
        EXPECT_TRUE(repo.update_status("file-lifecycle", FileStatus::Finalizing, FileStatus::Available, tx));
        tx.commit();
    }
    EXPECT_EQ(repo.find_by_id("file-lifecycle")->status, FileStatus::Available);

    // AVAILABLE -> EXPIRED
    {
        pqxx::work tx;
        EXPECT_TRUE(repo.update_status("file-lifecycle", FileStatus::Available, FileStatus::Expired, tx));
        tx.commit();
    }
    EXPECT_EQ(repo.find_by_id("file-lifecycle")->status, FileStatus::Expired);

    // EXPIRED -> DELETED
    {
        pqxx::work tx;
        EXPECT_TRUE(repo.update_status("file-lifecycle", FileStatus::Expired, FileStatus::Deleted, tx));
        tx.commit();
    }
    EXPECT_EQ(repo.find_by_id("file-lifecycle")->status, FileStatus::Deleted);
}

TEST_F(FileRepositoryTest, InvalidStateTransitionThrowsException) {
    FileRepository repo;
    auto file = make_sample_file("file-invalid-trans");
    auto meta = make_sample_metadata("file-invalid-trans");

    {
        pqxx::work tx;
        repo.create_file(file, meta, tx);
        tx.commit();
    }

    // Attempt invalid transition: AVAILABLE -> UPLOADING
    pqxx::work tx;
    EXPECT_THROW(
        repo.update_status("file-invalid-trans", FileStatus::Available, FileStatus::Uploading, tx),
        InvalidStateTransitionException
    );

    // Attempt invalid transition: DELETED -> AVAILABLE
    EXPECT_THROW(
        repo.update_status("file-invalid-trans", FileStatus::Deleted, FileStatus::Available, tx),
        InvalidStateTransitionException
    );
}

TEST_F(FileRepositoryTest, OptimisticConcurrencyMismatchReturnsFalse) {
    FileRepository repo;
    auto file = make_sample_file("file-occ");
    auto meta = make_sample_metadata("file-occ");

    {
        pqxx::work tx;
        repo.create_file(file, meta, tx);
        tx.commit();
    }

    // Expected status is UPLOADING, but file is in CREATED status
    pqxx::work tx;
    bool updated = repo.update_status("file-occ", FileStatus::Uploading, FileStatus::Finalizing, tx);
    EXPECT_FALSE(updated);
    tx.commit();

    // File remains in Created status
    EXPECT_EQ(repo.find_by_id("file-occ")->status, FileStatus::Created);
}

TEST_F(FileRepositoryTest, LogicalDeleteSetsStatusToDeleted) {
    FileRepository repo;
    auto file = make_sample_file("file-to-delete");
    auto meta = make_sample_metadata("file-to-delete");

    {
        pqxx::work tx;
        repo.create_file(file, meta, tx);
        tx.commit();
    }

    {
        pqxx::work tx;
        EXPECT_TRUE(repo.delete_file_logical("file-to-delete", tx));
        tx.commit();
    }

    auto deleted = repo.find_by_id("file-to-delete");
    ASSERT_TRUE(deleted.has_value());
    EXPECT_EQ(deleted->status, FileStatus::Deleted);
}

// --- 3. Expired Files Query Tests ---

TEST_F(FileRepositoryTest, FindExpiredFilesRetrievesExpiredNonDeletedOnly) {
    FileRepository repo;
    auto now = std::chrono::system_clock::now();

    // File 1: Expired in past
    auto f1 = make_sample_file("file-exp-1");
    f1.retention_until = now - std::chrono::hours(2);
    f1.status = FileStatus::Available;
    auto m1 = make_sample_metadata("file-exp-1");

    // File 2: Expired in past but already DELETED
    auto f2 = make_sample_file("file-exp-2");
    f2.retention_until = now - std::chrono::hours(1);
    f2.status = FileStatus::Deleted;
    auto m2 = make_sample_metadata("file-exp-2");

    // File 3: Not yet expired (future retention)
    auto f3 = make_sample_file("file-future");
    f3.retention_until = now + std::chrono::hours(24);
    f3.status = FileStatus::Available;
    auto m3 = make_sample_metadata("file-future");

    {
        pqxx::work tx;
        repo.create_file(f1, m1, tx);
        repo.create_file(f2, m2, tx);
        repo.create_file(f3, m3, tx);
        tx.commit();
    }

    auto expired = repo.find_expired_files(now, 10);
    ASSERT_EQ(expired.size(), 1);
    EXPECT_EQ(expired[0].file_id, "file-exp-1");
}

// --- 4. FileVersionRepository Tests ---

class FileVersionRepositoryTest : public FileRepositoryTest {};

TEST_F(FileVersionRepositoryTest, CreateAndQueryVersions) {
    FileVersionRepository ver_repo;

    FileVersionEntity v1;
    v1.version_id = "ver-uuid-1";
    v1.file_id = "file-ver-100";
    v1.version_number = 1;
    v1.encrypted_size = 2048;
    v1.minio_object_key = "files/file-ver-100/v1.bin";
    v1.checksum_sha256 = "sha256-hash-1";
    v1.created_at = std::chrono::system_clock::now();
    v1.is_active = true;

    {
        pqxx::work tx;
        ver_repo.create_version(v1, tx);
        tx.commit();
    }

    auto active = ver_repo.find_active_version("file-ver-100");
    ASSERT_TRUE(active.has_value());
    EXPECT_EQ(active->version_id, "ver-uuid-1");
    EXPECT_EQ(active->version_number, 1);
    EXPECT_TRUE(active->is_active);

    // Create version 2, active = true -> should deactivate v1
    FileVersionEntity v2;
    v2.version_id = "ver-uuid-2";
    v2.file_id = "file-ver-100";
    v2.version_number = 2;
    v2.encrypted_size = 4096;
    v2.minio_object_key = "files/file-ver-100/v2.bin";
    v2.checksum_sha256 = "sha256-hash-2";
    v2.created_at = std::chrono::system_clock::now();
    v2.is_active = true;

    {
        pqxx::work tx;
        ver_repo.create_version(v2, tx);
        tx.commit();
    }

    auto new_active = ver_repo.find_active_version("file-ver-100");
    ASSERT_TRUE(new_active.has_value());
    EXPECT_EQ(new_active->version_id, "ver-uuid-2");
    EXPECT_EQ(new_active->version_number, 2);

    auto all_versions = ver_repo.list_versions("file-ver-100");
    ASSERT_EQ(all_versions.size(), 2);
    EXPECT_EQ(all_versions[0].version_number, 1);
    EXPECT_FALSE(all_versions[0].is_active);
    EXPECT_EQ(all_versions[1].version_number, 2);
    EXPECT_TRUE(all_versions[1].is_active);
}

TEST_F(FileVersionRepositoryTest, UniqueConstraintViolationOnDuplicateVersion) {
    FileVersionRepository ver_repo;

    FileVersionEntity v1;
    v1.version_id = "ver-1";
    v1.file_id = "file-uniq";
    v1.version_number = 1;
    v1.encrypted_size = 100;
    v1.minio_object_key = "key1";
    v1.checksum_sha256 = "hash1";
    v1.created_at = std::chrono::system_clock::now();
    v1.is_active = true;

    {
        pqxx::work tx;
        ver_repo.create_version(v1, tx);
        tx.commit();
    }

    // Attempt inserting version 1 again for the same file
    FileVersionEntity v1_dup;
    v1_dup.version_id = "ver-2";
    v1_dup.file_id = "file-uniq";
    v1_dup.version_number = 1; // Duplicate
    v1_dup.encrypted_size = 200;
    v1_dup.minio_object_key = "key2";
    v1_dup.checksum_sha256 = "hash2";
    v1_dup.created_at = std::chrono::system_clock::now();
    v1_dup.is_active = true;

    pqxx::work tx;
    EXPECT_THROW(ver_repo.create_version(v1_dup, tx), UniqueConstraintViolationException);
}

} // namespace
} // namespace securecloud::files
