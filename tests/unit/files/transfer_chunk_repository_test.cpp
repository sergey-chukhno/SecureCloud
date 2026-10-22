#include "files/db/pqxx_compat.hpp"
#include "files/domain/file_chunk_entity.hpp"
#include "files/domain/file_transfer_entity.hpp"
#include "files/repository/file_chunk_repository.hpp"
#include "files/repository/file_transfer_repository.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::files {
namespace {

class TransferChunkRepositoryTest : public ::testing::Test {
  protected:
    void SetUp() override {
        // Reset mock in-memory storage before each test
        pqxx::MockStorage::instance().reset();
    }
};

FileTransferEntity make_sample_transfer(std::string transfer_id = "transfer-uuid-1",
                                        std::string file_id = "file-uuid-1") {
    FileTransferEntity t;
    t.transfer_id = std::move(transfer_id);
    t.file_id = std::move(file_id);
    t.transfer_type = TransferType::Upload;
    t.initiator_user_id = "user-uuid-1";
    t.initiator_device_id = "device-uuid-1";
    t.status = TransferStatus::Created;
    t.total_chunks = 3;
    t.accepted_chunks = 0;
    t.total_bytes = 3145728; // 3 * 1024 * 1024
    t.transferred_bytes = 0;
    t.created_at = std::chrono::system_clock::now();
    t.updated_at = t.created_at;
    t.expires_at = t.created_at + std::chrono::hours(24);
    return t;
}

FileChunkEntity make_sample_chunk(std::string transfer_id, int32_t chunk_index, std::string hash = "hash-abc-0") {
    FileChunkEntity c;
    c.chunk_id = "chunk-uuid-" + transfer_id + "-" + std::to_string(chunk_index);
    c.transfer_id = std::move(transfer_id);
    c.chunk_index = chunk_index;
    c.byte_offset = static_cast<int64_t>(chunk_index) * 1048576;
    c.chunk_size = 1048576;
    c.chunk_hash_sha256 = std::move(hash);
    c.minio_chunk_key = "chunks/" + c.transfer_id + "/" + std::to_string(chunk_index);
    c.status = ChunkStatus::Received;
    c.created_at = std::chrono::system_clock::now();
    return c;
}

// ============================================================================
// FileTransferRepository Unit Tests
// ============================================================================

TEST_F(TransferChunkRepositoryTest, CreateAndFindTransfer) {
    FileTransferRepository repo;
    auto transfer = make_sample_transfer("trans-100", "file-100");

    {
        pqxx::work tx;
        repo.create_transfer(transfer, tx);
        tx.commit();
    }

    // Retrieve via autonomous session
    auto found = repo.find_by_id("trans-100");
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->transfer_id, "trans-100");
    EXPECT_EQ(found->file_id, "file-100");
    EXPECT_EQ(found->transfer_type, TransferType::Upload);
    EXPECT_EQ(found->initiator_user_id, "user-uuid-1");
    EXPECT_EQ(found->initiator_device_id, "device-uuid-1");
    EXPECT_EQ(found->status, TransferStatus::Created);
    EXPECT_EQ(found->total_chunks, 3);
    EXPECT_EQ(found->accepted_chunks, 0);
    EXPECT_EQ(found->total_bytes, 3145728);
    EXPECT_EQ(found->transferred_bytes, 0);

    // Retrieve within transaction
    pqxx::work tx;
    auto found_tx = repo.find_by_id("trans-100", tx);
    ASSERT_TRUE(found_tx.has_value());
    EXPECT_EQ(found_tx->transfer_id, "trans-100");
}

TEST_F(TransferChunkRepositoryTest, FindNonExistentTransferReturnsNullopt) {
    FileTransferRepository repo;

    EXPECT_FALSE(repo.find_by_id("non-existent-transfer").has_value());
    EXPECT_FALSE(repo.find_by_id("").has_value());
}

TEST_F(TransferChunkRepositoryTest, UpdateTransferStatus) {
    FileTransferRepository repo;
    auto transfer = make_sample_transfer("trans-200", "file-200");

    {
        pqxx::work tx;
        repo.create_transfer(transfer, tx);
        tx.commit();
    }

    // Transition Created -> Transferring
    EXPECT_TRUE(repo.update_status("trans-200", TransferStatus::Transferring));
    auto t1 = repo.find_by_id("trans-200");
    ASSERT_TRUE(t1.has_value());
    EXPECT_EQ(t1->status, TransferStatus::Transferring);

    // Transition Transferring -> Completed
    EXPECT_TRUE(repo.update_status("trans-200", TransferStatus::Completed));
    auto t2 = repo.find_by_id("trans-200");
    ASSERT_TRUE(t2.has_value());
    EXPECT_EQ(t2->status, TransferStatus::Completed);

    // Unknown transfer update returns false
    EXPECT_FALSE(repo.update_status("unknown-transfer", TransferStatus::Failed));
    EXPECT_FALSE(repo.update_status("", TransferStatus::Failed));
}

TEST_F(TransferChunkRepositoryTest, IncrementChunkProgress) {
    FileTransferRepository repo;
    auto transfer = make_sample_transfer("trans-300", "file-300");

    {
        pqxx::work tx;
        repo.create_transfer(transfer, tx);
        tx.commit();
    }

    // First chunk progress increment
    EXPECT_TRUE(repo.increment_chunk_progress("trans-300", 1048576));
    auto t1 = repo.find_by_id("trans-300");
    ASSERT_TRUE(t1.has_value());
    EXPECT_EQ(t1->accepted_chunks, 1);
    EXPECT_EQ(t1->transferred_bytes, 1048576);

    // Second chunk progress increment
    EXPECT_TRUE(repo.increment_chunk_progress("trans-300", 1048576));
    auto t2 = repo.find_by_id("trans-300");
    ASSERT_TRUE(t2.has_value());
    EXPECT_EQ(t2->accepted_chunks, 2);
    EXPECT_EQ(t2->transferred_bytes, 2097152);

    // Non-existent transfer returns false
    EXPECT_FALSE(repo.increment_chunk_progress("unknown-transfer", 1024));
    EXPECT_FALSE(repo.increment_chunk_progress("", 1024));
}

TEST_F(TransferChunkRepositoryTest, CreateTransferValidationFailures) {
    FileTransferRepository repo;
    pqxx::work tx;

    auto t_empty_id = make_sample_transfer("", "file-1");
    EXPECT_THROW(repo.create_transfer(t_empty_id, tx), RepositoryException);

    auto t_empty_file = make_sample_transfer("trans-1", "");
    EXPECT_THROW(repo.create_transfer(t_empty_file, tx), RepositoryException);

    auto t_empty_user = make_sample_transfer("trans-1", "file-1");
    t_empty_user.initiator_user_id = "";
    EXPECT_THROW(repo.create_transfer(t_empty_user, tx), RepositoryException);
}

TEST_F(TransferChunkRepositoryTest, TransferTransactionRollback) {
    FileTransferRepository repo;
    auto transfer = make_sample_transfer("trans-rollback", "file-rollback");

    {
        pqxx::work tx;
        repo.create_transfer(transfer, tx);
        tx.abort(); // Explicit rollback
    }

    EXPECT_FALSE(repo.find_by_id("trans-rollback").has_value());
}

// ============================================================================
// FileChunkRepository Unit Tests
// ============================================================================

TEST_F(TransferChunkRepositoryTest, RecordChunkNewlyInserted) {
    FileChunkRepository repo;
    auto chunk = make_sample_chunk("trans-chunk-1", 0, "hash-0");

    pqxx::work tx;
    auto result = repo.record_chunk(chunk, tx);
    tx.commit();

    EXPECT_EQ(result, ChunkRecordResult::NewlyInserted);
    EXPECT_TRUE(repo.is_chunk_present("trans-chunk-1", 0));
    EXPECT_EQ(repo.count_accepted_chunks("trans-chunk-1"), 1);
}

TEST_F(TransferChunkRepositoryTest, RecordChunkIdempotentReplay) {
    FileChunkRepository repo;
    auto chunk = make_sample_chunk("trans-chunk-2", 0, "hash-idempotent");

    // First attempt: newly inserted
    {
        pqxx::work tx;
        auto result = repo.record_chunk(chunk, tx);
        EXPECT_EQ(result, ChunkRecordResult::NewlyInserted);
        tx.commit();
    }

    // Second attempt: identical replay
    {
        pqxx::work tx;
        auto result = repo.record_chunk(chunk, tx);
        EXPECT_EQ(result, ChunkRecordResult::AlreadyExistsIdentical);
        tx.commit();
    }

    // Count is still 1
    EXPECT_EQ(repo.count_accepted_chunks("trans-chunk-2"), 1);
}

TEST_F(TransferChunkRepositoryTest, RecordChunkConflictHashMismatchThrowsIntegrityException) {
    FileChunkRepository repo;
    auto chunk1 = make_sample_chunk("trans-chunk-3", 0, "original-sha256-hash");
    auto chunk2 = make_sample_chunk("trans-chunk-3", 0, "corrupted-or-tampered-hash");

    // First attempt: succeeds
    {
        pqxx::work tx;
        auto result = repo.record_chunk(chunk1, tx);
        EXPECT_EQ(result, ChunkRecordResult::NewlyInserted);
        tx.commit();
    }

    // Second attempt with differing hash: throws ChunkIntegrityException
    {
        pqxx::work tx;
        EXPECT_THROW(repo.record_chunk(chunk2, tx), ChunkIntegrityException);
    }
}

TEST_F(TransferChunkRepositoryTest, GetAcceptedChunkIndicesOrdered) {
    FileChunkRepository repo;
    const std::string transfer_id = "trans-chunk-4";

    // Insert chunks out of order: 2, 0, 1
    {
        pqxx::work tx;
        repo.record_chunk(make_sample_chunk(transfer_id, 2, "hash-2"), tx);
        repo.record_chunk(make_sample_chunk(transfer_id, 0, "hash-0"), tx);
        repo.record_chunk(make_sample_chunk(transfer_id, 1, "hash-1"), tx);
        tx.commit();
    }

    auto indices = repo.get_accepted_chunk_indices(transfer_id);
    ASSERT_EQ(indices.size(), 3u);
    EXPECT_EQ(indices[0], 0);
    EXPECT_EQ(indices[1], 1);
    EXPECT_EQ(indices[2], 2);

    // Empty transfer ID returns empty vector
    EXPECT_TRUE(repo.get_accepted_chunk_indices("").empty());
}

TEST_F(TransferChunkRepositoryTest, CountAcceptedChunks) {
    FileChunkRepository repo;
    const std::string transfer_id = "trans-chunk-5";

    EXPECT_EQ(repo.count_accepted_chunks(transfer_id), 0);

    {
        pqxx::work tx;
        repo.record_chunk(make_sample_chunk(transfer_id, 0, "h0"), tx);
        repo.record_chunk(make_sample_chunk(transfer_id, 1, "h1"), tx);
        repo.record_chunk(make_sample_chunk(transfer_id, 2, "h2"), tx);
        tx.commit();
    }

    EXPECT_EQ(repo.count_accepted_chunks(transfer_id), 3);
    EXPECT_EQ(repo.count_accepted_chunks("unknown-trans"), 0);
    EXPECT_EQ(repo.count_accepted_chunks(""), 0);
}

TEST_F(TransferChunkRepositoryTest, IsChunkPresent) {
    FileChunkRepository repo;
    const std::string transfer_id = "trans-chunk-6";

    {
        pqxx::work tx;
        repo.record_chunk(make_sample_chunk(transfer_id, 0, "h0"), tx);
        repo.record_chunk(make_sample_chunk(transfer_id, 2, "h2"), tx);
        tx.commit();
    }

    EXPECT_TRUE(repo.is_chunk_present(transfer_id, 0));
    EXPECT_FALSE(repo.is_chunk_present(transfer_id, 1));
    EXPECT_TRUE(repo.is_chunk_present(transfer_id, 2));
    EXPECT_FALSE(repo.is_chunk_present(transfer_id, 3));
    EXPECT_FALSE(repo.is_chunk_present(transfer_id, -1));
    EXPECT_FALSE(repo.is_chunk_present("unknown-trans", 0));
    EXPECT_FALSE(repo.is_chunk_present("", 0));
}

TEST_F(TransferChunkRepositoryTest, ListChunksForTransfer) {
    FileChunkRepository repo;
    const std::string transfer_id = "trans-chunk-7";

    // Insert out of order: 1, 0
    {
        pqxx::work tx;
        repo.record_chunk(make_sample_chunk(transfer_id, 1, "hash-1"), tx);
        repo.record_chunk(make_sample_chunk(transfer_id, 0, "hash-0"), tx);
        tx.commit();
    }

    auto chunks = repo.list_chunks_for_transfer(transfer_id);
    ASSERT_EQ(chunks.size(), 2u);

    // Ordered by chunk_index ASC
    EXPECT_EQ(chunks[0].chunk_index, 0);
    EXPECT_EQ(chunks[0].chunk_hash_sha256, "hash-0");
    EXPECT_EQ(chunks[0].chunk_size, 1048576);
    EXPECT_EQ(chunks[0].status, ChunkStatus::Received);

    EXPECT_EQ(chunks[1].chunk_index, 1);
    EXPECT_EQ(chunks[1].chunk_hash_sha256, "hash-1");

    EXPECT_TRUE(repo.list_chunks_for_transfer("").empty());
    EXPECT_TRUE(repo.list_chunks_for_transfer("unknown-trans").empty());
}

TEST_F(TransferChunkRepositoryTest, ChunkValidationFailures) {
    FileChunkRepository repo;
    pqxx::work tx;

    auto c_empty_id = make_sample_chunk("t1", 0, "h");
    c_empty_id.chunk_id = "";
    EXPECT_THROW(repo.record_chunk(c_empty_id, tx), RepositoryException);

    auto c_empty_trans = make_sample_chunk("", 0, "h");
    EXPECT_THROW(repo.record_chunk(c_empty_trans, tx), RepositoryException);

    auto c_neg_idx = make_sample_chunk("t1", -1, "h");
    EXPECT_THROW(repo.record_chunk(c_neg_idx, tx), RepositoryException);

    auto c_neg_size = make_sample_chunk("t1", 0, "h");
    c_neg_size.chunk_size = -1;
    EXPECT_THROW(repo.record_chunk(c_neg_size, tx), RepositoryException);

    auto c_empty_hash = make_sample_chunk("t1", 0, "");
    EXPECT_THROW(repo.record_chunk(c_empty_hash, tx), RepositoryException);
}

TEST_F(TransferChunkRepositoryTest, ChunkTransactionRollback) {
    FileChunkRepository repo;
    const std::string transfer_id = "trans-chunk-rollback";

    {
        pqxx::work tx;
        auto res = repo.record_chunk(make_sample_chunk(transfer_id, 0, "hash-0"), tx);
        EXPECT_EQ(res, ChunkRecordResult::NewlyInserted);
        tx.abort(); // Rollback
    }

    EXPECT_EQ(repo.count_accepted_chunks(transfer_id), 0);
    EXPECT_FALSE(repo.is_chunk_present(transfer_id, 0));
}

TEST_F(TransferChunkRepositoryTest, MultiTransferIsolation) {
    FileChunkRepository repo;
    const std::string trans_a = "trans-a";
    const std::string trans_b = "trans-b";

    {
        pqxx::work tx;
        repo.record_chunk(make_sample_chunk(trans_a, 0, "hash-a0"), tx);
        repo.record_chunk(make_sample_chunk(trans_a, 1, "hash-a1"), tx);
        repo.record_chunk(make_sample_chunk(trans_b, 0, "hash-b0"), tx);
        tx.commit();
    }

    EXPECT_EQ(repo.count_accepted_chunks(trans_a), 2);
    EXPECT_EQ(repo.count_accepted_chunks(trans_b), 1);

    auto indices_a = repo.get_accepted_chunk_indices(trans_a);
    ASSERT_EQ(indices_a.size(), 2u);
    EXPECT_EQ(indices_a[0], 0);
    EXPECT_EQ(indices_a[1], 1);

    auto indices_b = repo.get_accepted_chunk_indices(trans_b);
    ASSERT_EQ(indices_b.size(), 1u);
    EXPECT_EQ(indices_b[0], 0);
}

} // namespace
} // namespace securecloud::files
