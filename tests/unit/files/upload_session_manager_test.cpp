#include "files/service/upload_session_manager.hpp"

#include <gtest/gtest.h>
#include <thread>
#include <vector>

namespace securecloud::files::service {
namespace {

TEST(UploadSessionManagerTest, CreateAndRetrieveInMemorySession) {
    UploadSessionManager manager(nullptr, nullptr, nullptr);

    v1::CreateFileUploadRequest req;
    req.set_file_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e");
    req.set_owner_user_id("user-alice");
    req.set_owner_device_id("device-desktop");
    req.set_encrypted_size_bytes(8U * 1024U * 1024U);
    req.set_expected_chunk_count(2);
    req.set_encryption_version("XChaCha20-Poly1305");

    auto session_opt = manager.create_session(req);
    ASSERT_TRUE(session_opt.has_value());
    EXPECT_FALSE(session_opt->upload_id.empty());
    EXPECT_EQ(session_opt->file_id, req.file_id());
    EXPECT_EQ(session_opt->owner_user_id, req.owner_user_id());
    EXPECT_EQ(session_opt->expected_chunk_count, 2);
    EXPECT_EQ(session_opt->uploaded_chunk_count, 0);

    auto retrieved_opt = manager.get_session(session_opt->upload_id);
    ASSERT_TRUE(retrieved_opt.has_value());
    EXPECT_EQ(retrieved_opt->upload_id, session_opt->upload_id);
}

TEST(UploadSessionManagerTest, ComputeMissingChunkIndicesSparse) {
    UploadSessionManager manager(nullptr, nullptr, nullptr);

    v1::CreateFileUploadRequest req;
    req.set_file_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e");
    req.set_owner_user_id("user-alice");
    req.set_owner_device_id("device-desktop");
    req.set_encrypted_size_bytes(20U * 1024U * 1024U);
    req.set_expected_chunk_count(5);

    auto session = manager.create_session(req);
    ASSERT_TRUE(session.has_value());

    // In memory without DB, uploaded_chunk_count moves sequentially
    manager.record_chunk_upload(session->upload_id, 0, "hash0");
    manager.record_chunk_upload(session->upload_id, 1, "hash1");

    auto progress = manager.get_transfer_progress(session->upload_id);
    EXPECT_EQ(progress.accepted_chunks, 2);
    EXPECT_EQ(progress.total_chunks, 5);
    EXPECT_FALSE(progress.is_complete);

    std::vector<int32_t> expected_accepted = {0, 1};
    std::vector<int32_t> expected_missing = {2, 3, 4};
    EXPECT_EQ(progress.accepted_chunk_indices, expected_accepted);
    EXPECT_EQ(progress.missing_chunk_indices, expected_missing);

    auto missing_only = manager.get_missing_chunk_indices(session->upload_id);
    EXPECT_EQ(missing_only, expected_missing);
}

TEST(UploadSessionManagerTest, CancelActiveSession) {
    UploadSessionManager manager(nullptr, nullptr, nullptr);

    v1::CreateFileUploadRequest req;
    req.set_file_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e");
    req.set_expected_chunk_count(3);

    auto session = manager.create_session(req);
    ASSERT_TRUE(session.has_value());

    bool cancelled = manager.cancel_session(session->upload_id, "User requested cancel");
    EXPECT_TRUE(cancelled);

    auto progress = manager.get_transfer_progress(session->upload_id);
    EXPECT_EQ(progress.status, TransferStatus::Cancelled);

    auto retrieved = manager.get_session(session->upload_id);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->status, v1::TRANSFER_STATUS_CANCELLED);
}

TEST(UploadSessionManagerTest, NonExistentSessionThrowsOrReturnsFalse) {
    UploadSessionManager manager(nullptr, nullptr, nullptr);
    std::string fake_id = "018f6e80-0000-7000-8000-000000000000";

    EXPECT_FALSE(manager.get_session(fake_id).has_value());
    EXPECT_FALSE(manager.cancel_session(fake_id, "test"));
    EXPECT_THROW(manager.get_transfer_progress(fake_id), TransferNotFoundException);
    EXPECT_THROW(manager.reconstruct_session_from_storage(fake_id), TransferNotFoundException);
}

TEST(UploadSessionManagerTest, ConcurrentChunkRecordingThreadSafety) {
    UploadSessionManager manager(nullptr, nullptr, nullptr);

    v1::CreateFileUploadRequest req;
    req.set_file_id("018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e");
    req.set_expected_chunk_count(100);

    auto session = manager.create_session(req);
    ASSERT_TRUE(session.has_value());

    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < 50; ++i) {
        threads.emplace_back(
            [&manager, upload_id = session->upload_id, i]() { manager.record_chunk_upload(upload_id, i, "hash"); });
    }

    for (auto& t : threads) {
        t.join();
    }

    auto progress = manager.get_transfer_progress(session->upload_id);
    EXPECT_EQ(progress.accepted_chunks, 50);
}

} // namespace
} // namespace securecloud::files::service
