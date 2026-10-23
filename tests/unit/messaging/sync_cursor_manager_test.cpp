#include "messaging/domain/message_bucket.hpp"
#include "messaging/service/sync_cursor_manager.hpp"

#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::service::test {
namespace {

using domain::ConversationId;
using domain::DeviceId;
using domain::DeviceSyncCursor;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;

/// In-memory mock implementing ISyncCursorRepository
class MockSyncCursorRepo : public repository::ISyncCursorRepository {
  public:
    std::optional<DeviceSyncCursor> get_sync_cursor(const DeviceId& device_id,
                                                    const ConversationId& conversation_id) override {
        auto key = std::make_pair(device_id.str(), conversation_id.to_string());
        auto it = store_.find(key);
        if (it != store_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::vector<DeviceSyncCursor> list_sync_cursors_by_device(const DeviceId& device_id) override {
        std::vector<DeviceSyncCursor> results;
        for (const auto& [key, cursor] : store_) {
            if (key.first == device_id.str()) {
                results.push_back(cursor);
            }
        }
        return results;
    }

    void upsert_sync_cursor(const DeviceSyncCursor& cursor) override {
        if (fail_on_upsert_) {
            throw std::runtime_error("Simulated disk I/O error");
        }
        auto key = std::make_pair(cursor.device_id.str(), cursor.conversation_id.to_string());
        store_[key] = cursor;
    }

    void set_fail_on_upsert(bool fail) { fail_on_upsert_ = fail; }

  private:
    std::map<std::pair<std::string, std::string>, DeviceSyncCursor> store_;
    bool fail_on_upsert_{false};
};

/// In-memory mock implementing IMessageRepository for ceiling queries
class MockMessageRepo : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override { (void)msg; }

    std::optional<MessageEntity> find_by_id(const ConversationId& conv, const MessageBucket& bucket,
                                            const MessageId& id) override {
        (void)conv;
        (void)bucket;
        (void)id;
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId& conv, const MessageBucket& bucket,
                                                               uint64_t from, uint64_t to, size_t limit) override {
        (void)conv;
        (void)bucket;
        (void)from;
        (void)to;
        (void)limit;
        return {};
    }

    uint64_t get_last_sequence(const ConversationId& conversation_id, const MessageBucket& message_bucket) override {
        auto key = std::make_pair(conversation_id.to_string(), message_bucket.value());
        auto it = ceilings_.find(key);
        if (it != ceilings_.end()) {
            return it->second;
        }
        return 0;
    }

    void set_last_sequence(const ConversationId& conv, const MessageBucket& bucket, uint64_t seq) {
        ceilings_[std::make_pair(conv.to_string(), bucket.value())] = seq;
    }

  private:
    std::map<std::pair<std::string, std::string>, uint64_t> ceilings_;
};

/// In-memory mock implementing ISequenceAllocator
class MockSequenceAlloc : public ISequenceAllocator {
  public:
    uint64_t allocate_sequence(const ConversationId& conv, const MessageBucket& bucket) override {
        auto key = std::make_pair(conv.to_string(), bucket.value());
        return ++counters_[key];
    }

    uint64_t peek_sequence(const ConversationId& conv, const MessageBucket& bucket) override {
        auto key = std::make_pair(conv.to_string(), bucket.value());
        auto it = counters_.find(key);
        return it != counters_.end() ? it->second : 0;
    }

    void set_peek_sequence(const ConversationId& conv, const MessageBucket& bucket, uint64_t seq) {
        counters_[std::make_pair(conv.to_string(), bucket.value())] = seq;
    }

  private:
    std::map<std::pair<std::string, std::string>, uint64_t> counters_;
};

class SyncCursorManagerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        cursor_repo_ = std::make_shared<MockSyncCursorRepo>();
        message_repo_ = std::make_shared<MockMessageRepo>();
        seq_allocator_ = std::make_shared<MockSequenceAlloc>();
        manager_ = std::make_unique<SyncCursorManager>(cursor_repo_, message_repo_, seq_allocator_);

        dev_id_ = DeviceId("dev-phone-42");
        conv_id_ = ConversationId::generate_v7();
        current_bucket_ = MessageBucket::from_time_point(std::chrono::system_clock::now());
    }

    std::shared_ptr<MockSyncCursorRepo> cursor_repo_;
    std::shared_ptr<MockMessageRepo> message_repo_;
    std::shared_ptr<MockSequenceAlloc> seq_allocator_;
    std::unique_ptr<SyncCursorManager> manager_;

    DeviceId dev_id_;
    ConversationId conv_id_;
    MessageBucket current_bucket_;
};

TEST_F(SyncCursorManagerTest, ConstructorRejectsNullCursorRepository) {
    EXPECT_THROW(SyncCursorManager(nullptr, message_repo_), std::invalid_argument);
}

TEST_F(SyncCursorManagerTest, GetCursorReturnsDefaultInitialWhenNotFound) {
    auto cursor = manager_->get_cursor(dev_id_, conv_id_);

    EXPECT_TRUE(cursor.is_valid());
    EXPECT_EQ(cursor.device_id, dev_id_);
    EXPECT_EQ(cursor.conversation_id, conv_id_);
    EXPECT_EQ(cursor.last_synced_sequence, 0U);
    EXPECT_EQ(cursor.sync_version, 1);
}

TEST_F(SyncCursorManagerTest, GetCursorReturnsStoredCursorWhenPresent) {
    DeviceSyncCursor stored;
    stored.device_id = dev_id_;
    stored.conversation_id = conv_id_;
    stored.last_synced_sequence = 120;
    stored.sync_version = 4;
    stored.last_sync_at = std::chrono::system_clock::now();
    cursor_repo_->upsert_sync_cursor(stored);

    auto cursor = manager_->get_cursor(dev_id_, conv_id_);
    EXPECT_EQ(cursor.last_synced_sequence, 120U);
    EXPECT_EQ(cursor.sync_version, 4);
}

TEST_F(SyncCursorManagerTest, GetCursorRejectsInvalidInputsWithInitial) {
    auto c1 = manager_->get_cursor(DeviceId(""), conv_id_);
    EXPECT_FALSE(c1.is_valid());

    auto c2 = manager_->get_cursor(dev_id_, ConversationId{});
    EXPECT_FALSE(c2.is_valid());
}

TEST_F(SyncCursorManagerTest, ListCursorsReturnsAllDeviceConversations) {
    auto conv_2 = ConversationId::generate_v7();

    auto c1 = DeviceSyncCursor::create_initial(dev_id_, conv_id_);
    c1.last_synced_sequence = 50;
    cursor_repo_->upsert_sync_cursor(c1);

    auto c2 = DeviceSyncCursor::create_initial(dev_id_, conv_2);
    c2.last_synced_sequence = 75;
    cursor_repo_->upsert_sync_cursor(c2);

    auto other_dev = DeviceId("dev-laptop-99");
    auto c3 = DeviceSyncCursor::create_initial(other_dev, conv_id_);
    cursor_repo_->upsert_sync_cursor(c3);

    auto list = manager_->list_cursors(dev_id_);
    ASSERT_EQ(list.size(), 2U);
    EXPECT_EQ(list[0].device_id, dev_id_);
    EXPECT_EQ(list[1].device_id, dev_id_);

    EXPECT_TRUE(manager_->list_cursors(DeviceId("")).empty());
}

TEST_F(SyncCursorManagerTest, MonotonicProgressionSucceedsAndIncrementsVersion) {
    // Set sequence ceiling in conversation
    seq_allocator_->set_peek_sequence(conv_id_, current_bucket_, 500);

    // Initial sync to 100
    auto outcome1 = manager_->update_cursor(dev_id_, conv_id_, 100);
    ASSERT_TRUE(outcome1.is_success());
    EXPECT_EQ(outcome1.status, SyncCursorUpdateStatus::Success);
    EXPECT_EQ(outcome1.cursor.last_synced_sequence, 100U);
    EXPECT_EQ(outcome1.cursor.sync_version, 2);

    // Verify stored in repository
    auto stored = cursor_repo_->get_sync_cursor(dev_id_, conv_id_);
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->last_synced_sequence, 100U);
    EXPECT_EQ(stored->sync_version, 2);

    // Advance to 250
    auto outcome2 = manager_->update_cursor(dev_id_, conv_id_, 250);
    ASSERT_TRUE(outcome2.is_success());
    EXPECT_EQ(outcome2.cursor.last_synced_sequence, 250U);
    EXPECT_EQ(outcome2.cursor.sync_version, 3);
}

TEST_F(SyncCursorManagerTest, IdempotentReacknowledgmentAllowed) {
    seq_allocator_->set_peek_sequence(conv_id_, current_bucket_, 200);

    // Advance to 150
    auto res1 = manager_->update_cursor(dev_id_, conv_id_, 150);
    ASSERT_TRUE(res1.is_success());
    EXPECT_EQ(res1.cursor.sync_version, 2);

    // Re-advance to 150 (idempotent re-ack after crash/retry)
    auto res2 = manager_->update_cursor(dev_id_, conv_id_, 150);
    ASSERT_TRUE(res2.is_success());
    EXPECT_EQ(res2.cursor.last_synced_sequence, 150U);
    EXPECT_EQ(res2.cursor.sync_version, 3);
}

TEST_F(SyncCursorManagerTest, RegressionRejected) {
    seq_allocator_->set_peek_sequence(conv_id_, current_bucket_, 300);

    // Set cursor to 150
    auto res1 = manager_->update_cursor(dev_id_, conv_id_, 150);
    ASSERT_TRUE(res1.is_success());

    // Try to regress to 149
    auto res2 = manager_->update_cursor(dev_id_, conv_id_, 149);
    EXPECT_FALSE(res2.is_success());
    EXPECT_EQ(res2.status, SyncCursorUpdateStatus::RegressionRejected);
    EXPECT_EQ(res2.cursor.last_synced_sequence, 150U);

    // Ensure database remained at 150
    auto stored = cursor_repo_->get_sync_cursor(dev_id_, conv_id_);
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->last_synced_sequence, 150U);
}

TEST_F(SyncCursorManagerTest, OutOfBoundsSequenceRejected) {
    // Ceiling is 100
    seq_allocator_->set_peek_sequence(conv_id_, current_bucket_, 100);

    // Attempting to advance to 101 should fail
    auto outcome = manager_->update_cursor(dev_id_, conv_id_, 101);
    EXPECT_FALSE(outcome.is_success());
    EXPECT_EQ(outcome.status, SyncCursorUpdateStatus::OutOfBoundsRejected);

    // Advancing to exact ceiling 100 should succeed
    auto ok_outcome = manager_->update_cursor(dev_id_, conv_id_, 100);
    EXPECT_TRUE(ok_outcome.is_success());
    EXPECT_EQ(ok_outcome.cursor.last_synced_sequence, 100U);
}

TEST_F(SyncCursorManagerTest, OptimisticConcurrencyVersionConflict) {
    seq_allocator_->set_peek_sequence(conv_id_, current_bucket_, 200);

    // Advance to 50: current version becomes 2
    auto res1 = manager_->update_cursor(dev_id_, conv_id_, 50);
    ASSERT_TRUE(res1.is_success());
    EXPECT_EQ(res1.cursor.sync_version, 2);

    // Next update expects version 1 (out of date / concurrent conflict)
    auto conflict = manager_->update_cursor(dev_id_, conv_id_, 60, /*expected_version=*/1);
    EXPECT_FALSE(conflict.is_success());
    EXPECT_EQ(conflict.status, SyncCursorUpdateStatus::VersionConflict);

    // Matching expected version 2 succeeds
    auto ok_res = manager_->update_cursor(dev_id_, conv_id_, 60, /*expected_version=*/2);
    EXPECT_TRUE(ok_res.is_success());
    EXPECT_EQ(ok_res.cursor.sync_version, 3);
}

TEST_F(SyncCursorManagerTest, InvalidCursorInputsRejected) {
    seq_allocator_->set_peek_sequence(conv_id_, current_bucket_, 100);

    auto r1 = manager_->update_cursor(DeviceId(""), conv_id_, 10);
    EXPECT_EQ(r1.status, SyncCursorUpdateStatus::InvalidCursor);

    auto r2 = manager_->update_cursor(dev_id_, ConversationId{}, 10);
    EXPECT_EQ(r2.status, SyncCursorUpdateStatus::InvalidCursor);
}

TEST_F(SyncCursorManagerTest, UpdateCursorViaCommandOverload) {
    seq_allocator_->set_peek_sequence(conv_id_, current_bucket_, 50);

    UpdateSyncCursorCommand cmd{
        .device_id = dev_id_, .conversation_id = conv_id_, .new_sequence = 25, .sync_version = 1};

    auto outcome = manager_->update_cursor(cmd);
    EXPECT_TRUE(outcome.is_success());
    EXPECT_EQ(outcome.cursor.last_synced_sequence, 25U);
}

TEST_F(SyncCursorManagerTest, CeilingFallsBackToMessageRepositoryAndPreviousBucket) {
    // Sequence allocator has no entry
    // Current bucket in message_repo has 0
    // Previous bucket in message_repo has 350
    auto prev_bucket = current_bucket_.previous_bucket();
    message_repo_->set_last_sequence(conv_id_, prev_bucket, 350);

    auto ceiling = manager_->get_conversation_sequence_ceiling(conv_id_);
    EXPECT_EQ(ceiling, 350U);

    auto outcome = manager_->update_cursor(dev_id_, conv_id_, 300);
    EXPECT_TRUE(outcome.is_success());
    EXPECT_EQ(outcome.cursor.last_synced_sequence, 300U);
}

TEST_F(SyncCursorManagerTest, StorageErrorHandledGracefully) {
    seq_allocator_->set_peek_sequence(conv_id_, current_bucket_, 100);
    cursor_repo_->set_fail_on_upsert(true);

    auto outcome = manager_->update_cursor(dev_id_, conv_id_, 50);
    EXPECT_FALSE(outcome.is_success());
    EXPECT_EQ(outcome.status, SyncCursorUpdateStatus::StorageError);
    EXPECT_NE(outcome.error_message.find("Simulated disk I/O error"), std::string::npos);
}

} // namespace
} // namespace securecloud::messaging::service::test
