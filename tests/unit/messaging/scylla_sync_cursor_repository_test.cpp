#include "messaging/db/mock_scylla_session.hpp"
#include "messaging/domain/sync_types.hpp"
#include "messaging/repository/scylla_sync_cursor_repository.hpp"

#include <gtest/gtest.h>
#include <memory>

namespace securecloud::messaging::repository::test {
namespace {

using domain::ConversationId;
using domain::DeviceId;
using domain::DeviceSyncCursor;

TEST(ScyllaSyncCursorRepositoryTest, RejectsNullSession) {
    EXPECT_THROW(ScyllaSyncCursorRepository(nullptr), std::invalid_argument);
}

TEST(ScyllaSyncCursorRepositoryTest, UpsertAndGetSyncCursor) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaSyncCursorRepository repo(mock);

    auto dev_id = DeviceId("dev-laptop-789");
    auto conv_id = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    DeviceSyncCursor cursor;
    cursor.device_id = dev_id;
    cursor.conversation_id = conv_id;
    cursor.last_synced_sequence = 450;
    cursor.last_sync_at = now;
    cursor.sync_version = 3;

    // 1. Upsert cursor
    repo.upsert_sync_cursor(cursor);
    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "sync_repo_upsert_cursor");

    // 2. Configure mock response for get_sync_cursor
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    db::ScyllaRow row({"device_id", "conversation_id", "last_synced_sequence", "last_sync_at", "sync_version"},
                      {db::ScyllaValue(dev_id.str()), db::ScyllaValue(conv_id.to_string()),
                       db::ScyllaValue(static_cast<int64_t>(450)), db::ScyllaValue(now_ms), db::ScyllaValue(3)});

    mock->set_prepared_result(db::PreparedStatementId("sync_repo_get_cursor"), db::ScyllaQueryResult({row}));

    auto found = repo.get_sync_cursor(dev_id, conv_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->device_id, dev_id);
    EXPECT_EQ(found->conversation_id, conv_id);
    EXPECT_EQ(found->last_synced_sequence, 450U);
    EXPECT_EQ(found->sync_version, 3);

    // 3. Not found returns nullopt
    mock->set_prepared_result(db::PreparedStatementId("sync_repo_get_cursor"), db::ScyllaQueryResult{});
    auto not_found = repo.get_sync_cursor(dev_id, ConversationId::generate_v7());
    EXPECT_FALSE(not_found.has_value());
}

TEST(ScyllaSyncCursorRepositoryTest, ListSyncCursorsByDevice) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaSyncCursorRepository repo(mock);

    auto dev_id = DeviceId("dev-laptop-789");
    auto conv_1 = ConversationId::generate_v7();
    auto conv_2 = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    db::ScyllaRow row1({"device_id", "conversation_id", "last_synced_sequence", "last_sync_at", "sync_version"},
                       {db::ScyllaValue(dev_id.str()), db::ScyllaValue(conv_1.to_string()),
                        db::ScyllaValue(static_cast<int64_t>(100)), db::ScyllaValue(now_ms), db::ScyllaValue(1)});
    db::ScyllaRow row2({"device_id", "conversation_id", "last_synced_sequence", "last_sync_at", "sync_version"},
                       {db::ScyllaValue(dev_id.str()), db::ScyllaValue(conv_2.to_string()),
                        db::ScyllaValue(static_cast<int64_t>(200)), db::ScyllaValue(now_ms), db::ScyllaValue(2)});

    mock->set_prepared_result(db::PreparedStatementId("sync_repo_list_cursors_by_device"),
                              db::ScyllaQueryResult({row1, row2}));

    auto list = repo.list_sync_cursors_by_device(dev_id);
    ASSERT_EQ(list.size(), 2U);
    EXPECT_EQ(list[0].device_id, dev_id);
    EXPECT_EQ(list[0].conversation_id, conv_1);
    EXPECT_EQ(list[0].last_synced_sequence, 100U);
    EXPECT_EQ(list[1].conversation_id, conv_2);
    EXPECT_EQ(list[1].last_synced_sequence, 200U);
}

} // namespace
} // namespace securecloud::messaging::repository::test
