#include "messaging/repository/scylla_sync_cursor_repository.hpp"

#include <chrono>
#include <stdexcept>

namespace securecloud::messaging::repository {
namespace {

inline int64_t to_millis(std::chrono::system_clock::time_point tp) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

inline std::chrono::system_clock::time_point from_millis(int64_t ms) noexcept {
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
}

domain::DeviceSyncCursor row_to_sync_cursor(const db::ScyllaRow& row) {
    domain::DeviceSyncCursor cursor;
    cursor.device_id = domain::DeviceId(row.get_string("device_id"));

    auto opt_conv_id = domain::ConversationId::from_string(row.get_string("conversation_id"));
    if (opt_conv_id) {
        cursor.conversation_id = *opt_conv_id;
    }

    cursor.last_synced_sequence = static_cast<uint64_t>(row.get_int64("last_synced_sequence"));
    cursor.last_sync_at = from_millis(row.get_timestamp("last_sync_at"));
    cursor.sync_version = row.get_int("sync_version");

    return cursor;
}

} // namespace

ScyllaSyncCursorRepository::ScyllaSyncCursorRepository(std::shared_ptr<db::IScyllaSession> session)
    : session_(std::move(session)) {
    if (!session_) {
        throw std::invalid_argument("ScyllaSyncCursorRepository requires non-null IScyllaSession");
    }
    init_prepared_statements();
}

void ScyllaSyncCursorRepository::init_prepared_statements() {
    prep_get_cursor_ = session_->prepare(
        "sync_repo_get_cursor", "SELECT device_id, conversation_id, last_synced_sequence, last_sync_at, sync_version "
                                "FROM securecloud_messaging.sync_state_by_device "
                                "WHERE device_id = ? AND conversation_id = ?;");

    prep_list_cursors_by_device_ =
        session_->prepare("sync_repo_list_cursors_by_device",
                          "SELECT device_id, conversation_id, last_synced_sequence, last_sync_at, sync_version "
                          "FROM securecloud_messaging.sync_state_by_device "
                          "WHERE device_id = ?;");

    prep_upsert_cursor_ = session_->prepare(
        "sync_repo_upsert_cursor", "INSERT INTO securecloud_messaging.sync_state_by_device "
                                   "(device_id, conversation_id, last_synced_sequence, last_sync_at, sync_version) "
                                   "VALUES (?, ?, ?, ?, ?);");
}

std::optional<domain::DeviceSyncCursor>
ScyllaSyncCursorRepository::get_sync_cursor(const domain::DeviceId& device_id,
                                            const domain::ConversationId& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(device_id.str());
    params.add_string(conversation_id.to_string());

    auto result = session_->execute_prepared(prep_get_cursor_, params);
    if (result.empty()) {
        return std::nullopt;
    }

    return row_to_sync_cursor(result.front());
}

std::vector<domain::DeviceSyncCursor>
ScyllaSyncCursorRepository::list_sync_cursors_by_device(const domain::DeviceId& device_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(device_id.str());

    auto result = session_->execute_prepared(prep_list_cursors_by_device_, params);
    std::vector<domain::DeviceSyncCursor> cursors;
    cursors.reserve(result.size());
    for (const auto& row : result) {
        cursors.push_back(row_to_sync_cursor(row));
    }
    return cursors;
}

void ScyllaSyncCursorRepository::upsert_sync_cursor(const domain::DeviceSyncCursor& cursor) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(cursor.device_id.str());
    params.add_string(cursor.conversation_id.to_string());
    params.add_int64(static_cast<int64_t>(cursor.last_synced_sequence));
    params.add_timestamp(to_millis(cursor.last_sync_at));
    params.add_int(cursor.sync_version);

    session_->execute_prepared(prep_upsert_cursor_, params);
}

} // namespace securecloud::messaging::repository
