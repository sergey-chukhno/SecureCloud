#pragma once

#include "messaging/db/scylla_session_interface.hpp"
#include "messaging/repository/sync_cursor_repository_interface.hpp"

#include <memory>
#include <mutex>

namespace securecloud::messaging::repository {

/// ScyllaDB persistence adapter for Device Synchronization Cursors.
/// Conforms to:
/// - securecloud_messaging.sync_state_by_device
/// - Partition Key: ((device_id))
/// - Clustering Key: conversation_id ASC
class ScyllaSyncCursorRepository : public ISyncCursorRepository {
  public:
    explicit ScyllaSyncCursorRepository(std::shared_ptr<db::IScyllaSession> session);

    [[nodiscard]] std::optional<domain::DeviceSyncCursor>
    get_sync_cursor(const domain::DeviceId& device_id, const domain::ConversationId& conversation_id) override;

    [[nodiscard]] std::vector<domain::DeviceSyncCursor>
    list_sync_cursors_by_device(const domain::DeviceId& device_id) override;

    void upsert_sync_cursor(const domain::DeviceSyncCursor& cursor) override;

  private:
    void init_prepared_statements();

    std::shared_ptr<db::IScyllaSession> session_;
    mutable std::mutex mutex_;

    db::PreparedStatementId prep_get_cursor_;
    db::PreparedStatementId prep_list_cursors_by_device_;
    db::PreparedStatementId prep_upsert_cursor_;
};

} // namespace securecloud::messaging::repository
