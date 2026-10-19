#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_types.hpp"
#include "domain/sync_types.hpp"

#include <optional>

namespace securecloud::messaging::repository {

/// Abstract repository contract for Per-Device Synchronization Cursors.
/// Conforms to:
/// - securecloud_messaging.sync_state_by_device
/// - Partition Key: ((device_id))
/// - Clustering Key: conversation_id ASC
class ISyncCursorRepository {
  public:
    virtual ~ISyncCursorRepository() = default;

    /// Retrieves the synchronization cursor for a device in a conversation.
    [[nodiscard]] virtual std::optional<domain::DeviceSyncCursor>
    get_sync_cursor(const domain::DeviceId& device_id, const domain::ConversationId& conversation_id) = 0;

    /// Inserts or updates the synchronization cursor for a device.
    virtual void upsert_sync_cursor(const domain::DeviceSyncCursor& cursor) = 0;
};

} // namespace securecloud::messaging::repository
