#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_types.hpp"

#include <chrono>
#include <compare>
#include <cstdint>

namespace securecloud::messaging::domain {

/// Resumable incremental synchronization cursor for a client device in a conversation.
/// Matches schema of securecloud_messaging.sync_state_by_device:
/// - Partition Key: ((device_id))
/// - Clustering Key: conversation_id ASC
struct DeviceSyncCursor {
    DeviceId device_id;
    ConversationId conversation_id;
    MessageSequence last_synced_sequence{0};
    std::chrono::system_clock::time_point last_sync_at;
    int32_t sync_version{1};

    auto operator<=>(const DeviceSyncCursor& other) const noexcept = default;
    bool operator==(const DeviceSyncCursor& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
