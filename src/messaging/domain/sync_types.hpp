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

    [[nodiscard]] bool is_valid() const noexcept { return !device_id.empty() && !conversation_id.is_nil(); }

    [[nodiscard]] constexpr bool can_advance_to(MessageSequence new_seq) const noexcept {
        return new_seq >= last_synced_sequence;
    }

    void advance_to(MessageSequence new_seq,
                    std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) {
        if (!can_advance_to(new_seq)) {
            throw std::invalid_argument("Cannot regress synchronization cursor sequence");
        }
        last_synced_sequence = new_seq;
        last_sync_at = now;
        ++sync_version;
    }

    [[nodiscard]] static DeviceSyncCursor
    create_initial(const DeviceId& dev_id, const ConversationId& conv_id,
                   std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) {
        return DeviceSyncCursor{.device_id = dev_id,
                                .conversation_id = conv_id,
                                .last_synced_sequence = 0,
                                .last_sync_at = now,
                                .sync_version = 1};
    }

    auto operator<=>(const DeviceSyncCursor& other) const noexcept = default;
    bool operator==(const DeviceSyncCursor& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
