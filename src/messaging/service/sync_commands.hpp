#pragma once

#include "domain/conversation_types.hpp"
#include "domain/envelope_types.hpp"
#include "domain/message_entity.hpp"
#include "domain/message_types.hpp"
#include "domain/sync_types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace securecloud::messaging::service {

/// Synchronization batch size boundaries (ADR-010, Section 5.39).
inline constexpr uint32_t k_min_sync_batch_size = 1;
inline constexpr uint32_t k_default_sync_batch_size = 50;
inline constexpr uint32_t k_max_sync_batch_size = 500;

/// Clamps requested sync batch size to configured boundaries [1, 500].
[[nodiscard]] inline constexpr uint32_t clamp_sync_batch_size(uint32_t requested) noexcept {
    if (requested < k_min_sync_batch_size) {
        return k_default_sync_batch_size;
    }
    if (requested > k_max_sync_batch_size) {
        return k_max_sync_batch_size;
    }
    return requested;
}

/// Status outcome for a message synchronization request.
enum class SyncMessagesStatus {
    Success = 0,
    NotAuthorized,
    ConversationNotFound,
    CursorOutOfBounds,
    InvalidArguments,
    StorageError
};

[[nodiscard]] inline std::string to_string(SyncMessagesStatus status) {
    switch (status) {
    case SyncMessagesStatus::Success:
        return "SUCCESS";
    case SyncMessagesStatus::NotAuthorized:
        return "NOT_AUTHORIZED";
    case SyncMessagesStatus::ConversationNotFound:
        return "CONVERSATION_NOT_FOUND";
    case SyncMessagesStatus::CursorOutOfBounds:
        return "CURSOR_OUT_OF_BOUNDS";
    case SyncMessagesStatus::InvalidArguments:
        return "INVALID_ARGUMENTS";
    case SyncMessagesStatus::StorageError:
        return "STORAGE_ERROR";
    }
    return "UNKNOWN";
}

/// Command requesting message synchronization for a device.
/// Optionally scoped to a specific conversation.
struct SyncDeviceMessagesCommand {
    domain::DeviceId device_id;
    std::optional<domain::ConversationId> conversation_id{std::nullopt};
    domain::MessageSequence since_sequence{0};
    uint32_t max_messages{k_default_sync_batch_size};
};

/// Result of message synchronization for a device.
struct SyncMessagesResult {
    SyncMessagesStatus status{SyncMessagesStatus::Success};
    domain::DeviceId device_id;
    std::optional<domain::ConversationId> conversation_id{std::nullopt};
    std::vector<domain::MessageEntity> messages{};
    domain::DeviceSyncCursor cursor{};
    bool has_more{false};
    domain::MessageSequence next_sequence{0};
    domain::MessageSequence latest_sequence{0};
    std::string error_message{};

    [[nodiscard]] bool is_success() const noexcept {
        return status == SyncMessagesStatus::Success;
    }

    [[nodiscard]] static SyncMessagesResult failure(SyncMessagesStatus st,
                                                    domain::DeviceId dev_id,
                                                    std::optional<domain::ConversationId> conv_id,
                                                    std::string msg) {
        return SyncMessagesResult{
            .status = st,
            .device_id = std::move(dev_id),
            .conversation_id = std::move(conv_id),
            .messages = {},
            .cursor = {},
            .has_more = false,
            .next_sequence = 0,
            .latest_sequence = 0,
            .error_message = std::move(msg)
        };
    }
};

/// Command to retrieve the sync cursor for a device in a conversation.
struct GetSyncCursorCommand {
    domain::DeviceId device_id;
    domain::ConversationId conversation_id;
};

/// Command to update the sync cursor after the client has durably persisted the batch.
struct UpdateSyncCursorCommand {
    domain::DeviceId device_id;
    domain::ConversationId conversation_id;
    domain::MessageSequence new_sequence{0};
    int32_t sync_version{1};
};

/// Result of updating a sync cursor.
struct UpdateSyncCursorResult {
    domain::DeviceSyncCursor cursor{};
    bool success{false};
    std::string error_message{};

    [[nodiscard]] static UpdateSyncCursorResult ok(domain::DeviceSyncCursor c) noexcept {
        return UpdateSyncCursorResult{
            .cursor = std::move(c),
            .success = true,
            .error_message = ""
        };
    }

    [[nodiscard]] static UpdateSyncCursorResult failure(std::string message) {
        return UpdateSyncCursorResult{
            .cursor = {},
            .success = false,
            .error_message = std::move(message)
        };
    }
};

} // namespace securecloud::messaging::service
