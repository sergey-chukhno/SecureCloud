#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_types.hpp"
#include "domain/sync_types.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/repository/sync_cursor_repository_interface.hpp"
#include "service/sequence_allocator_interface.hpp"
#include "service/sync_commands.hpp"

#include <array>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace securecloud::messaging::service {

/// Outcome status codes for synchronization cursor updates.
enum class SyncCursorUpdateStatus {
    Success = 0,
    RegressionRejected,
    OutOfBoundsRejected,
    VersionConflict,
    InvalidCursor,
    StorageError
};

[[nodiscard]] inline std::string to_string(SyncCursorUpdateStatus status) {
    switch (status) {
    case SyncCursorUpdateStatus::Success:
        return "SUCCESS";
    case SyncCursorUpdateStatus::RegressionRejected:
        return "REGRESSION_REJECTED";
    case SyncCursorUpdateStatus::OutOfBoundsRejected:
        return "OUT_OF_BOUNDS_REJECTED";
    case SyncCursorUpdateStatus::VersionConflict:
        return "VERSION_CONFLICT";
    case SyncCursorUpdateStatus::InvalidCursor:
        return "INVALID_CURSOR";
    case SyncCursorUpdateStatus::StorageError:
        return "STORAGE_ERROR";
    }
    return "UNKNOWN";
}

/// Structured outcome resulting from a cursor update attempt.
struct SyncCursorUpdateOutcome {
    SyncCursorUpdateStatus status{SyncCursorUpdateStatus::Success};
    domain::DeviceSyncCursor cursor{};
    std::string error_message{};

    [[nodiscard]] bool is_success() const noexcept { return status == SyncCursorUpdateStatus::Success; }
};

/**
 * @brief Authoritative engine governing client device synchronization cursors.
 *
 * Implements strict monotonic checkpoint progression, stream ceiling bounds validation,
 * optimistic concurrency versioning, and default initialization for online synchronization (MSG-009).
 */
class SyncCursorManager {
  public:
    /**
     * @brief Constructs SyncCursorManager with required repository dependencies.
     * @throws std::invalid_argument if cursor_repo is nullptr.
     */
    SyncCursorManager(std::shared_ptr<repository::ISyncCursorRepository> cursor_repo,
                      std::shared_ptr<repository::IMessageRepository> message_repo = nullptr,
                      std::shared_ptr<ISequenceAllocator> sequence_allocator = nullptr);

    /// Retrieves current cursor for a device in a conversation.
    /// Returns default initial cursor (sequence = 0, version = 1) if not found in storage.
    [[nodiscard]] domain::DeviceSyncCursor get_cursor(const domain::DeviceId& device_id,
                                                      const domain::ConversationId& conversation_id);

    /// Lists all synchronization cursors across all conversations for a given device.
    [[nodiscard]] std::vector<domain::DeviceSyncCursor> list_cursors(const domain::DeviceId& device_id);

    /// Updates cursor enforcing monotonicity, sequence ceiling, and optimistic concurrency.
    [[nodiscard]] SyncCursorUpdateOutcome update_cursor(const domain::DeviceId& device_id,
                                                        const domain::ConversationId& conversation_id,
                                                        domain::MessageSequence new_sequence,
                                                        int32_t expected_version = 0);

    /// Overload processing an UpdateSyncCursorCommand.
    [[nodiscard]] SyncCursorUpdateOutcome update_cursor(const UpdateSyncCursorCommand& cmd);

    /// Queries the highest allocated message sequence (stream ceiling) in a conversation.
    [[nodiscard]] domain::MessageSequence
    get_conversation_sequence_ceiling(const domain::ConversationId& conversation_id);

  private:
    std::shared_ptr<repository::ISyncCursorRepository> cursor_repo_;
    std::shared_ptr<repository::IMessageRepository> message_repo_;
    std::shared_ptr<ISequenceAllocator> sequence_allocator_;

    static constexpr size_t kNumStripes = 64;
    mutable std::array<std::mutex, kNumStripes> cursor_stripes_;
};

} // namespace securecloud::messaging::service
