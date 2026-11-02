#include "service/sync_cursor_manager.hpp"

#include "domain/message_bucket.hpp"

#include <chrono>
#include <stdexcept>

namespace securecloud::messaging::service {

SyncCursorManager::SyncCursorManager(std::shared_ptr<repository::ISyncCursorRepository> cursor_repo,
                                     std::shared_ptr<repository::IMessageRepository> message_repo,
                                     std::shared_ptr<ISequenceAllocator> sequence_allocator)
    : cursor_repo_(std::move(cursor_repo)), message_repo_(std::move(message_repo)),
      sequence_allocator_(std::move(sequence_allocator)) {
    if (!cursor_repo_) {
        throw std::invalid_argument("SyncCursorManager requires non-null ISyncCursorRepository");
    }
}

domain::DeviceSyncCursor SyncCursorManager::get_cursor(const domain::DeviceId& device_id,
                                                       const domain::ConversationId& conversation_id) {
    if (device_id.empty() || conversation_id.is_nil()) {
        return domain::DeviceSyncCursor::create_initial(device_id, conversation_id);
    }

    auto existing = cursor_repo_->get_sync_cursor(device_id, conversation_id);
    if (existing.has_value()) {
        return *existing;
    }

    return domain::DeviceSyncCursor::create_initial(device_id, conversation_id);
}

std::vector<domain::DeviceSyncCursor> SyncCursorManager::list_cursors(const domain::DeviceId& device_id) {
    if (device_id.empty()) {
        return {};
    }
    return cursor_repo_->list_sync_cursors_by_device(device_id);
}

domain::MessageSequence
SyncCursorManager::get_conversation_sequence_ceiling(const domain::ConversationId& conversation_id) {
    auto now = std::chrono::system_clock::now();
    auto current_bucket = domain::MessageBucket::from_time_point(now);

    uint64_t ceiling = 0;
    if (sequence_allocator_) {
        ceiling = sequence_allocator_->peek_sequence(conversation_id, current_bucket);
    }
    if (ceiling == 0 && message_repo_) {
        ceiling = message_repo_->get_last_sequence(conversation_id, current_bucket);
        if (ceiling == 0) {
            auto prev_bucket = current_bucket.previous_bucket();
            ceiling = message_repo_->get_last_sequence(conversation_id, prev_bucket);
        }
    }
    return ceiling;
}

SyncCursorUpdateOutcome SyncCursorManager::update_cursor(const domain::DeviceId& device_id,
                                                         const domain::ConversationId& conversation_id,
                                                         domain::MessageSequence new_sequence,
                                                         int32_t expected_version) {
    // 1. Validate identifiers
    if (device_id.empty()) {
        return SyncCursorUpdateOutcome{.status = SyncCursorUpdateStatus::InvalidCursor,
                                       .cursor = {},
                                       .error_message = "Device ID cannot be empty"};
    }
    if (conversation_id.is_nil()) {
        return SyncCursorUpdateOutcome{.status = SyncCursorUpdateStatus::InvalidCursor,
                                       .cursor = {},
                                       .error_message = "Conversation ID must be a valid non-nil UUID"};
    }

    // Lock-striped concurrency control per (device_id, conversation_id) (MSG-012-T02)
    const size_t stripe_idx =
        std::hash<std::string>{}(device_id.str() + ":" + conversation_id.to_string()) % kNumStripes;
    std::lock_guard<std::mutex> stripe_lock(cursor_stripes_[stripe_idx]);

    // 2. Stream ceiling boundary check (cannot advance beyond highest allocated sequence)
    auto ceiling = get_conversation_sequence_ceiling(conversation_id);
    if (new_sequence > ceiling) {
        return SyncCursorUpdateOutcome{.status = SyncCursorUpdateStatus::OutOfBoundsRejected,
                                       .cursor = {},
                                       .error_message = "Requested sequence " + std::to_string(new_sequence) +
                                                        " exceeds conversation sequence ceiling " +
                                                        std::to_string(ceiling)};
    }

    // 3. Fetch active cursor (or default initial)
    auto cursor = get_cursor(device_id, conversation_id);

    // 4. Monotonic progression guard (regression prevention)
    if (!cursor.can_advance_to(new_sequence)) {
        return SyncCursorUpdateOutcome{.status = SyncCursorUpdateStatus::RegressionRejected,
                                       .cursor = cursor,
                                       .error_message = "Requested sequence " + std::to_string(new_sequence) +
                                                        " regresses from active cursor sequence " +
                                                        std::to_string(cursor.last_synced_sequence)};
    }

    // 5. Optimistic concurrency check (if client specified a non-zero expected version)
    if (expected_version > 0 && cursor.sync_version != expected_version) {
        return SyncCursorUpdateOutcome{.status = SyncCursorUpdateStatus::VersionConflict,
                                       .cursor = cursor,
                                       .error_message = "Optimistic concurrency conflict: expected sync_version " +
                                                        std::to_string(expected_version) + " but active version is " +
                                                        std::to_string(cursor.sync_version)};
    }

    // 6. Advance cursor state and persist atomically
    try {
        cursor.advance_to(new_sequence);
        cursor_repo_->upsert_sync_cursor(cursor);
    } catch (const std::exception& ex) {
        return SyncCursorUpdateOutcome{.status = SyncCursorUpdateStatus::StorageError,
                                       .cursor = cursor,
                                       .error_message =
                                           std::string("Storage error persisting sync cursor: ") + ex.what()};
    }

    return SyncCursorUpdateOutcome{.status = SyncCursorUpdateStatus::Success, .cursor = cursor, .error_message = ""};
}

SyncCursorUpdateOutcome SyncCursorManager::update_cursor(const UpdateSyncCursorCommand& cmd) {
    return update_cursor(cmd.device_id, cmd.conversation_id, cmd.new_sequence, cmd.sync_version);
}

} // namespace securecloud::messaging::service
