#include "service/message_sync_service.hpp"

#include "domain/message_bucket.hpp"

#include <chrono>
#include <stdexcept>

namespace securecloud::messaging::service {

MessageSyncService::MessageSyncService(std::shared_ptr<repository::IMessageRepository> message_repo,
                                       std::shared_ptr<SyncCursorManager> cursor_manager,
                                       std::shared_ptr<ConversationAuthorizationService> auth_service,
                                       std::shared_ptr<repository::IDeliveryStateRepository> delivery_state_repo)
    : message_repo_(std::move(message_repo)), cursor_manager_(std::move(cursor_manager)),
      auth_service_(std::move(auth_service)), delivery_state_repo_(std::move(delivery_state_repo)) {
    if (!message_repo_) {
        throw std::invalid_argument("MessageSyncService requires non-null IMessageRepository");
    }
    if (!cursor_manager_) {
        throw std::invalid_argument("MessageSyncService requires non-null SyncCursorManager");
    }
}

SyncMessagesResult MessageSyncService::sync_messages(const domain::UserId& caller_id,
                                                     const SyncDeviceMessagesCommand& cmd) {
    // 1. Validate arguments
    if (cmd.device_id.empty()) {
        return SyncMessagesResult::failure(SyncMessagesStatus::InvalidArguments, cmd.device_id, cmd.conversation_id,
                                           "Device ID cannot be empty");
    }
    if (!cmd.conversation_id.has_value() || cmd.conversation_id->is_nil()) {
        return SyncMessagesResult::failure(SyncMessagesStatus::InvalidArguments, cmd.device_id, cmd.conversation_id,
                                           "Conversation ID must be specified and non-nil");
    }

    const auto& conv_id = *cmd.conversation_id;

    // 2. Authorize caller
    if (auth_service_) {
        auto auth_res = auth_service_->can_view_conversation(caller_id, conv_id);
        if (!auth_res.allowed) {
            if (auth_res.error_code == v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND) {
                return SyncMessagesResult::failure(
                    SyncMessagesStatus::ConversationNotFound, cmd.device_id, cmd.conversation_id,
                    auth_res.reason.empty() ? "Conversation not found" : auth_res.reason);
            }
            return SyncMessagesResult::failure(
                SyncMessagesStatus::NotAuthorized, cmd.device_id, cmd.conversation_id,
                auth_res.reason.empty() ? "Caller is not an active participant in the conversation" : auth_res.reason);
        }
    }

    // 3. Clamp batch size [1, 500]
    uint32_t batch_size = clamp_sync_batch_size(cmd.max_messages);

    // 4. Retrieve cursor and sequence ceiling
    auto cursor = cursor_manager_->get_cursor(cmd.device_id, conv_id);
    uint64_t effective_since = (cmd.since_sequence > 0) ? cmd.since_sequence : cursor.last_synced_sequence;
    uint64_t ceiling = cursor_manager_->get_conversation_sequence_ceiling(conv_id);

    if (effective_since > ceiling && ceiling > 0) {
        return SyncMessagesResult::failure(SyncMessagesStatus::CursorOutOfBounds, cmd.device_id, cmd.conversation_id,
                                           "since_sequence " + std::to_string(effective_since) +
                                               " exceeds conversation ceiling " + std::to_string(ceiling));
    }

    // If already at ceiling or conversation has 0 messages, return empty result
    if (effective_since >= ceiling || ceiling == 0) {
        return SyncMessagesResult{.status = SyncMessagesStatus::Success,
                                  .device_id = cmd.device_id,
                                  .conversation_id = cmd.conversation_id,
                                  .messages = {},
                                  .cursor = cursor,
                                  .has_more = false,
                                  .next_sequence = effective_since + 1,
                                  .latest_sequence = ceiling,
                                  .error_message = ""};
    }

    // 5. Query message repository across monthly buckets
    uint64_t from_seq = effective_since + 1;
    uint64_t to_seq = effective_since + batch_size + 1; // Request 1 extra to determine has_more

    auto now = std::chrono::system_clock::now();
    auto current_bucket = domain::MessageBucket::from_time_point(now);
    auto prev_bucket = current_bucket.previous_bucket();

    std::vector<domain::MessageEntity> fetched;

    // Check previous bucket first
    auto prev_msgs =
        message_repo_->list_messages_by_sequence_range(conv_id, prev_bucket, from_seq, to_seq, batch_size + 1);
    fetched.insert(fetched.end(), prev_msgs.begin(), prev_msgs.end());

    // If previous bucket didn't saturate the batch request, check current bucket
    if (fetched.size() <= batch_size) {
        size_t needed = (batch_size + 1) - fetched.size();
        uint64_t next_from = fetched.empty() ? from_seq : fetched.back().message_sequence + 1;
        auto curr_msgs =
            message_repo_->list_messages_by_sequence_range(conv_id, current_bucket, next_from, to_seq, needed);
        fetched.insert(fetched.end(), curr_msgs.begin(), curr_msgs.end());
    }

    // 6. Evaluate pagination boundaries
    bool has_more = false;
    if (fetched.size() > batch_size) {
        has_more = true;
        fetched.pop_back();
    } else if (!fetched.empty()) {
        has_more = (fetched.back().message_sequence < ceiling);
    }

    uint64_t next_seq = fetched.empty() ? (effective_since + 1) : (fetched.back().message_sequence + 1);

    return SyncMessagesResult{.status = SyncMessagesStatus::Success,
                              .device_id = cmd.device_id,
                              .conversation_id = cmd.conversation_id,
                              .messages = std::move(fetched),
                              .cursor = cursor,
                              .has_more = has_more,
                              .next_sequence = next_seq,
                              .latest_sequence = ceiling,
                              .error_message = ""};
}

SyncMessagesResult MessageSyncService::sync_messages(const MessagingCallerContext& caller,
                                                     const SyncDeviceMessagesCommand& cmd) {
    return sync_messages(domain::UserId(caller.user_id()), cmd);
}

} // namespace securecloud::messaging::service
