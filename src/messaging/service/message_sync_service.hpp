#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_types.hpp"
#include "domain/sync_types.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/messaging_caller_context.hpp"
#include "service/sync_commands.hpp"
#include "service/sync_cursor_manager.hpp"

#include <memory>
#include <vector>

namespace securecloud::messaging::service {

/**
 * @brief Authoritative service for bounded online message synchronization (MSG-009).
 *
 * Enforces:
 * - Conversation authorization: caller must be an active participant to read history.
 * - Deterministic bounded batch pagination [1, 500].
 * - Monotonic stream pagination evaluation (has_more, next_sequence, latest_sequence).
 * - Multi-month message bucket traversal.
 */
class MessageSyncService {
  public:
    /**
     * @brief Constructs MessageSyncService with required repository and manager dependencies.
     * @throws std::invalid_argument if message_repo or cursor_manager is nullptr.
     */
    MessageSyncService(std::shared_ptr<repository::IMessageRepository> message_repo,
                       std::shared_ptr<SyncCursorManager> cursor_manager,
                       std::shared_ptr<ConversationAuthorizationService> auth_service = nullptr,
                       std::shared_ptr<repository::IDeliveryStateRepository> delivery_state_repo = nullptr);

    /// Synchronizes messages for a caller's device within a conversation using domain UserId.
    [[nodiscard]] SyncMessagesResult sync_messages(const domain::UserId& caller_id,
                                                   const SyncDeviceMessagesCommand& cmd);

    /// Overload synchronizing messages using authenticated MessagingCallerContext.
    [[nodiscard]] SyncMessagesResult sync_messages(const MessagingCallerContext& caller,
                                                   const SyncDeviceMessagesCommand& cmd);

  private:
    std::shared_ptr<repository::IMessageRepository> message_repo_;
    std::shared_ptr<SyncCursorManager> cursor_manager_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<repository::IDeliveryStateRepository> delivery_state_repo_;
};

} // namespace securecloud::messaging::service
