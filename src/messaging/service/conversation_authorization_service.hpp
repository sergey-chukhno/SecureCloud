#pragma once

#include "domain/conversation_entity.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/group_metadata_entity.hpp"
#include "repository/conversation_repository_interface.hpp"
#include "repository/membership_repository_interface.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "service/messaging_caller_context.hpp"

#include <optional>
#include <string>
#include <utility>

namespace securecloud::messaging::service {

/// Result object returned by conversation authorization evaluators.
struct AuthorizationResult {
    bool allowed{false};
    v1::MessagingErrorCode error_code{v1::MESSAGING_ERROR_CODE_UNSPECIFIED};
    std::string reason;

    [[nodiscard]] static AuthorizationResult ok() noexcept {
        return AuthorizationResult{true, v1::MESSAGING_ERROR_CODE_UNSPECIFIED, ""};
    }

    [[nodiscard]] static AuthorizationResult denied(v1::MessagingErrorCode code, std::string reason) {
        return AuthorizationResult{false, code, std::move(reason)};
    }

    [[nodiscard]] explicit operator bool() const noexcept { return allowed; }
};

/// Authoritative resource-level authorization engine evaluating fine-grained
/// permissions within conversations based on identity, membership status, roles,
/// and conversation lifecycle state.
class ConversationAuthorizationService {
  public:
    ConversationAuthorizationService(repository::IConversationRepository& conversation_repo,
                                     repository::IMembershipRepository& membership_repo);

    /// Checks if caller is authorized to view conversation metadata, history, and participants.
    [[nodiscard]] AuthorizationResult can_view_conversation(const domain::UserId& caller,
                                                            const domain::ConversationId& conv_id) const;
    [[nodiscard]] AuthorizationResult can_view_conversation(const MessagingCallerContext& caller,
                                                            const domain::ConversationId& conv_id) const;

    /// Checks if caller is authorized to send messages to the conversation.
    [[nodiscard]] AuthorizationResult can_send_message(const domain::UserId& caller,
                                                       const domain::ConversationId& conv_id) const;
    [[nodiscard]] AuthorizationResult can_send_message(const MessagingCallerContext& caller,
                                                       const domain::ConversationId& conv_id) const;

    /// Checks if caller is authorized to add participants to the conversation (caller authority check).
    [[nodiscard]] AuthorizationResult can_add_participant(const domain::UserId& caller,
                                                          const domain::ConversationId& conv_id) const;
    [[nodiscard]] AuthorizationResult can_add_participant(const MessagingCallerContext& caller,
                                                          const domain::ConversationId& conv_id) const;

    /// Checks if caller is authorized to add a new participant to the conversation.
    [[nodiscard]] AuthorizationResult can_add_participant(const domain::UserId& caller,
                                                          const domain::ConversationId& conv_id,
                                                          const domain::UserId& target_user) const;
    [[nodiscard]] AuthorizationResult can_add_participant(const MessagingCallerContext& caller,
                                                          const domain::ConversationId& conv_id,
                                                          const domain::UserId& target_user) const;

    /// Checks if caller is authorized to remove an existing participant from the conversation.
    [[nodiscard]] AuthorizationResult can_remove_participant(const domain::UserId& caller,
                                                             const domain::ConversationId& conv_id,
                                                             const domain::UserId& target_user) const;
    [[nodiscard]] AuthorizationResult can_remove_participant(const MessagingCallerContext& caller,
                                                             const domain::ConversationId& conv_id,
                                                             const domain::UserId& target_user) const;

    /// Checks if caller is authorized to leave the conversation.
    [[nodiscard]] AuthorizationResult can_leave_conversation(const domain::UserId& caller,
                                                             const domain::ConversationId& conv_id) const;
    [[nodiscard]] AuthorizationResult can_leave_conversation(const MessagingCallerContext& caller,
                                                             const domain::ConversationId& conv_id) const;

    /// Checks if caller is authorized to update conversation metadata (e.g., title).
    [[nodiscard]] AuthorizationResult can_update_metadata(const domain::UserId& caller,
                                                          const domain::ConversationId& conv_id) const;
    [[nodiscard]] AuthorizationResult can_update_metadata(const MessagingCallerContext& caller,
                                                          const domain::ConversationId& conv_id) const;

    /// Checks if caller is authorized to close/archive the group conversation.
    [[nodiscard]] AuthorizationResult can_close_conversation(const domain::UserId& caller,
                                                             const domain::ConversationId& conv_id) const;
    [[nodiscard]] AuthorizationResult can_close_conversation(const MessagingCallerContext& caller,
                                                             const domain::ConversationId& conv_id) const;

  private:
    repository::IConversationRepository& conversation_repo_;
    repository::IMembershipRepository& membership_repo_;

    [[nodiscard]] static std::optional<domain::UserId> parse_caller_user_id(const MessagingCallerContext& caller);
};

} // namespace securecloud::messaging::service
