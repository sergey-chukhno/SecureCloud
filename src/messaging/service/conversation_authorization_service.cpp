#include "service/conversation_authorization_service.hpp"

namespace securecloud::messaging::service {

ConversationAuthorizationService::ConversationAuthorizationService(
    repository::IConversationRepository& conversation_repo, repository::IMembershipRepository& membership_repo)
    : conversation_repo_(conversation_repo), membership_repo_(membership_repo) {}

std::optional<domain::UserId>
ConversationAuthorizationService::parse_caller_user_id(const MessagingCallerContext& caller) {
    if (caller.user_id().empty()) {
        return std::nullopt;
    }
    return domain::UserId::from_string(caller.user_id());
}

// ============================================================================
// 1. can_view_conversation
// ============================================================================

AuthorizationResult
ConversationAuthorizationService::can_view_conversation(const domain::UserId& caller,
                                                        const domain::ConversationId& conv_id) const {
    auto conv = conversation_repo_.find_conversation_by_id(conv_id);
    if (!conv) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND,
                                           "Conversation does not exist");
    }

    auto participant = membership_repo_.find_participant(conv_id, caller);
    if (!participant || participant->status != domain::MembershipStatus::Active) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                                           "Caller is not an active participant in this conversation");
    }

    return AuthorizationResult::ok();
}

AuthorizationResult
ConversationAuthorizationService::can_view_conversation(const MessagingCallerContext& caller,
                                                        const domain::ConversationId& conv_id) const {
    auto caller_id = parse_caller_user_id(caller);
    if (!caller_id) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Invalid or missing caller user ID in context");
    }
    return can_view_conversation(*caller_id, conv_id);
}

// ============================================================================
// 2. can_send_message
// ============================================================================

AuthorizationResult ConversationAuthorizationService::can_send_message(const domain::UserId& caller,
                                                                       const domain::ConversationId& conv_id) const {
    auto conv = conversation_repo_.find_conversation_by_id(conv_id);
    if (!conv) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND,
                                           "Conversation does not exist");
    }

    if (conv->type == domain::ConversationType::Group) {
        auto meta = conversation_repo_.find_group_metadata(conv_id);
        if (meta && meta->status == domain::GroupStatus::Closed) {
            return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND,
                                               "Conversation is closed");
        }
    }

    auto participant = membership_repo_.find_participant(conv_id, caller);
    if (!participant || participant->status != domain::MembershipStatus::Active) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                                           "Caller is not an active participant in this conversation");
    }

    return AuthorizationResult::ok();
}

AuthorizationResult ConversationAuthorizationService::can_send_message(const MessagingCallerContext& caller,
                                                                       const domain::ConversationId& conv_id) const {
    auto caller_id = parse_caller_user_id(caller);
    if (!caller_id) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Invalid or missing caller user ID in context");
    }
    return can_send_message(*caller_id, conv_id);
}

// ============================================================================
// 3. can_add_participant
// ============================================================================

AuthorizationResult ConversationAuthorizationService::can_add_participant(const domain::UserId& caller,
                                                                          const domain::ConversationId& conv_id) const {
    auto conv = conversation_repo_.find_conversation_by_id(conv_id);
    if (!conv) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND,
                                           "Conversation does not exist");
    }

    if (conv->type == domain::ConversationType::Direct) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Cannot add participants to a direct conversation");
    }

    auto meta = conversation_repo_.find_group_metadata(conv_id);
    if (meta && meta->status == domain::GroupStatus::Closed) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Group conversation is closed");
    }

    auto caller_part = membership_repo_.find_participant(conv_id, caller);
    if (!caller_part || caller_part->status != domain::MembershipStatus::Active) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                                           "Caller is not an active participant in this conversation");
    }

    if (caller_part->role != domain::ParticipantRole::Admin) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Only conversation admins can add participants");
    }

    return AuthorizationResult::ok();
}

AuthorizationResult ConversationAuthorizationService::can_add_participant(const MessagingCallerContext& caller,
                                                                          const domain::ConversationId& conv_id) const {
    auto caller_id = parse_caller_user_id(caller);
    if (!caller_id) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Invalid or missing caller user ID in context");
    }
    return can_add_participant(*caller_id, conv_id);
}

AuthorizationResult ConversationAuthorizationService::can_add_participant(const domain::UserId& caller,
                                                                          const domain::ConversationId& conv_id,
                                                                          const domain::UserId& target_user) const {
    auto caller_auth = can_add_participant(caller, conv_id);
    if (!caller_auth) {
        return caller_auth;
    }

    auto target_part = membership_repo_.find_participant(conv_id, target_user);
    if (target_part && target_part->status == domain::MembershipStatus::Active) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "User is already an active participant in this conversation");
    }

    return AuthorizationResult::ok();
}

AuthorizationResult ConversationAuthorizationService::can_add_participant(const MessagingCallerContext& caller,
                                                                          const domain::ConversationId& conv_id,
                                                                          const domain::UserId& target_user) const {
    auto caller_id = parse_caller_user_id(caller);
    if (!caller_id) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Invalid or missing caller user ID in context");
    }
    return can_add_participant(*caller_id, conv_id, target_user);
}

// ============================================================================
// 4. can_remove_participant
// ============================================================================

AuthorizationResult ConversationAuthorizationService::can_remove_participant(const domain::UserId& caller,
                                                                             const domain::ConversationId& conv_id,
                                                                             const domain::UserId& target_user) const {
    auto conv = conversation_repo_.find_conversation_by_id(conv_id);
    if (!conv) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND,
                                           "Conversation does not exist");
    }

    if (conv->type == domain::ConversationType::Direct) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Cannot remove participants from a direct conversation");
    }

    auto meta = conversation_repo_.find_group_metadata(conv_id);
    if (meta && meta->status == domain::GroupStatus::Closed) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Group conversation is closed");
    }

    if (caller == target_user) {
        return can_leave_conversation(caller, conv_id);
    }

    auto caller_part = membership_repo_.find_participant(conv_id, caller);
    if (!caller_part || caller_part->status != domain::MembershipStatus::Active) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                                           "Caller is not an active participant in this conversation");
    }

    if (caller_part->role != domain::ParticipantRole::Admin) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Only conversation admins can remove participants");
    }

    auto target_part = membership_repo_.find_participant(conv_id, target_user);
    if (!target_part || target_part->status != domain::MembershipStatus::Active) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                                           "Target user is not an active participant in this conversation");
    }

    return AuthorizationResult::ok();
}

AuthorizationResult ConversationAuthorizationService::can_remove_participant(const MessagingCallerContext& caller,
                                                                             const domain::ConversationId& conv_id,
                                                                             const domain::UserId& target_user) const {
    auto caller_id = parse_caller_user_id(caller);
    if (!caller_id) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Invalid or missing caller user ID in context");
    }
    return can_remove_participant(*caller_id, conv_id, target_user);
}

// ============================================================================
// 5. can_leave_conversation
// ============================================================================

AuthorizationResult
ConversationAuthorizationService::can_leave_conversation(const domain::UserId& caller,
                                                         const domain::ConversationId& conv_id) const {
    auto conv = conversation_repo_.find_conversation_by_id(conv_id);
    if (!conv) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND,
                                           "Conversation does not exist");
    }

    if (conv->type == domain::ConversationType::Direct) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Cannot leave a direct conversation");
    }

    auto caller_part = membership_repo_.find_participant(conv_id, caller);
    if (!caller_part || caller_part->status != domain::MembershipStatus::Active) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                                           "Caller is not an active participant in this conversation");
    }

    if (caller_part->role == domain::ParticipantRole::Admin) {
        auto active_participants = membership_repo_.list_active_participants(conv_id);
        size_t other_active_admins = 0;
        size_t other_active_members = 0;

        for (const auto& p : active_participants) {
            if (p.user_id == caller) {
                continue;
            }
            if (p.role == domain::ParticipantRole::Admin) {
                ++other_active_admins;
            } else {
                ++other_active_members;
            }
        }

        if (other_active_admins == 0 && other_active_members > 0) {
            return AuthorizationResult::denied(
                v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                "The last remaining admin cannot leave a conversation while other active members remain. "
                "Transfer admin role first.");
        }
    }

    return AuthorizationResult::ok();
}

AuthorizationResult
ConversationAuthorizationService::can_leave_conversation(const MessagingCallerContext& caller,
                                                         const domain::ConversationId& conv_id) const {
    auto caller_id = parse_caller_user_id(caller);
    if (!caller_id) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Invalid or missing caller user ID in context");
    }
    return can_leave_conversation(*caller_id, conv_id);
}

// ============================================================================
// 6. can_update_metadata
// ============================================================================

AuthorizationResult ConversationAuthorizationService::can_update_metadata(const domain::UserId& caller,
                                                                          const domain::ConversationId& conv_id) const {
    auto conv = conversation_repo_.find_conversation_by_id(conv_id);
    if (!conv) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND,
                                           "Conversation does not exist");
    }

    if (conv->type == domain::ConversationType::Direct) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Direct conversations do not have group metadata");
    }

    auto meta = conversation_repo_.find_group_metadata(conv_id);
    if (meta && meta->status == domain::GroupStatus::Closed) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Group conversation is closed");
    }

    auto caller_part = membership_repo_.find_participant(conv_id, caller);
    if (!caller_part || caller_part->status != domain::MembershipStatus::Active) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                                           "Caller is not an active participant in this conversation");
    }

    if (caller_part->role != domain::ParticipantRole::Admin) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Only conversation admins can update conversation metadata");
    }

    return AuthorizationResult::ok();
}

AuthorizationResult ConversationAuthorizationService::can_update_metadata(const MessagingCallerContext& caller,
                                                                          const domain::ConversationId& conv_id) const {
    auto caller_id = parse_caller_user_id(caller);
    if (!caller_id) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Invalid or missing caller user ID in context");
    }
    return can_update_metadata(*caller_id, conv_id);
}

// ============================================================================
// 7. can_close_conversation
// ============================================================================

AuthorizationResult
ConversationAuthorizationService::can_close_conversation(const domain::UserId& caller,
                                                         const domain::ConversationId& conv_id) const {
    auto conv = conversation_repo_.find_conversation_by_id(conv_id);
    if (!conv) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND,
                                           "Conversation does not exist");
    }

    if (conv->type == domain::ConversationType::Direct) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Cannot close a direct conversation");
    }

    auto meta = conversation_repo_.find_group_metadata(conv_id);
    if (meta && meta->status == domain::GroupStatus::Closed) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Group conversation is already closed");
    }

    auto caller_part = membership_repo_.find_participant(conv_id, caller);
    if (!caller_part || caller_part->status != domain::MembershipStatus::Active) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                                           "Caller is not an active participant in this conversation");
    }

    if (caller_part->role != domain::ParticipantRole::Admin) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Only conversation admins can close a group conversation");
    }

    return AuthorizationResult::ok();
}

AuthorizationResult
ConversationAuthorizationService::can_close_conversation(const MessagingCallerContext& caller,
                                                         const domain::ConversationId& conv_id) const {
    auto caller_id = parse_caller_user_id(caller);
    if (!caller_id) {
        return AuthorizationResult::denied(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                           "Invalid or missing caller user ID in context");
    }
    return can_close_conversation(*caller_id, conv_id);
}

bool ConversationAuthorizationService::shares_mutual_conversation(const domain::UserId& caller,
                                                                  const domain::UserId& target) const {
    if (caller == target) {
        return true;
    }

    auto conversations_page = membership_repo_.list_user_conversations(caller, 100, std::nullopt);
    for (const auto& item : conversations_page.items) {
        if (item.membership_status != domain::MembershipStatus::Active) {
            continue;
        }

        auto target_part = membership_repo_.find_participant(item.conversation_id, target);
        if (target_part && target_part->status == domain::MembershipStatus::Active) {
            return true;
        }
    }

    return false;
}

} // namespace securecloud::messaging::service
