#include "service/conversation_service.hpp"

#include <mutex>
#include <unordered_set>

namespace securecloud::messaging::service {

ConversationService::ConversationService(repository::IConversationRepository& conversation_repo,
                                         repository::IMembershipRepository& membership_repo,
                                         ConversationAuthorizationService& auth_service)
    : conversation_repo_(conversation_repo), membership_repo_(membership_repo), auth_service_(auth_service) {}

// ============================================================================
// 1. create_direct_conversation
// ============================================================================

ServiceResult<domain::ConversationEntity>
ConversationService::create_direct_conversation(const domain::UserId& caller, const domain::UserId& recipient) {
    if (caller == recipient) {
        return ServiceResult<domain::ConversationEntity>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                                               "Cannot create a direct conversation with yourself");
    }

    domain::DirectPair pair(caller, recipient);

    // Idempotent lookup
    auto existing_id = conversation_repo_.find_direct_conversation(pair);
    if (existing_id) {
        auto existing_conv = conversation_repo_.find_conversation_by_id(*existing_id);
        if (existing_conv) {
            return ServiceResult<domain::ConversationEntity>::ok(*existing_conv);
        }
    }

    auto conv_id = domain::ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    domain::ConversationEntity conv{
        .conversation_id = conv_id,
        .type = domain::ConversationType::Direct,
        .created_by_user_id = caller,
        .created_at = now,
        .metadata_version = 1,
    };

    conversation_repo_.save_conversation(conv);
    conversation_repo_.save_direct_conversation(pair, conv_id);

    domain::ConversationParticipantEntity part_caller{
        .conversation_id = conv_id,
        .user_id = caller,
        .role = domain::ParticipantRole::Member,
        .status = domain::MembershipStatus::Active,
        .joined_at = now,
        .left_at = std::nullopt,
        .membership_version = 1,
    };
    domain::ConversationParticipantEntity part_recipient{
        .conversation_id = conv_id,
        .user_id = recipient,
        .role = domain::ParticipantRole::Member,
        .status = domain::MembershipStatus::Active,
        .joined_at = now,
        .left_at = std::nullopt,
        .membership_version = 1,
    };

    membership_repo_.add_participant(part_caller);
    membership_repo_.add_participant(part_recipient);

    membership_repo_.touch_user_conversation(caller, conv_id, domain::ConversationType::Direct,
                                             domain::MembershipStatus::Active, now);
    membership_repo_.touch_user_conversation(recipient, conv_id, domain::ConversationType::Direct,
                                             domain::MembershipStatus::Active, now);

    record_outbox_event(conv_id, domain::ConversationOutboxEventType::ConversationCreated,
                        "{\"type\":\"direct\",\"creator\":\"" + caller.str() + "\"}");

    return ServiceResult<domain::ConversationEntity>::ok(conv);
}

// ============================================================================
// 2. create_group_conversation
// ============================================================================

ServiceResult<domain::ConversationEntity>
ConversationService::create_group_conversation(const domain::UserId& caller, std::string_view title,
                                               const std::vector<domain::UserId>& initial_participant_user_ids) {
    if (title.empty() || title.size() > 256) {
        return ServiceResult<domain::ConversationEntity>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                                               "Group title must be between 1 and 256 characters");
    }

    auto conv_id = domain::ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    domain::ConversationEntity conv{
        .conversation_id = conv_id,
        .type = domain::ConversationType::Group,
        .created_by_user_id = caller,
        .created_at = now,
        .metadata_version = 1,
    };

    domain::GroupMetadataEntity meta{
        .conversation_id = conv_id,
        .title = std::string(title),
        .status = domain::GroupStatus::Active,
        .created_at = now,
        .updated_at = now,
        .metadata_version = 1,
    };

    conversation_repo_.save_conversation(conv);
    conversation_repo_.save_group_metadata(meta);

    // Caller is Admin
    domain::ConversationParticipantEntity admin_part{
        .conversation_id = conv_id,
        .user_id = caller,
        .role = domain::ParticipantRole::Admin,
        .status = domain::MembershipStatus::Active,
        .joined_at = now,
        .left_at = std::nullopt,
        .membership_version = 1,
    };
    membership_repo_.add_participant(admin_part);
    membership_repo_.touch_user_conversation(caller, conv_id, domain::ConversationType::Group,
                                             domain::MembershipStatus::Active, now);

    std::unordered_set<std::string> added;
    added.insert(caller.str());

    for (const auto& uid : initial_participant_user_ids) {
        if (added.insert(uid.str()).second) {
            domain::ConversationParticipantEntity member_part{
                .conversation_id = conv_id,
                .user_id = uid,
                .role = domain::ParticipantRole::Member,
                .status = domain::MembershipStatus::Active,
                .joined_at = now,
                .left_at = std::nullopt,
                .membership_version = 1,
            };
            membership_repo_.add_participant(member_part);
            membership_repo_.touch_user_conversation(uid, conv_id, domain::ConversationType::Group,
                                                     domain::MembershipStatus::Active, now);
        }
    }

    record_outbox_event(conv_id, domain::ConversationOutboxEventType::ConversationCreated,
                        "{\"type\":\"group\",\"creator\":\"" + caller.str() + "\",\"title\":\"" + std::string(title) +
                            "\"}");

    return ServiceResult<domain::ConversationEntity>::ok(conv);
}

// ============================================================================
// 3. add_participant
// ============================================================================

ServiceResult<void> ConversationService::add_participant(const domain::UserId& caller,
                                                         const domain::ConversationId& conv_id,
                                                         const domain::UserId& target_user) {
    auto auth_res = auth_service_.can_add_participant(caller, conv_id);
    if (!auth_res) {
        return ServiceResult<void>::fail(auth_res.error_code, auth_res.reason);
    }

    auto now = std::chrono::system_clock::now();
    auto existing = membership_repo_.find_participant(conv_id, target_user);

    if (existing) {
        if (existing->status == domain::MembershipStatus::Active) {
            return ServiceResult<void>::ok(); // Idempotent success
        }
        auto updated = *existing;
        updated.status = domain::MembershipStatus::Active;
        updated.joined_at = now;
        updated.left_at = std::nullopt;
        updated.membership_version++;
        membership_repo_.update_participant(updated);
    } else {
        domain::ConversationParticipantEntity part{
            .conversation_id = conv_id,
            .user_id = target_user,
            .role = domain::ParticipantRole::Member,
            .status = domain::MembershipStatus::Active,
            .joined_at = now,
            .left_at = std::nullopt,
            .membership_version = 1,
        };
        membership_repo_.add_participant(part);
    }

    membership_repo_.touch_user_conversation(target_user, conv_id, domain::ConversationType::Group,
                                             domain::MembershipStatus::Active, now);

    record_outbox_event(conv_id, domain::ConversationOutboxEventType::ParticipantJoined,
                        "{\"user_id\":\"" + target_user.str() + "\"}");

    return ServiceResult<void>::ok();
}

// ============================================================================
// 4. remove_participant
// ============================================================================

ServiceResult<void> ConversationService::remove_participant(const domain::UserId& caller,
                                                            const domain::ConversationId& conv_id,
                                                            const domain::UserId& target_user) {
    auto auth_res = auth_service_.can_remove_participant(caller, conv_id, target_user);
    if (!auth_res) {
        return ServiceResult<void>::fail(auth_res.error_code, auth_res.reason);
    }

    auto existing = membership_repo_.find_participant(conv_id, target_user);
    if (!existing) {
        return ServiceResult<void>::fail(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                                         "Target user is not a participant");
    }

    auto now = std::chrono::system_clock::now();
    auto updated = *existing;
    updated.status = domain::MembershipStatus::Removed;
    updated.left_at = now;
    updated.membership_version++;
    membership_repo_.update_participant(updated);

    membership_repo_.touch_user_conversation(target_user, conv_id, domain::ConversationType::Group,
                                             domain::MembershipStatus::Removed, now);

    record_outbox_event(conv_id, domain::ConversationOutboxEventType::ParticipantRemoved,
                        "{\"user_id\":\"" + target_user.str() + "\",\"removed_by\":\"" + caller.str() + "\"}");

    return ServiceResult<void>::ok();
}

// ============================================================================
// 5. leave_conversation
// ============================================================================

ServiceResult<void> ConversationService::leave_conversation(const domain::UserId& caller,
                                                            const domain::ConversationId& conv_id) {
    auto auth_res = auth_service_.can_leave_conversation(caller, conv_id);
    if (!auth_res) {
        return ServiceResult<void>::fail(auth_res.error_code, auth_res.reason);
    }

    auto existing = membership_repo_.find_participant(conv_id, caller);
    if (!existing) {
        return ServiceResult<void>::fail(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT, "Caller is not a participant");
    }

    auto now = std::chrono::system_clock::now();
    auto updated = *existing;
    updated.status = domain::MembershipStatus::Left;
    updated.left_at = now;
    updated.membership_version++;
    membership_repo_.update_participant(updated);

    membership_repo_.touch_user_conversation(caller, conv_id, domain::ConversationType::Group,
                                             domain::MembershipStatus::Left, now);

    record_outbox_event(conv_id, domain::ConversationOutboxEventType::ParticipantLeft,
                        "{\"user_id\":\"" + caller.str() + "\"}");

    // If zero active participants remain, automatically close the group conversation
    auto active = membership_repo_.list_active_participants(conv_id);
    if (active.empty()) {
        auto meta = conversation_repo_.find_group_metadata(conv_id);
        if (meta) {
            auto closed_meta = *meta;
            closed_meta.status = domain::GroupStatus::Closed;
            closed_meta.updated_at = now;
            closed_meta.metadata_version++;
            conversation_repo_.save_group_metadata(closed_meta);

            record_outbox_event(conv_id, domain::ConversationOutboxEventType::ConversationClosed,
                                "{\"reason\":\"all_participants_left\"}");
        }
    }

    return ServiceResult<void>::ok();
}

// ============================================================================
// 6. update_group_metadata
// ============================================================================

ServiceResult<domain::GroupMetadataEntity>
ConversationService::update_group_metadata(const domain::UserId& caller, const domain::ConversationId& conv_id,
                                           std::string_view new_title) {
    if (new_title.empty() || new_title.size() > 256) {
        return ServiceResult<domain::GroupMetadataEntity>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                                                "Group title must be between 1 and 256 characters");
    }

    auto auth_res = auth_service_.can_update_metadata(caller, conv_id);
    if (!auth_res) {
        return ServiceResult<domain::GroupMetadataEntity>::fail(auth_res.error_code, auth_res.reason);
    }

    auto meta = conversation_repo_.find_group_metadata(conv_id);
    if (!meta) {
        return ServiceResult<domain::GroupMetadataEntity>::fail(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND,
                                                                "Group metadata not found");
    }

    auto now = std::chrono::system_clock::now();
    auto updated = *meta;
    updated.title = std::string(new_title);
    updated.updated_at = now;
    updated.metadata_version++;
    conversation_repo_.save_group_metadata(updated);

    record_outbox_event(conv_id, domain::ConversationOutboxEventType::GroupMetadataUpdated,
                        "{\"new_title\":\"" + std::string(new_title) + "\",\"updated_by\":\"" + caller.str() + "\"}");

    return ServiceResult<domain::GroupMetadataEntity>::ok(updated);
}

// ============================================================================
// 7. get_conversation
// ============================================================================

ServiceResult<ConversationDetails> ConversationService::get_conversation(const domain::UserId& caller,
                                                                         const domain::ConversationId& conv_id) {
    auto auth_res = auth_service_.can_view_conversation(caller, conv_id);
    if (!auth_res) {
        return ServiceResult<ConversationDetails>::fail(auth_res.error_code, auth_res.reason);
    }

    auto conv = conversation_repo_.find_conversation_by_id(conv_id);
    if (!conv) {
        return ServiceResult<ConversationDetails>::fail(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND,
                                                        "Conversation not found");
    }

    ConversationDetails details;
    details.conversation = *conv;

    if (conv->type == domain::ConversationType::Group) {
        details.group_metadata = conversation_repo_.find_group_metadata(conv_id);
    }

    details.active_participants = membership_repo_.list_active_participants(conv_id);
    return ServiceResult<ConversationDetails>::ok(details);
}

// ============================================================================
// 8. list_user_conversations
// ============================================================================

ServiceResult<repository::UserConversationsPage>
ConversationService::list_user_conversations(const domain::UserId& caller, int limit,
                                             const std::optional<std::string>& page_token) {
    auto page = membership_repo_.list_user_conversations(caller, limit, page_token);
    return ServiceResult<repository::UserConversationsPage>::ok(page);
}

// ============================================================================
// Outbox Management
// ============================================================================

std::vector<domain::ConversationOutboxEvent> ConversationService::get_outbox_events() const {
    std::lock_guard<std::mutex> lock(outbox_mutex_);
    return outbox_events_;
}

void ConversationService::clear_outbox_events() {
    std::lock_guard<std::mutex> lock(outbox_mutex_);
    outbox_events_.clear();
}

void ConversationService::record_outbox_event(const domain::ConversationId& conv_id,
                                              domain::ConversationOutboxEventType type, std::string payload_json) {
    std::lock_guard<std::mutex> lock(outbox_mutex_);
    outbox_events_.push_back({
        .event_id = domain::ConversationId::generate_v7().to_string(),
        .conversation_id = conv_id,
        .event_type = type,
        .payload_json = std::move(payload_json),
        .created_at = std::chrono::system_clock::now(),
    });
}

} // namespace securecloud::messaging::service
