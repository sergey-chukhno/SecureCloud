#pragma once

#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::messaging::repository {

/// Summary view of a user's conversation inbox for paginated queries (conversations_by_user).
struct UserConversationSummary {
    domain::ConversationId conversation_id{};
    domain::ConversationType type{domain::ConversationType::Direct};
    domain::MembershipStatus membership_status{domain::MembershipStatus::Active};
    std::chrono::system_clock::time_point last_activity_at{};

    auto operator<=>(const UserConversationSummary& other) const noexcept = default;
    bool operator==(const UserConversationSummary& other) const noexcept = default;
};

/// Paginated page result for user conversations.
struct UserConversationsPage {
    std::vector<UserConversationSummary> items{};
    std::optional<std::string> next_page_token{std::nullopt};
};

/// Abstract repository contract for Conversation Membership and User Inbox queries.
/// Conforms to ScyllaDB query patterns (ADR-005, 03-messaging-data-model.md):
/// - conversation_members_by_conversation
/// - conversations_by_user
class IMembershipRepository {
  public:
    virtual ~IMembershipRepository() = default;

    /// Adds or updates a participant in a conversation roster.
    virtual void add_participant(const domain::ConversationParticipantEntity& participant) = 0;

    /// Updates existing participant membership status, role, and exit timestamp.
    virtual void update_participant(const domain::ConversationParticipantEntity& participant) = 0;

    /// Retrieves participant details for a specific user in a conversation.
    [[nodiscard]] virtual std::optional<domain::ConversationParticipantEntity>
    find_participant(const domain::ConversationId& conv_id, const domain::UserId& user_id) = 0;

    /// Retrieves all participant records (active, left, removed) for a conversation.
    [[nodiscard]] virtual std::vector<domain::ConversationParticipantEntity>
    list_participants(const domain::ConversationId& conv_id) = 0;

    /// Retrieves only active participant records for a conversation.
    [[nodiscard]] virtual std::vector<domain::ConversationParticipantEntity>
    list_active_participants(const domain::ConversationId& conv_id) = 0;

    /// Updates the user inbox entry with latest activity timestamp (conversations_by_user).
    virtual void touch_user_conversation(const domain::UserId& user_id, const domain::ConversationId& conv_id,
                                         domain::ConversationType type, domain::MembershipStatus status,
                                         std::chrono::system_clock::time_point activity_at) = 0;

    /// Lists conversations for a user ordered by last activity with pagination (conversations_by_user).
    [[nodiscard]] virtual UserConversationsPage
    list_user_conversations(const domain::UserId& user_id, int limit, const std::optional<std::string>& page_token) = 0;
};

} // namespace securecloud::messaging::repository
