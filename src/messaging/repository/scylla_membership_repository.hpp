#pragma once

#include "messaging/db/scylla_session_interface.hpp"
#include "messaging/repository/membership_repository_interface.hpp"

#include <memory>
#include <mutex>

namespace securecloud::messaging::repository {

/// ScyllaDB persistence adapter for Conversation Membership and User Inbox queries.
/// Conforms strictly to tables:
/// - securecloud_messaging.conversation_members_by_conversation
/// - securecloud_messaging.conversations_by_user
class ScyllaMembershipRepository : public IMembershipRepository {
  public:
    explicit ScyllaMembershipRepository(std::shared_ptr<db::IScyllaSession> session);

    void add_participant(const domain::ConversationParticipantEntity& participant) override;

    void update_participant(const domain::ConversationParticipantEntity& participant) override;

    [[nodiscard]] std::optional<domain::ConversationParticipantEntity>
    find_participant(const domain::ConversationId& conv_id, const domain::UserId& user_id) override;

    [[nodiscard]] std::vector<domain::ConversationParticipantEntity>
    list_participants(const domain::ConversationId& conv_id) override;

    [[nodiscard]] std::vector<domain::ConversationParticipantEntity>
    list_active_participants(const domain::ConversationId& conv_id) override;

    void touch_user_conversation(const domain::UserId& user_id, const domain::ConversationId& conv_id,
                                 domain::ConversationType type, domain::MembershipStatus status,
                                 std::chrono::system_clock::time_point activity_at) override;

    [[nodiscard]] UserConversationsPage list_user_conversations(const domain::UserId& user_id, int limit,
                                                                const std::optional<std::string>& page_token) override;

  private:
    void init_prepared_statements();

    std::shared_ptr<db::IScyllaSession> session_;
    mutable std::mutex mutex_;

    db::PreparedStatementId prep_save_member_;
    db::PreparedStatementId prep_find_member_;
    db::PreparedStatementId prep_list_members_;
    db::PreparedStatementId prep_touch_user_conv_;
    db::PreparedStatementId prep_list_user_convs_;
};

} // namespace securecloud::messaging::repository
