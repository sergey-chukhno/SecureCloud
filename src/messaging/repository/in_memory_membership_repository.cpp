#include "repository/in_memory_membership_repository.hpp"

#include <mutex>

namespace securecloud::messaging::repository {

void InMemoryMembershipRepository::add_participant(const domain::ConversationParticipantEntity& participant) {
    std::lock_guard<std::mutex> lock(mutex_);
    ParticipantKey key{participant.conversation_id, participant.user_id};
    participants_[key] = participant;
}

void InMemoryMembershipRepository::update_participant(const domain::ConversationParticipantEntity& participant) {
    std::lock_guard<std::mutex> lock(mutex_);
    ParticipantKey key{participant.conversation_id, participant.user_id};
    participants_[key] = participant;
}

std::optional<domain::ConversationParticipantEntity>
InMemoryMembershipRepository::find_participant(const domain::ConversationId& conv_id, const domain::UserId& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    ParticipantKey key{conv_id, user_id};
    auto it = participants_.find(key);
    if (it != participants_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<domain::ConversationParticipantEntity>
InMemoryMembershipRepository::list_participants(const domain::ConversationId& conv_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<domain::ConversationParticipantEntity> result;
    for (const auto& [key, participant] : participants_) {
        if (key.conv_id == conv_id) {
            result.push_back(participant);
        }
    }
    return result;
}

std::vector<domain::ConversationParticipantEntity>
InMemoryMembershipRepository::list_active_participants(const domain::ConversationId& conv_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<domain::ConversationParticipantEntity> result;
    for (const auto& [key, participant] : participants_) {
        if (key.conv_id == conv_id && participant.status == domain::MembershipStatus::Active) {
            result.push_back(participant);
        }
    }
    return result;
}

void InMemoryMembershipRepository::touch_user_conversation(const domain::UserId& user_id,
                                                           const domain::ConversationId& conv_id,
                                                           domain::ConversationType type,
                                                           domain::MembershipStatus status,
                                                           std::chrono::system_clock::time_point activity_at) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& inbox = user_inboxes_[user_id];

    // Remove existing entry for conv_id if present
    inbox.erase(std::remove_if(inbox.begin(), inbox.end(),
                               [&](const UserConversationSummary& s) { return s.conversation_id == conv_id; }),
                inbox.end());

    // Insert new summary
    inbox.push_back(UserConversationSummary{
        .conversation_id = conv_id,
        .type = type,
        .membership_status = status,
        .last_activity_at = activity_at,
    });

    // Sort descending by last_activity_at
    std::sort(inbox.begin(), inbox.end(), [](const UserConversationSummary& a, const UserConversationSummary& b) {
        if (a.last_activity_at != b.last_activity_at) {
            return a.last_activity_at > b.last_activity_at;
        }
        return a.conversation_id > b.conversation_id;
    });
}

UserConversationsPage
InMemoryMembershipRepository::list_user_conversations(const domain::UserId& user_id, int limit,
                                                      const std::optional<std::string>& page_token) {
    std::lock_guard<std::mutex> lock(mutex_);
    UserConversationsPage page;

    auto it = user_inboxes_.find(user_id);
    if (it == user_inboxes_.end() || it->second.empty()) {
        return page;
    }

    const auto& inbox = it->second;
    std::size_t start_idx = 0;

    if (page_token.has_value() && !page_token->empty()) {
        try {
            start_idx = std::stoul(*page_token);
        } catch (...) {
            start_idx = 0;
        }
    }

    if (start_idx >= inbox.size()) {
        return page;
    }

    std::size_t effective_limit = (limit <= 0 || limit > 100) ? 50 : static_cast<std::size_t>(limit);
    std::size_t end_idx = std::min(start_idx + effective_limit, inbox.size());

    page.items.reserve(end_idx - start_idx);
    for (std::size_t i = start_idx; i < end_idx; ++i) {
        page.items.push_back(inbox[i]);
    }

    if (end_idx < inbox.size()) {
        page.next_page_token = std::to_string(end_idx);
    }

    return page;
}

void InMemoryMembershipRepository::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    participants_.clear();
    user_inboxes_.clear();
}

} // namespace securecloud::messaging::repository
