#include "domain/conversation.hpp"

#include <algorithm>
#include <utility>

namespace securecloud::client::domain {

std::string_view to_string(ConversationType type) noexcept {
    switch (type) {
    case ConversationType::Direct:
        return "Direct";
    case ConversationType::Group:
        return "Group";
    }
    return "Unknown";
}

Conversation::Conversation(ConversationId conversation_id, ConversationType type, std::string title,
                           std::vector<UserId> participants, std::chrono::system_clock::time_point created_at,
                           std::chrono::system_clock::time_point last_activity_at)
    : conversation_id_(std::move(conversation_id)), type_(type), title_(std::move(title)),
      participants_(std::move(participants)), created_at_(created_at), last_activity_at_(last_activity_at) {}

void Conversation::add_participant(UserId user_id) {
    if (std::find(participants_.begin(), participants_.end(), user_id) == participants_.end()) {
        participants_.push_back(std::move(user_id));
    }
}

void Conversation::remove_participant(const UserId& user_id) {
    participants_.erase(std::remove(participants_.begin(), participants_.end(), user_id), participants_.end());
}

bool Conversation::operator==(const Conversation& other) const noexcept {
    return conversation_id_ == other.conversation_id_ && type_ == other.type_ && title_ == other.title_ &&
           participants_ == other.participants_;
}

} // namespace securecloud::client::domain
