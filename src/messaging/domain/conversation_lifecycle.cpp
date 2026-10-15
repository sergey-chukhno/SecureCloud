#include "domain/conversation_lifecycle.hpp"

#include <algorithm>

namespace securecloud::messaging::domain {

bool ConversationLifecycleManager::is_valid_group_transition(GroupStatus current_status,
                                                             GroupStatus new_status) noexcept {
    if (current_status == new_status) {
        return true; // Idempotent no-op
    }

    switch (current_status) {
    case GroupStatus::Active:
        return new_status == GroupStatus::Closed;
    case GroupStatus::Closed:
        return false; // Terminal state in MVP
    }
    return false;
}

bool ConversationLifecycleManager::is_valid_membership_transition(MembershipStatus current_status,
                                                                  MembershipStatus new_status) noexcept {
    if (current_status == new_status) {
        return true; // Idempotent no-op
    }

    switch (current_status) {
    case MembershipStatus::Active:
        return new_status == MembershipStatus::Left || new_status == MembershipStatus::Removed;
    case MembershipStatus::Left:
    case MembershipStatus::Removed:
        return new_status == MembershipStatus::Active; // Rejoining or readmission
    }
    return false;
}

bool ConversationLifecycleManager::is_valid_direct_participant_count(std::size_t participant_count) noexcept {
    return participant_count == 2;
}

bool ConversationLifecycleManager::is_valid_group_initial_participant_count(std::size_t participant_count) noexcept {
    return participant_count >= 1 && participant_count <= 500;
}

bool ConversationLifecycleManager::is_valid_group_title(std::string_view title) noexcept {
    if (title.empty() || title.size() > 255) {
        return false;
    }
    // Title must contain at least one non-whitespace character
    return std::any_of(title.begin(), title.end(),
                       [](char c) { return c != ' ' && c != '\t' && c != '\r' && c != '\n'; });
}

} // namespace securecloud::messaging::domain
