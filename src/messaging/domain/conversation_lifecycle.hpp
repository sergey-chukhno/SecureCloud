#pragma once

#include "domain/conversation_types.hpp"

#include <string_view>

namespace securecloud::messaging::domain {

/// Validates conversation and participant lifecycle state transitions.
class ConversationLifecycleManager {
  public:
    /// Checks if a group conversation status transition from current_status to new_status is valid.
    [[nodiscard]] static bool is_valid_group_transition(GroupStatus current_status, GroupStatus new_status) noexcept;

    /// Checks if a participant membership status transition from current_status to new_status is valid.
    [[nodiscard]] static bool is_valid_membership_transition(MembershipStatus current_status,
                                                             MembershipStatus new_status) noexcept;

    /// Checks if a direct conversation participant count is valid (must be exactly 2).
    [[nodiscard]] static bool is_valid_direct_participant_count(std::size_t participant_count) noexcept;

    /// Checks if a group conversation initial participant count is valid (must be >= 1).
    [[nodiscard]] static bool is_valid_group_initial_participant_count(std::size_t participant_count) noexcept;

    /// Checks if a group title is valid (1 to 255 non-whitespace characters).
    [[nodiscard]] static bool is_valid_group_title(std::string_view title) noexcept;
};

} // namespace securecloud::messaging::domain
