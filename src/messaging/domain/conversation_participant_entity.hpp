#pragma once

#include "domain/conversation_types.hpp"

#include <chrono>
#include <cstdint>
#include <optional>

namespace securecloud::messaging::domain {

/// Domain entity representing a participant within a conversation.
struct ConversationParticipantEntity {
    ConversationId conversation_id{};
    UserId user_id{};
    ParticipantRole role{ParticipantRole::Member};
    MembershipStatus status{MembershipStatus::Active};
    std::chrono::system_clock::time_point joined_at{};
    std::optional<std::chrono::system_clock::time_point> left_at{std::nullopt};
    uint64_t membership_version{1};

    auto operator<=>(const ConversationParticipantEntity& other) const noexcept = default;
    bool operator==(const ConversationParticipantEntity& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
