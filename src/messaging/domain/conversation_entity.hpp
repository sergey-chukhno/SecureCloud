#pragma once

#include "domain/conversation_types.hpp"

#include <chrono>
#include <cstdint>

namespace securecloud::messaging::domain {

/// Canonical in-memory domain entity representing a conversation.
struct ConversationEntity {
    ConversationId conversation_id{};
    ConversationType type{ConversationType::Direct};
    UserId created_by_user_id{};
    std::chrono::system_clock::time_point created_at{};
    uint64_t metadata_version{1};

    auto operator<=>(const ConversationEntity& other) const noexcept = default;
    bool operator==(const ConversationEntity& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
