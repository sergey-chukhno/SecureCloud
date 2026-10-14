#pragma once

#include "domain/conversation_types.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace securecloud::messaging::domain {

/// Domain entity representing specific metadata for group conversations.
struct GroupMetadataEntity {
    ConversationId conversation_id{};
    std::string title{};
    GroupStatus status{GroupStatus::Active};
    std::chrono::system_clock::time_point created_at{};
    std::chrono::system_clock::time_point updated_at{};
    uint64_t metadata_version{1};

    auto operator<=>(const GroupMetadataEntity& other) const noexcept = default;
    bool operator==(const GroupMetadataEntity& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
