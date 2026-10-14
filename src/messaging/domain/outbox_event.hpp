#pragma once

#include "domain/conversation_types.hpp"

#include <chrono>
#include <string>

namespace securecloud::messaging::domain {

/// Classification of conversation outbox domain events.
enum class ConversationOutboxEventType {
    ConversationCreated,
    ParticipantJoined,
    ParticipantLeft,
    ParticipantRemoved,
    GroupMetadataUpdated,
    ConversationClosed,
};

/// Strongly-typed outbox domain event captured transactionally
/// for asynchronous event distribution without dual-write inconsistency.
struct ConversationOutboxEvent {
    std::string event_id;
    ConversationId conversation_id;
    ConversationOutboxEventType event_type;
    std::string payload_json;
    std::chrono::system_clock::time_point created_at;

    auto operator<=>(const ConversationOutboxEvent& other) const noexcept = default;
    bool operator==(const ConversationOutboxEvent& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
