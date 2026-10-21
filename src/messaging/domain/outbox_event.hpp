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
    MessageSent,
    MessageDelivered,
};

[[nodiscard]] inline std::string to_string(ConversationOutboxEventType type) {
    switch (type) {
    case ConversationOutboxEventType::ConversationCreated:
        return "ConversationCreated";
    case ConversationOutboxEventType::ParticipantJoined:
        return "ParticipantJoined";
    case ConversationOutboxEventType::ParticipantLeft:
        return "ParticipantLeft";
    case ConversationOutboxEventType::ParticipantRemoved:
        return "ParticipantRemoved";
    case ConversationOutboxEventType::GroupMetadataUpdated:
        return "GroupMetadataUpdated";
    case ConversationOutboxEventType::ConversationClosed:
        return "ConversationClosed";
    case ConversationOutboxEventType::MessageSent:
        return "MessageSent";
    case ConversationOutboxEventType::MessageDelivered:
        return "MessageDelivered";
    }
    return "ConversationCreated";
}

[[nodiscard]] inline std::optional<ConversationOutboxEventType>
conversation_outbox_event_type_from_string(std::string_view sv) noexcept {
    if (sv == "ConversationCreated") {
        return ConversationOutboxEventType::ConversationCreated;
    }
    if (sv == "ParticipantJoined") {
        return ConversationOutboxEventType::ParticipantJoined;
    }
    if (sv == "ParticipantLeft") {
        return ConversationOutboxEventType::ParticipantLeft;
    }
    if (sv == "ParticipantRemoved") {
        return ConversationOutboxEventType::ParticipantRemoved;
    }
    if (sv == "GroupMetadataUpdated") {
        return ConversationOutboxEventType::GroupMetadataUpdated;
    }
    if (sv == "ConversationClosed") {
        return ConversationOutboxEventType::ConversationClosed;
    }
    if (sv == "MessageSent") {
        return ConversationOutboxEventType::MessageSent;
    }
    if (sv == "MessageDelivered") {
        return ConversationOutboxEventType::MessageDelivered;
    }
    return std::nullopt;
}

/// Strongly-typed outbox domain event captured transactionally
/// for asynchronous event distribution without dual-write inconsistency.
struct ConversationOutboxEvent {
    std::string event_id;
    ConversationId conversation_id;
    ConversationOutboxEventType event_type{ConversationOutboxEventType::ConversationCreated};
    std::string payload_json;
    std::chrono::system_clock::time_point created_at;

    auto operator<=>(const ConversationOutboxEvent& other) const noexcept = default;
    bool operator==(const ConversationOutboxEvent& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
