#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/message_types.hpp"

#include <chrono>
#include <compare>
#include <string>
#include <vector>

namespace securecloud::messaging::domain {

/// Authoritative Domain Entity representing an immutable message stored in ScyllaDB.
/// Matches the schema of securecloud_messaging.messages_by_conversation:
/// - Partition Key: ((conversation_id, message_bucket))
/// - Clustering Key: message_sequence ASC, message_id ASC
struct MessageEntity {
    ConversationId conversation_id;
    MessageBucket message_bucket;
    MessageSequence message_sequence{0};
    MessageId message_id;
    UserId sender_user_id;
    DeviceId sender_device_id;
    MessagePriority priority{MessagePriority::Normal};
    std::chrono::system_clock::time_point accepted_at;
    CiphertextEnvelope envelope;
    std::vector<std::string> file_reference_ids;

    auto operator<=>(const MessageEntity& other) const noexcept = default;
    bool operator==(const MessageEntity& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
