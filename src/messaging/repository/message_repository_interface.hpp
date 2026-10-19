#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/message_entity.hpp"
#include "domain/message_types.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace securecloud::messaging::repository {

/// Abstract repository contract for immutable message persistence.
/// Conforms to ScyllaDB access patterns (ADR-007, 03-messaging-data-model.md):
/// - Table: securecloud_messaging.messages_by_conversation
/// - Partition Key: ((conversation_id, message_bucket))
/// - Clustering Key: message_sequence ASC, message_id ASC
class IMessageRepository {
  public:
    virtual ~IMessageRepository() = default;

    /// Persists an immutable message into messages_by_conversation.
    virtual void save_message(const domain::MessageEntity& msg) = 0;

    /// Retrieves a specific message by its partition key ((conversation_id, message_bucket)) and message_id.
    [[nodiscard]] virtual std::optional<domain::MessageEntity> find_by_id(const domain::ConversationId& conversation_id,
                                                                          const domain::MessageBucket& message_bucket,
                                                                          const domain::MessageId& message_id) = 0;

    /// Chronological range query over sequence numbers within a conversation and monthly bucket.
    [[nodiscard]] virtual std::vector<domain::MessageEntity>
    list_messages_by_sequence_range(const domain::ConversationId& conversation_id,
                                    const domain::MessageBucket& message_bucket, uint64_t from_sequence,
                                    uint64_t to_sequence, size_t limit) = 0;

    /// Queries the highest allocated sequence number in a conversation bucket (returns 0 if empty).
    [[nodiscard]] virtual uint64_t get_last_sequence(const domain::ConversationId& conversation_id,
                                                     const domain::MessageBucket& message_bucket) = 0;
};

} // namespace securecloud::messaging::repository
