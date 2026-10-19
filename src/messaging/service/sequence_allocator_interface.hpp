#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_bucket.hpp"

#include <cstdint>

namespace securecloud::messaging::service {

/**
 * @brief Abstract interface for monotonic per-conversation message sequence allocation.
 *
 * Each conversation maintains a strictly increasing sequence counter within its
 * monthly partition ((conversation_id, message_bucket)). Sequence numbers start at 1
 * and increase monotonically without gaps or duplicates under concurrency.
 */
class ISequenceAllocator {
  public:
    virtual ~ISequenceAllocator() = default;

    /**
     * @brief Atomically allocates and returns the next sequence number (starting at 1)
     * for the given conversation in the specified monthly message bucket.
     *
     * @param conversation_id The target conversation.
     * @param message_bucket The monthly UTC message bucket (YYYYMM).
     * @return The next strictly monotonic sequence number.
     */
    [[nodiscard]] virtual uint64_t allocate_sequence(const domain::ConversationId& conversation_id,
                                                     const domain::MessageBucket& message_bucket) = 0;

    /**
     * @brief Inspects the currently allocated sequence number without incrementing it.
     *
     * @param conversation_id The target conversation.
     * @param message_bucket The monthly UTC message bucket (YYYYMM).
     * @return The current sequence number, or 0 if no messages have been allocated.
     */
    [[nodiscard]] virtual uint64_t peek_sequence(const domain::ConversationId& conversation_id,
                                                 const domain::MessageBucket& message_bucket) = 0;
};

} // namespace securecloud::messaging::service
