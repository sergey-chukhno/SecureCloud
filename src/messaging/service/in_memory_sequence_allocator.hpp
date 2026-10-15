#pragma once

#include "service/sequence_allocator_interface.hpp"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace securecloud::messaging::service {

/**
 * @brief Thread-safe in-memory sequence allocator.
 * Useful for standalone unit testing, benchmarks, and isolated environments.
 */
class InMemorySequenceAllocator : public ISequenceAllocator {
  public:
    InMemorySequenceAllocator() = default;

    [[nodiscard]] uint64_t allocate_sequence(const domain::ConversationId& conversation_id,
                                             const domain::MessageBucket& message_bucket) override;

    [[nodiscard]] uint64_t peek_sequence(const domain::ConversationId& conversation_id,
                                         const domain::MessageBucket& message_bucket) override;

    void set_sequence(const domain::ConversationId& conversation_id, const domain::MessageBucket& message_bucket,
                      uint64_t sequence);

  private:
    [[nodiscard]] static std::string make_key(const domain::ConversationId& conversation_id,
                                              const domain::MessageBucket& message_bucket);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, uint64_t> counters_;
};

} // namespace securecloud::messaging::service
