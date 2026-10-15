#include "service/in_memory_sequence_allocator.hpp"

namespace securecloud::messaging::service {

std::string InMemorySequenceAllocator::make_key(const domain::ConversationId& conversation_id,
                                                const domain::MessageBucket& message_bucket) {
    return conversation_id.to_string() + ":" + message_bucket.value();
}

uint64_t InMemorySequenceAllocator::allocate_sequence(const domain::ConversationId& conversation_id,
                                                      const domain::MessageBucket& message_bucket) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto key = make_key(conversation_id, message_bucket);
    return ++counters_[key];
}

uint64_t InMemorySequenceAllocator::peek_sequence(const domain::ConversationId& conversation_id,
                                                  const domain::MessageBucket& message_bucket) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto key = make_key(conversation_id, message_bucket);
    auto it = counters_.find(key);
    if (it == counters_.end()) {
        return 0;
    }
    return it->second;
}

void InMemorySequenceAllocator::set_sequence(const domain::ConversationId& conversation_id,
                                             const domain::MessageBucket& message_bucket, uint64_t sequence) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto key = make_key(conversation_id, message_bucket);
    counters_[key] = sequence;
}

} // namespace securecloud::messaging::service
