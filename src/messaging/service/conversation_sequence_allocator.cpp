#include "service/conversation_sequence_allocator.hpp"

#include <functional>
#include <stdexcept>

namespace securecloud::messaging::service {

ConversationSequenceAllocator::ConversationSequenceAllocator(
    std::shared_ptr<repository::IMessageRepository> message_repo)
    : message_repo_(std::move(message_repo)) {
    if (!message_repo_) {
        throw std::invalid_argument("ConversationSequenceAllocator requires non-null IMessageRepository");
    }
}

std::string ConversationSequenceAllocator::make_key(const domain::ConversationId& conversation_id,
                                                    const domain::MessageBucket& message_bucket) {
    return conversation_id.to_string() + ":" + message_bucket.value();
}

std::size_t ConversationSequenceAllocator::get_stripe_index(const std::string& key) noexcept {
    return std::hash<std::string>{}(key) % kNumStripes;
}

uint64_t ConversationSequenceAllocator::allocate_sequence(const domain::ConversationId& conversation_id,
                                                          const domain::MessageBucket& message_bucket) {
    const auto key = make_key(conversation_id, message_bucket);
    auto& stripe = stripes_[get_stripe_index(key)];
    std::lock_guard<std::mutex> lock(stripe.mtx);

    auto it = stripe.counters.find(key);
    if (it == stripe.counters.end()) {
        uint64_t last_seq = message_repo_->get_last_sequence(conversation_id, message_bucket);
        stripe.counters[key] = last_seq;
        it = stripe.counters.find(key);
    }

    return ++(it->second);
}

uint64_t ConversationSequenceAllocator::peek_sequence(const domain::ConversationId& conversation_id,
                                                      const domain::MessageBucket& message_bucket) {
    const auto key = make_key(conversation_id, message_bucket);
    auto& stripe = stripes_[get_stripe_index(key)];
    std::lock_guard<std::mutex> lock(stripe.mtx);

    auto it = stripe.counters.find(key);
    if (it == stripe.counters.end()) {
        uint64_t last_seq = message_repo_->get_last_sequence(conversation_id, message_bucket);
        stripe.counters[key] = last_seq;
        return last_seq;
    }

    return it->second;
}

void ConversationSequenceAllocator::invalidate(const domain::ConversationId& conversation_id,
                                               const domain::MessageBucket& message_bucket) {
    const auto key = make_key(conversation_id, message_bucket);
    auto& stripe = stripes_[get_stripe_index(key)];
    std::lock_guard<std::mutex> lock(stripe.mtx);
    stripe.counters.erase(key);
}

void ConversationSequenceAllocator::clear() {
    for (auto& stripe : stripes_) {
        std::lock_guard<std::mutex> lock(stripe.mtx);
        stripe.counters.clear();
    }
}

} // namespace securecloud::messaging::service
