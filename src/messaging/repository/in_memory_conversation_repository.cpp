#include "repository/in_memory_conversation_repository.hpp"

#include <mutex>

namespace securecloud::messaging::repository {

void InMemoryConversationRepository::save_conversation(const domain::ConversationEntity& conv) {
    std::lock_guard<std::mutex> lock(mutex_);
    conversations_[conv.conversation_id] = conv;
}

std::optional<domain::ConversationEntity>
InMemoryConversationRepository::find_conversation_by_id(const domain::ConversationId& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = conversations_.find(id);
    if (it != conversations_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<domain::ConversationId>
InMemoryConversationRepository::find_direct_conversation(const domain::DirectPair& pair) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = direct_pairs_.find(pair);
    if (it != direct_pairs_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void InMemoryConversationRepository::save_direct_conversation(const domain::DirectPair& pair,
                                                              const domain::ConversationId& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    direct_pairs_[pair] = id;
}

void InMemoryConversationRepository::save_group_metadata(const domain::GroupMetadataEntity& meta) {
    std::lock_guard<std::mutex> lock(mutex_);
    group_metadata_[meta.conversation_id] = meta;
}

std::optional<domain::GroupMetadataEntity>
InMemoryConversationRepository::find_group_metadata(const domain::ConversationId& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = group_metadata_.find(id);
    if (it != group_metadata_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void InMemoryConversationRepository::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    conversations_.clear();
    direct_pairs_.clear();
    group_metadata_.clear();
}

} // namespace securecloud::messaging::repository
