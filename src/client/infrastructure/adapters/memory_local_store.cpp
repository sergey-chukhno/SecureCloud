#include "infrastructure/adapters/memory_local_store.hpp"

#include <algorithm>

namespace securecloud::client::infrastructure::adapters {

application::ClientResult<void> MemoryLocalStore::open(std::string_view /*path*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    is_open_ = true;
    return application::ClientResult<void>::ok();
}

application::ClientResult<void> MemoryLocalStore::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    is_open_ = false;
    return application::ClientResult<void>::ok();
}

application::ClientResult<void> MemoryLocalStore::save_conversation(const domain::Conversation& conversation) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    conversations_[conversation.conversation_id()] = conversation;
    return application::ClientResult<void>::ok();
}

application::ClientResult<domain::Conversation> MemoryLocalStore::get_conversation(const domain::ConversationId& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<domain::Conversation>::error(
            application::ClientError::storage("Storage is closed"));
    }
    const auto it = conversations_.find(id);
    if (it == conversations_.end()) {
        return application::ClientResult<domain::Conversation>::error(
            application::ClientError::storage("Conversation not found"));
    }
    return application::ClientResult<domain::Conversation>::ok(it->second);
}

application::ClientResult<std::vector<domain::Conversation>> MemoryLocalStore::list_conversations() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<std::vector<domain::Conversation>>::error(
            application::ClientError::storage("Storage is closed"));
    }
    std::vector<domain::Conversation> result;
    result.reserve(conversations_.size());
    for (const auto& [_, conv] : conversations_) {
        result.push_back(conv);
    }
    return application::ClientResult<std::vector<domain::Conversation>>::ok(std::move(result));
}

application::ClientResult<void> MemoryLocalStore::save_message(const domain::Message& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    messages_[message.conversation_id()].push_back(message);
    return application::ClientResult<void>::ok();
}

application::ClientResult<std::vector<domain::Message>> MemoryLocalStore::get_messages(const domain::ConversationId& id,
                                                                                       std::size_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<std::vector<domain::Message>>::error(
            application::ClientError::storage("Storage is closed"));
    }
    const auto it = messages_.find(id);
    if (it == messages_.end()) {
        return application::ClientResult<std::vector<domain::Message>>::ok(std::vector<domain::Message>{});
    }

    const auto& all = it->second;
    const std::size_t count = (limit > 0 && limit < all.size()) ? limit : all.size();
    std::vector<domain::Message> result(all.begin(), all.begin() + static_cast<std::ptrdiff_t>(count));
    return application::ClientResult<std::vector<domain::Message>>::ok(std::move(result));
}

application::ClientResult<void> MemoryLocalStore::save_contact(const domain::Contact& contact) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    contacts_[contact.user_id()] = contact;
    return application::ClientResult<void>::ok();
}

application::ClientResult<std::vector<domain::Contact>> MemoryLocalStore::list_contacts() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<std::vector<domain::Contact>>::error(
            application::ClientError::storage("Storage is closed"));
    }
    std::vector<domain::Contact> result;
    result.reserve(contacts_.size());
    for (const auto& [_, contact] : contacts_) {
        result.push_back(contact);
    }
    return application::ClientResult<std::vector<domain::Contact>>::ok(std::move(result));
}

void MemoryLocalStore::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    conversations_.clear();
    messages_.clear();
    contacts_.clear();
}

} // namespace securecloud::client::infrastructure::adapters
