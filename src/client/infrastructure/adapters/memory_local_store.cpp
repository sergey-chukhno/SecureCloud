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

application::ClientResult<void> MemoryLocalStore::delete_conversation(const domain::ConversationId& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    const auto it = conversations_.find(id);
    if (it == conversations_.end()) {
        return application::ClientResult<void>::error(application::ClientError::storage("Conversation not found"));
    }
    conversations_.erase(it);
    messages_.erase(id);
    std::erase_if(file_transfers_, [&id](const auto& entry) { return entry.second.conversation_id == id; });
    return application::ClientResult<void>::ok();
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

application::ClientResult<domain::Message> MemoryLocalStore::get_message(const domain::ConversationId& conversation_id,
                                                                         const domain::MessageId& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<domain::Message>::error(
            application::ClientError::storage("Storage is closed"));
    }
    const auto it = messages_.find(conversation_id);
    if (it == messages_.end()) {
        return application::ClientResult<domain::Message>::error(
            application::ClientError::storage("Message not found"));
    }
    for (const auto& msg : it->second) {
        if (msg.message_id() == message_id) {
            return application::ClientResult<domain::Message>::ok(msg);
        }
    }
    return application::ClientResult<domain::Message>::error(application::ClientError::storage("Message not found"));
}

application::ClientResult<void> MemoryLocalStore::update_message(const domain::Message& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    auto it = messages_.find(message.conversation_id());
    if (it == messages_.end()) {
        return application::ClientResult<void>::error(application::ClientError::storage("Message not found"));
    }
    for (auto& msg : it->second) {
        if (msg.message_id() == message.message_id()) {
            msg = message;
            return application::ClientResult<void>::ok();
        }
    }
    return application::ClientResult<void>::error(application::ClientError::storage("Message not found"));
}

application::ClientResult<void> MemoryLocalStore::save_contact(const domain::Contact& contact) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    contacts_[contact.user_id()] = contact;
    return application::ClientResult<void>::ok();
}

application::ClientResult<domain::Contact> MemoryLocalStore::get_contact(const domain::UserId& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<domain::Contact>::error(
            application::ClientError::storage("Storage is closed"));
    }
    const auto it = contacts_.find(user_id);
    if (it == contacts_.end()) {
        return application::ClientResult<domain::Contact>::error(
            application::ClientError::storage("Contact not found"));
    }
    return application::ClientResult<domain::Contact>::ok(it->second);
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

application::ClientResult<void> MemoryLocalStore::delete_contact(const domain::UserId& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    const auto it = contacts_.find(user_id);
    if (it == contacts_.end()) {
        return application::ClientResult<void>::error(application::ClientError::storage("Contact not found"));
    }
    contacts_.erase(it);
    return application::ClientResult<void>::ok();
}

application::ClientResult<void> MemoryLocalStore::save_file_transfer(const domain::FileTransferRecord& record) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    if (record.transfer_id.empty() || record.file_id.empty() || record.conversation_id.empty()) {
        return application::ClientResult<void>::error(application::ClientError::validation(
            "Transfer ID, file ID, and conversation ID are required for file transfer persistence"));
    }
    file_transfers_[record.transfer_id] = record;
    return application::ClientResult<void>::ok();
}

application::ClientResult<domain::FileTransferRecord>
MemoryLocalStore::get_file_transfer(std::string_view transfer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<domain::FileTransferRecord>::error(
            application::ClientError::storage("Storage is closed"));
    }
    if (transfer_id.empty()) {
        return application::ClientResult<domain::FileTransferRecord>::error(
            application::ClientError::validation("Transfer ID cannot be empty"));
    }
    const auto it = file_transfers_.find(std::string(transfer_id));
    if (it == file_transfers_.end()) {
        return application::ClientResult<domain::FileTransferRecord>::error(
            application::ClientError::storage("File transfer not found"));
    }
    return application::ClientResult<domain::FileTransferRecord>::ok(it->second);
}

application::ClientResult<std::vector<domain::FileTransferRecord>>
MemoryLocalStore::list_file_transfers(const domain::ConversationId& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<std::vector<domain::FileTransferRecord>>::error(
            application::ClientError::storage("Storage is closed"));
    }
    std::vector<domain::FileTransferRecord> result;
    result.reserve(file_transfers_.size());
    for (const auto& [_, rec] : file_transfers_) {
        if (conversation_id.empty() || rec.conversation_id == conversation_id) {
            result.push_back(rec);
        }
    }
    std::sort(result.begin(), result.end(),
              [](const domain::FileTransferRecord& a, const domain::FileTransferRecord& b) {
                  if (a.updated_at_ms != b.updated_at_ms) {
                      return a.updated_at_ms > b.updated_at_ms;
                  }
                  return a.transfer_id < b.transfer_id;
              });
    return application::ClientResult<std::vector<domain::FileTransferRecord>>::ok(std::move(result));
}

application::ClientResult<void> MemoryLocalStore::delete_file_transfer(std::string_view transfer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_open_) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    if (transfer_id.empty()) {
        return application::ClientResult<void>::error(
            application::ClientError::validation("Transfer ID cannot be empty"));
    }
    const auto it = file_transfers_.find(std::string(transfer_id));
    if (it == file_transfers_.end()) {
        return application::ClientResult<void>::error(application::ClientError::storage("File transfer not found"));
    }
    file_transfers_.erase(it);
    return application::ClientResult<void>::ok();
}

void MemoryLocalStore::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    conversations_.clear();
    messages_.clear();
    contacts_.clear();
    file_transfers_.clear();
}

} // namespace securecloud::client::infrastructure::adapters
