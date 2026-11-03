#pragma once

#include "application/interfaces/i_local_store.hpp"

#include <mutex>
#include <unordered_map>
#include <vector>

namespace securecloud::client::infrastructure::adapters {

class MemoryLocalStore final : public application::interfaces::ILocalStore {
  public:
    MemoryLocalStore() = default;
    ~MemoryLocalStore() override = default;

    application::ClientResult<void> open(std::string_view path) override;
    application::ClientResult<void> close() override;

    application::ClientResult<void> save_conversation(const domain::Conversation& conversation) override;
    application::ClientResult<domain::Conversation> get_conversation(const domain::ConversationId& id) override;
    application::ClientResult<std::vector<domain::Conversation>> list_conversations() override;

    application::ClientResult<void> save_message(const domain::Message& message) override;
    application::ClientResult<std::vector<domain::Message>> get_messages(const domain::ConversationId& id,
                                                                         std::size_t limit) override;

    application::ClientResult<void> save_contact(const domain::Contact& contact) override;
    application::ClientResult<std::vector<domain::Contact>> list_contacts() override;

    void clear();

  private:
    std::mutex mutex_;
    bool is_open_{true};
    std::unordered_map<domain::ConversationId, domain::Conversation> conversations_;
    std::unordered_map<domain::ConversationId, std::vector<domain::Message>> messages_;
    std::unordered_map<domain::UserId, domain::Contact> contacts_;
};

} // namespace securecloud::client::infrastructure::adapters
