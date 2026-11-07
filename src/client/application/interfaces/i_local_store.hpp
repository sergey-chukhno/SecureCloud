#pragma once

#include "application/client_error.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/message.hpp"
#include "domain/message_id.hpp"
#include "domain/user_id.hpp"

#include <cstddef>
#include <string_view>
#include <vector>

namespace securecloud::client::application::interfaces {

class ILocalStore {
  public:
    virtual ~ILocalStore() = default;

    virtual ClientResult<void> open(std::string_view path) = 0;
    virtual ClientResult<void> close() = 0;

    virtual ClientResult<void> save_conversation(const domain::Conversation& conversation) = 0;
    virtual ClientResult<domain::Conversation> get_conversation(const domain::ConversationId& id) = 0;
    virtual ClientResult<std::vector<domain::Conversation>> list_conversations() = 0;
    virtual ClientResult<void> delete_conversation(const domain::ConversationId& id) = 0;

    virtual ClientResult<void> save_message(const domain::Message& message) = 0;
    virtual ClientResult<std::vector<domain::Message>> get_messages(const domain::ConversationId& id,
                                                                    std::size_t limit) = 0;
    virtual ClientResult<domain::Message> get_message(const domain::ConversationId& conversation_id,
                                                      const domain::MessageId& message_id) = 0;
    virtual ClientResult<void> update_message(const domain::Message& message) = 0;

    virtual ClientResult<void> save_contact(const domain::Contact& contact) = 0;
    virtual ClientResult<domain::Contact> get_contact(const domain::UserId& user_id) = 0;
    virtual ClientResult<std::vector<domain::Contact>> list_contacts() = 0;
    virtual ClientResult<void> delete_contact(const domain::UserId& user_id) = 0;
};

} // namespace securecloud::client::application::interfaces
