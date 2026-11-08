#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/delivery_state.hpp"
#include "domain/message.hpp"
#include "domain/message_id.hpp"
#include "domain/user_id.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::application::managers {

class MessagingManager {
  public:
    MessagingManager(interfaces::IGatewayClient& gateway, interfaces::ILocalStore& local_store,
                     interfaces::ICryptoProvider& crypto_provider);
    ~MessagingManager() = default;

    MessagingManager(const MessagingManager&) = delete;
    MessagingManager& operator=(const MessagingManager&) = delete;

    // Direct and Group Conversations
    ClientResult<domain::Conversation> open_direct_conversation(const domain::UserId& local_user,
                                                                const domain::UserId& peer_user,
                                                                const std::string& title = "");
    ClientResult<domain::Conversation> create_group_conversation(const domain::UserId& creator,
                                                                 const std::string& title,
                                                                 const std::vector<domain::UserId>& participants);
    ClientResult<std::vector<domain::Conversation>> list_conversations();
    ClientResult<domain::Conversation> get_conversation(const domain::ConversationId& conversation_id);
    ClientResult<void> add_group_participant(const domain::ConversationId& conversation_id,
                                             const domain::UserId& user_id);
    ClientResult<void> remove_group_participant(const domain::ConversationId& conversation_id,
                                                const domain::UserId& user_id);
    ClientResult<void> leave_conversation(const domain::ConversationId& conversation_id,
                                          const domain::UserId& local_user_id);
    ClientResult<void> delete_conversation(const domain::ConversationId& conversation_id);
    ClientResult<void> mark_conversation_read(const domain::ConversationId& conversation_id);

    // Message Submission, ADR-008 Guard & Delivery Lifecycle
    ClientResult<domain::Message> send_message(const domain::ConversationId& conversation_id,
                                               const domain::UserId& sender_user_id,
                                               const domain::DeviceId& sender_device_id,
                                               const domain::DeviceId& recipient_device_id, std::string_view plaintext);

    ClientResult<domain::Message>
    stage_outbound_message(const domain::ConversationId& conversation_id, const domain::UserId& sender_user_id,
                           const domain::DeviceId& sender_device_id, std::string_view plaintext, int32_t priority = 0,
                           const std::string& sender_display_name = "", const std::string& attachment_name = "",
                           int64_t attachment_size = 0, const std::string& attachment_hash = "");

    ClientResult<domain::Message> retry_failed_message(const domain::ConversationId& conversation_id,
                                                       const domain::MessageId& message_id);

    ClientResult<void> update_message_delivery_state(const domain::ConversationId& conversation_id,
                                                     const domain::MessageId& message_id,
                                                     domain::DeliveryState new_state);

    ClientResult<void> discard_failed_message(const domain::ConversationId& conversation_id,
                                              const domain::MessageId& message_id);

    ClientResult<std::vector<domain::Message>> get_conversation_messages(const domain::ConversationId& conversation_id,
                                                                         std::size_t limit = 50);

  private:
    interfaces::IGatewayClient& gateway_;
    interfaces::ILocalStore& local_store_;
    interfaces::ICryptoProvider& crypto_provider_;
};

} // namespace securecloud::client::application::managers
