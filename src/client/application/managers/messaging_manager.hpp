#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "domain/conversation_id.hpp"
#include "domain/message.hpp"

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

    ClientResult<domain::Message> send_message(const domain::ConversationId& conversation_id,
                                               const domain::UserId& sender_user_id,
                                               const domain::DeviceId& sender_device_id,
                                               const domain::DeviceId& recipient_device_id, std::string_view plaintext);

    ClientResult<std::vector<domain::Message>> get_conversation_messages(const domain::ConversationId& conversation_id,
                                                                         std::size_t limit = 50);

  private:
    interfaces::IGatewayClient& gateway_;
    interfaces::ILocalStore& local_store_;
    interfaces::ICryptoProvider& crypto_provider_;
};

} // namespace securecloud::client::application::managers
