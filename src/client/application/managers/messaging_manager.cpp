#include "application/managers/messaging_manager.hpp"

#include <chrono>

namespace securecloud::client::application::managers {

MessagingManager::MessagingManager(interfaces::IGatewayClient& gateway, interfaces::ILocalStore& local_store,
                                   interfaces::ICryptoProvider& crypto_provider)
    : gateway_(gateway), local_store_(local_store), crypto_provider_(crypto_provider) {}

ClientResult<domain::Message> MessagingManager::send_message(const domain::ConversationId& conversation_id,
                                                             const domain::UserId& sender_user_id,
                                                             const domain::DeviceId& sender_device_id,
                                                             const domain::DeviceId& recipient_device_id,
                                                             std::string_view plaintext) {
    if (conversation_id.empty()) {
        return ClientResult<domain::Message>::error(ClientError::validation("Conversation ID cannot be empty"));
    }

    const auto encrypt_res = crypto_provider_.encrypt_message(recipient_device_id, plaintext);
    if (encrypt_res.is_error()) {
        return ClientResult<domain::Message>::error(encrypt_res.error());
    }

    const auto send_res = gateway_.send_message(conversation_id, encrypt_res.value());
    if (send_res.is_error()) {
        return ClientResult<domain::Message>::error(send_res.error());
    }

    const domain::MessageId mid(send_res.value());
    domain::Message msg(mid, conversation_id, sender_user_id, sender_device_id, domain::DeliveryState::Accepted,
                        std::chrono::system_clock::now(), encrypt_res.value(), 0);

    const auto save_res = local_store_.save_message(msg);
    if (save_res.is_error()) {
        return ClientResult<domain::Message>::error(save_res.error());
    }

    return ClientResult<domain::Message>::ok(std::move(msg));
}

ClientResult<std::vector<domain::Message>>
MessagingManager::get_conversation_messages(const domain::ConversationId& conversation_id, std::size_t limit) {
    return local_store_.get_messages(conversation_id, limit);
}

} // namespace securecloud::client::application::managers
