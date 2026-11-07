#include "application/managers/emergency_manager.hpp"

namespace securecloud::client::application::managers {

EmergencyManager::EmergencyManager(interfaces::ILocalStore& local_store, interfaces::ISecureStorage& secure_storage)
    : local_store_(local_store), secure_storage_(secure_storage) {}

ClientResult<void> EmergencyManager::trigger_emergency_wipe() {
    is_wiped_ = true;
    (void)local_store_.close();
    (void)secure_storage_.delete_secret("session_auth_token");
    (void)secure_storage_.delete_secret("device_private_identity_key");
    return ClientResult<void>::ok();
}

ClientResult<void> EmergencyManager::acknowledge_emergency_message(const domain::ConversationId& conversation_id,
                                                                   const domain::MessageId& message_id,
                                                                   const domain::UserId& /*acknowledger_user_id*/) {
    if (conversation_id.empty() || message_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Conversation ID and Message ID required"));
    }

    auto msg_res = local_store_.get_message(conversation_id, message_id);
    if (msg_res.is_error()) {
        return ClientResult<void>::error(msg_res.error());
    }

    auto msg = msg_res.value();
    msg.set_emergency_acknowledged(true);
    return local_store_.update_message(msg);
}

size_t EmergencyManager::unacknowledged_emergency_count(const domain::ConversationId& conversation_id) {
    if (conversation_id.empty()) {
        return 0;
    }

    const auto msgs_res = local_store_.get_messages(conversation_id, 0);
    if (msgs_res.is_error()) {
        return 0;
    }

    size_t count = 0;
    for (const auto& msg : msgs_res.value()) {
        // priority 2 is Emergency (0: Normal, 1: Urgent, 2: Emergency)
        if (msg.priority() >= 2 && !msg.emergency_acknowledged()) {
            count++;
        }
    }
    return count;
}

} // namespace securecloud::client::application::managers
