#include "domain/message.hpp"

#include <utility>

namespace securecloud::client::domain {

Message::Message(MessageId message_id, ConversationId conversation_id, UserId sender_user_id, DeviceId sender_device_id,
                 DeliveryState delivery_state, std::chrono::system_clock::time_point sent_at,
                 std::string encrypted_envelope_ref, int32_t priority)
    : message_id_(std::move(message_id)), conversation_id_(std::move(conversation_id)),
      sender_user_id_(std::move(sender_user_id)), sender_device_id_(std::move(sender_device_id)),
      delivery_state_(delivery_state), sent_at_(sent_at), encrypted_envelope_ref_(std::move(encrypted_envelope_ref)),
      priority_(priority) {}

bool Message::operator==(const Message& other) const noexcept {
    return message_id_ == other.message_id_ && conversation_id_ == other.conversation_id_ &&
           sender_user_id_ == other.sender_user_id_ && sender_device_id_ == other.sender_device_id_ &&
           delivery_state_ == other.delivery_state_ && priority_ == other.priority_;
}

} // namespace securecloud::client::domain
