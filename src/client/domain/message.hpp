#pragma once

#include "domain/conversation_id.hpp"
#include "domain/delivery_state.hpp"
#include "domain/device_id.hpp"
#include "domain/message_id.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace securecloud::client::domain {

class Message {
  public:
    Message() = default;
    Message(MessageId message_id, ConversationId conversation_id, UserId sender_user_id, DeviceId sender_device_id,
            DeliveryState delivery_state = DeliveryState::LocalPending,
            std::chrono::system_clock::time_point sent_at = std::chrono::system_clock::now(),
            std::string encrypted_envelope_ref = "", int32_t priority = 0);

    [[nodiscard]] const MessageId& message_id() const noexcept { return message_id_; }
    [[nodiscard]] const ConversationId& conversation_id() const noexcept { return conversation_id_; }
    [[nodiscard]] const UserId& sender_user_id() const noexcept { return sender_user_id_; }
    [[nodiscard]] const DeviceId& sender_device_id() const noexcept { return sender_device_id_; }
    [[nodiscard]] DeliveryState delivery_state() const noexcept { return delivery_state_; }
    [[nodiscard]] std::chrono::system_clock::time_point sent_at() const noexcept { return sent_at_; }
    [[nodiscard]] const std::string& encrypted_envelope_ref() const noexcept { return encrypted_envelope_ref_; }
    [[nodiscard]] int32_t priority() const noexcept { return priority_; }

    void set_delivery_state(DeliveryState state) noexcept { delivery_state_ = state; }
    void set_encrypted_envelope_ref(std::string envelope_ref) { encrypted_envelope_ref_ = std::move(envelope_ref); }
    void set_priority(int32_t priority) noexcept { priority_ = priority; }

    bool operator==(const Message& other) const noexcept;
    bool operator!=(const Message& other) const noexcept { return !(*this == other); }

  private:
    MessageId message_id_;
    ConversationId conversation_id_;
    UserId sender_user_id_;
    DeviceId sender_device_id_;
    DeliveryState delivery_state_{DeliveryState::LocalPending};
    std::chrono::system_clock::time_point sent_at_{std::chrono::system_clock::now()};
    std::string encrypted_envelope_ref_;
    int32_t priority_{0};
};

} // namespace securecloud::client::domain
