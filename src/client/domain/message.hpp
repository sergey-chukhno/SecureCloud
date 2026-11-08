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

    Message(MessageId message_id, ConversationId conversation_id, UserId sender_user_id, DeviceId sender_device_id,
            DeliveryState delivery_state, std::chrono::system_clock::time_point sent_at,
            std::string encrypted_envelope_ref, int32_t priority, std::string sender_display_name,
            std::string idempotency_key = "", bool emergency_acknowledged = false, std::string attachment_name = "",
            int64_t attachment_size = 0, std::string attachment_hash = "");

    [[nodiscard]] const MessageId& message_id() const noexcept { return message_id_; }
    [[nodiscard]] const ConversationId& conversation_id() const noexcept { return conversation_id_; }
    [[nodiscard]] const UserId& sender_user_id() const noexcept { return sender_user_id_; }
    [[nodiscard]] const DeviceId& sender_device_id() const noexcept { return sender_device_id_; }
    [[nodiscard]] DeliveryState delivery_state() const noexcept { return delivery_state_; }
    [[nodiscard]] std::chrono::system_clock::time_point sent_at() const noexcept { return sent_at_; }
    [[nodiscard]] const std::string& encrypted_envelope_ref() const noexcept { return encrypted_envelope_ref_; }
    [[nodiscard]] int32_t priority() const noexcept { return priority_; }
    [[nodiscard]] const std::string& sender_display_name() const noexcept { return sender_display_name_; }
    [[nodiscard]] const std::string& idempotency_key() const noexcept { return idempotency_key_; }
    [[nodiscard]] bool emergency_acknowledged() const noexcept { return emergency_acknowledged_; }
    [[nodiscard]] const std::string& attachment_name() const noexcept { return attachment_name_; }
    [[nodiscard]] int64_t attachment_size() const noexcept { return attachment_size_; }
    [[nodiscard]] const std::string& attachment_hash() const noexcept { return attachment_hash_; }

    void set_delivery_state(DeliveryState state) noexcept { delivery_state_ = state; }
    void set_encrypted_envelope_ref(std::string envelope_ref) { encrypted_envelope_ref_ = std::move(envelope_ref); }
    void set_priority(int32_t priority) noexcept { priority_ = priority; }
    void set_sender_display_name(std::string name) { sender_display_name_ = std::move(name); }
    void set_idempotency_key(std::string key) { idempotency_key_ = std::move(key); }
    void set_emergency_acknowledged(bool acknowledged) noexcept { emergency_acknowledged_ = acknowledged; }
    void set_attachment(std::string name, int64_t size, std::string hash) {
        attachment_name_ = std::move(name);
        attachment_size_ = size;
        attachment_hash_ = std::move(hash);
    }

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
    std::string sender_display_name_;
    std::string idempotency_key_;
    bool emergency_acknowledged_{false};
    std::string attachment_name_;
    int64_t attachment_size_{0};
    std::string attachment_hash_;
};

} // namespace securecloud::client::domain
