#include "domain/message.hpp"

#include <nlohmann/json.hpp>
#include <utility>

namespace securecloud::client::domain {

Message::Message(MessageId message_id, ConversationId conversation_id, UserId sender_user_id, DeviceId sender_device_id,
                 DeliveryState delivery_state, std::chrono::system_clock::time_point sent_at,
                 std::string encrypted_envelope_ref, int32_t priority)
    : message_id_(std::move(message_id)), conversation_id_(std::move(conversation_id)),
      sender_user_id_(std::move(sender_user_id)), sender_device_id_(std::move(sender_device_id)),
      delivery_state_(delivery_state), sent_at_(sent_at), encrypted_envelope_ref_(std::move(encrypted_envelope_ref)),
      priority_(priority) {}

Message::Message(MessageId message_id, ConversationId conversation_id, UserId sender_user_id, DeviceId sender_device_id,
                 DeliveryState delivery_state, std::chrono::system_clock::time_point sent_at,
                 std::string encrypted_envelope_ref, int32_t priority, std::string sender_display_name,
                 std::string idempotency_key, bool emergency_acknowledged, std::string attachment_name,
                 int64_t attachment_size, std::string attachment_hash)
    : message_id_(std::move(message_id)), conversation_id_(std::move(conversation_id)),
      sender_user_id_(std::move(sender_user_id)), sender_device_id_(std::move(sender_device_id)),
      delivery_state_(delivery_state), sent_at_(sent_at), encrypted_envelope_ref_(std::move(encrypted_envelope_ref)),
      priority_(priority), sender_display_name_(std::move(sender_display_name)),
      idempotency_key_(std::move(idempotency_key)), emergency_acknowledged_(emergency_acknowledged),
      attachment_name_(std::move(attachment_name)), attachment_size_(attachment_size),
      attachment_hash_(std::move(attachment_hash)) {}

std::string Message::client_message_id() const {
    return idempotency_key_.empty() ? message_id_.value() : idempotency_key_;
}

std::string Message::to_json() const {
    nlohmann::json j;
    j["message_id"] = message_id_.value();
    j["conversation_id"] = conversation_id_.value();
    j["sender_user_id"] = sender_user_id_.str();
    j["sender_device_id"] = sender_device_id_.str();
    j["delivery_state"] = std::string(to_string(delivery_state_));
    j["sent_at_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(sent_at_.time_since_epoch()).count();
    j["encrypted_envelope_ref"] = encrypted_envelope_ref_;
    j["priority"] = priority_;
    j["sender_display_name"] = sender_display_name_;
    j["idempotency_key"] = idempotency_key_;
    j["emergency_acknowledged"] = emergency_acknowledged_;
    j["attachment_name"] = attachment_name_;
    j["attachment_size"] = attachment_size_;
    j["attachment_hash"] = attachment_hash_;
    j["server_sequence_number"] = server_sequence_number_;
    j["expires_at_ms"] = expires_at_ms_;
    if (sender_key_epoch_.has_value()) {
        j["sender_key_epoch"] = *sender_key_epoch_;
    } else {
        j["sender_key_epoch"] = nullptr;
    }
    return j.dump();
}

std::optional<Message> Message::from_json(std::string_view json_str) {
    try {
        const auto j = nlohmann::json::parse(json_str);
        if (!j.is_object() || !j.contains("message_id") || !j["message_id"].is_string() ||
            !j.contains("conversation_id") || !j["conversation_id"].is_string() || !j.contains("sender_user_id") ||
            !j["sender_user_id"].is_string() || !j.contains("sender_device_id") || !j["sender_device_id"].is_string()) {
            return std::nullopt;
        }

        const std::string mid_str = j["message_id"].get<std::string>();
        const std::string cid_str = j["conversation_id"].get<std::string>();
        const std::string sender_uid_str = j["sender_user_id"].get<std::string>();
        const std::string sender_did_str = j["sender_device_id"].get<std::string>();
        if (mid_str.empty() || cid_str.empty() || sender_uid_str.empty() || sender_did_str.empty()) {
            return std::nullopt;
        }

        const MessageId mid(mid_str);
        const ConversationId cid(cid_str);
        const UserId sender_uid(sender_uid_str);
        const DeviceId sender_did(sender_did_str);

        const auto state_opt = delivery_state_from_string(j.value("delivery_state", "LocalPending"));
        if (!state_opt.has_value()) {
            return std::nullopt;
        }

        auto sent_at = std::chrono::system_clock::now();
        if (j.contains("sent_at_ms") && j["sent_at_ms"].is_number_integer()) {
            sent_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(j["sent_at_ms"].get<int64_t>()));
        }

        Message msg(mid, cid, sender_uid, sender_did, *state_opt, sent_at, j.value("encrypted_envelope_ref", ""),
                    j.value("priority", 0), j.value("sender_display_name", ""), j.value("idempotency_key", ""),
                    j.value("emergency_acknowledged", false), j.value("attachment_name", ""),
                    j.value("attachment_size", int64_t{0}), j.value("attachment_hash", ""));

        if (j.contains("server_sequence_number") && j["server_sequence_number"].is_number_unsigned()) {
            msg.set_server_sequence_number(j["server_sequence_number"].get<uint64_t>());
        }
        if (j.contains("sender_key_epoch") && j["sender_key_epoch"].is_number_unsigned()) {
            msg.set_sender_key_epoch(j["sender_key_epoch"].get<uint64_t>());
        }
        if (j.contains("expires_at_ms")) {
            if (!j["expires_at_ms"].is_number_integer()) {
                return std::nullopt;
            }
            msg.set_expires_at_ms(j["expires_at_ms"].get<int64_t>());
        }

        return msg;
    } catch (...) {
        return std::nullopt;
    }
}

bool Message::operator==(const Message& other) const noexcept {
    return message_id_ == other.message_id_ && conversation_id_ == other.conversation_id_ &&
           sender_user_id_ == other.sender_user_id_ && sender_device_id_ == other.sender_device_id_ &&
           delivery_state_ == other.delivery_state_ && priority_ == other.priority_ &&
           sender_display_name_ == other.sender_display_name_ && idempotency_key_ == other.idempotency_key_ &&
           emergency_acknowledged_ == other.emergency_acknowledged_ &&
           server_sequence_number_ == other.server_sequence_number_ && sender_key_epoch_ == other.sender_key_epoch_ &&
           expires_at_ms_ == other.expires_at_ms_;
}

} // namespace securecloud::client::domain
