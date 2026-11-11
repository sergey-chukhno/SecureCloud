#include "application/managers/messaging_manager.hpp"

#include "application/managers/ratchet_session_manager.hpp"
#include "domain/crypto/ratchet_models.hpp"

#include <algorithm>
#include <chrono>
#include <random>
#include <span>
#include <sstream>

namespace securecloud::client::application::managers {

namespace {

std::string generate_unique_id(std::string_view prefix) {
    const auto now = std::chrono::system_clock::now().time_since_epoch().count();
    static thread_local std::mt19937_64 rng(1337);
    std::uniform_int_distribution<uint64_t> dist;
    std::ostringstream ss;
    ss << prefix << "-" << now << "-" << (dist(rng) & 0xFFFF);
    return ss.str();
}

} // namespace

MessagingManager::MessagingManager(interfaces::IGatewayClient& gateway, interfaces::ILocalStore& local_store,
                                   interfaces::ICryptoProvider& crypto_provider,
                                   RatchetSessionManager* ratchet_session_manager)
    : gateway_(gateway), local_store_(local_store), crypto_provider_(crypto_provider),
      ratchet_session_manager_(ratchet_session_manager) {}

void MessagingManager::set_ratchet_session_manager(RatchetSessionManager* ratchet_session_manager) noexcept {
    ratchet_session_manager_ = ratchet_session_manager;
}

RatchetSessionManager* MessagingManager::ratchet_session_manager() noexcept {
    return ratchet_session_manager_;
}

ClientResult<domain::Conversation> MessagingManager::open_direct_conversation(const domain::UserId& local_user,
                                                                              const domain::UserId& peer_user,
                                                                              const std::string& title) {
    if (local_user.empty() || peer_user.empty()) {
        return ClientResult<domain::Conversation>::error(
            ClientError::validation("Participants cannot be empty for direct conversation"));
    }

    const std::string min_user =
        (local_user.str() < peer_user.str()) ? std::string(local_user.str()) : std::string(peer_user.str());
    const std::string max_user =
        (local_user.str() < peer_user.str()) ? std::string(peer_user.str()) : std::string(local_user.str());
    const domain::ConversationId cid("direct-" + min_user + "-" + max_user);

    const auto existing_res = local_store_.get_conversation(cid);
    if (existing_res.is_ok()) {
        return existing_res;
    }

    const std::string conv_title = title.empty() ? std::string(peer_user.str()) : title;
    std::vector<domain::UserId> participants = {local_user, peer_user};
    domain::Conversation conv(cid, domain::ConversationType::Direct, conv_title, std::move(participants),
                              std::chrono::system_clock::now(), std::chrono::system_clock::now());

    const auto save_res = local_store_.save_conversation(conv);
    if (save_res.is_error()) {
        return ClientResult<domain::Conversation>::error(save_res.error());
    }
    return ClientResult<domain::Conversation>::ok(std::move(conv));
}

ClientResult<domain::Conversation>
MessagingManager::create_group_conversation(const domain::UserId& creator, const std::string& title,
                                            const std::vector<domain::UserId>& participants) {
    if (creator.empty()) {
        return ClientResult<domain::Conversation>::error(ClientError::validation("Creator user_id cannot be empty"));
    }
    if (title.empty()) {
        return ClientResult<domain::Conversation>::error(ClientError::validation("Group title cannot be empty"));
    }

    std::vector<domain::UserId> all_participants;
    all_participants.push_back(creator);
    for (const auto& p : participants) {
        if (!p.empty() && std::find(all_participants.begin(), all_participants.end(), p) == all_participants.end()) {
            all_participants.push_back(p);
        }
    }

    const domain::ConversationId cid(generate_unique_id("group"));
    domain::Conversation conv(cid, domain::ConversationType::Group, title, std::move(all_participants),
                              std::chrono::system_clock::now(), std::chrono::system_clock::now());

    const auto save_res = local_store_.save_conversation(conv);
    if (save_res.is_error()) {
        return ClientResult<domain::Conversation>::error(save_res.error());
    }
    return ClientResult<domain::Conversation>::ok(std::move(conv));
}

ClientResult<std::vector<domain::Conversation>> MessagingManager::list_conversations() {
    return local_store_.list_conversations();
}

ClientResult<domain::Conversation> MessagingManager::get_conversation(const domain::ConversationId& conversation_id) {
    if (conversation_id.empty()) {
        return ClientResult<domain::Conversation>::error(ClientError::validation("Conversation ID cannot be empty"));
    }
    return local_store_.get_conversation(conversation_id);
}

ClientResult<void> MessagingManager::add_group_participant(const domain::ConversationId& conversation_id,
                                                           const domain::UserId& user_id) {
    if (conversation_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Conversation ID cannot be empty"));
    }
    if (user_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("User ID cannot be empty"));
    }

    auto conv_res = local_store_.get_conversation(conversation_id);
    if (conv_res.is_error()) {
        return ClientResult<void>::error(conv_res.error());
    }

    auto conv = conv_res.value();
    if (conv.type() != domain::ConversationType::Group) {
        return ClientResult<void>::error(
            ClientError::validation("Cannot add participants to a non-group conversation"));
    }

    conv.add_participant(user_id);
    conv.set_last_activity_at(std::chrono::system_clock::now());
    return local_store_.save_conversation(conv);
}

ClientResult<void> MessagingManager::remove_group_participant(const domain::ConversationId& conversation_id,
                                                              const domain::UserId& user_id) {
    if (conversation_id.empty() || user_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Conversation ID and User ID cannot be empty"));
    }

    auto conv_res = local_store_.get_conversation(conversation_id);
    if (conv_res.is_error()) {
        return ClientResult<void>::error(conv_res.error());
    }

    auto conv = conv_res.value();
    if (conv.type() != domain::ConversationType::Group) {
        return ClientResult<void>::error(
            ClientError::validation("Cannot remove participants from a non-group conversation"));
    }

    conv.remove_participant(user_id);
    conv.set_last_activity_at(std::chrono::system_clock::now());
    return local_store_.save_conversation(conv);
}

ClientResult<void> MessagingManager::leave_conversation(const domain::ConversationId& conversation_id,
                                                        const domain::UserId& local_user_id) {
    return remove_group_participant(conversation_id, local_user_id);
}

ClientResult<void> MessagingManager::delete_conversation(const domain::ConversationId& conversation_id) {
    if (conversation_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Conversation ID cannot be empty"));
    }
    return local_store_.delete_conversation(conversation_id);
}

ClientResult<void> MessagingManager::mark_conversation_read(const domain::ConversationId& conversation_id) {
    if (conversation_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Conversation ID cannot be empty"));
    }

    auto conv_res = local_store_.get_conversation(conversation_id);
    if (conv_res.is_error()) {
        return ClientResult<void>::error(conv_res.error());
    }

    auto conv = conv_res.value();
    conv.set_unread_count(0);
    return local_store_.save_conversation(conv);
}

ClientResult<domain::Message> MessagingManager::send_message(const domain::ConversationId& conversation_id,
                                                             const domain::UserId& sender_user_id,
                                                             const domain::DeviceId& sender_device_id,
                                                             const domain::DeviceId& recipient_device_id,
                                                             std::string_view plaintext) {
    if (conversation_id.empty()) {
        return ClientResult<domain::Message>::error(ClientError::validation("Conversation ID cannot be empty"));
    }

    std::string ciphertext;
    if (ratchet_session_manager_ != nullptr) {
        domain::UserId peer_user_id;
        auto conv_res = local_store_.get_conversation(conversation_id);
        if (conv_res.is_ok()) {
            for (const auto& p : conv_res.value().participants()) {
                if (p != sender_user_id) {
                    peer_user_id = p;
                    break;
                }
            }
        }
        if (peer_user_id.empty()) {
            peer_user_id = domain::UserId(std::string(recipient_device_id.str()));
        }

        std::span<const uint8_t> pt_bytes(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
        auto enc_res =
            ratchet_session_manager_->encrypt_payload_for_device(peer_user_id, recipient_device_id, pt_bytes);
        if (enc_res.is_error()) {
            return ClientResult<domain::Message>::error(enc_res.error());
        }
        ciphertext = enc_res.value().ciphertext_blob;
    } else {
        const auto encrypt_res = crypto_provider_.encrypt_message(recipient_device_id, plaintext);
        if (encrypt_res.is_error()) {
            return ClientResult<domain::Message>::error(encrypt_res.error());
        }
        ciphertext = encrypt_res.value();
    }

    const auto send_res = gateway_.send_message(conversation_id, ciphertext);
    if (send_res.is_error()) {
        return ClientResult<domain::Message>::error(send_res.error());
    }

    const domain::MessageId mid(send_res.value());
    domain::Message msg(mid, conversation_id, sender_user_id, sender_device_id, domain::DeliveryState::Accepted,
                        std::chrono::system_clock::now(), std::move(ciphertext), 0);

    const auto save_res = local_store_.save_message(msg);
    if (save_res.is_error()) {
        return ClientResult<domain::Message>::error(save_res.error());
    }

    return ClientResult<domain::Message>::ok(std::move(msg));
}

ClientResult<domain::Message>
MessagingManager::stage_outbound_message(const domain::ConversationId& conversation_id,
                                         const domain::UserId& sender_user_id, const domain::DeviceId& sender_device_id,
                                         std::string_view plaintext, int32_t priority,
                                         const std::string& sender_display_name, const std::string& attachment_name,
                                         int64_t attachment_size, const std::string& attachment_hash) {
    if (conversation_id.empty()) {
        return ClientResult<domain::Message>::error(ClientError::validation("Conversation ID cannot be empty"));
    }
    if (sender_user_id.empty()) {
        return ClientResult<domain::Message>::error(ClientError::validation("Sender User ID cannot be empty"));
    }

    // 1. Verify conversation existence and check participants
    auto conv_res = local_store_.get_conversation(conversation_id);
    if (conv_res.is_error()) {
        return ClientResult<domain::Message>::error(conv_res.error());
    }

    const auto& conv = conv_res.value();

    // 2. ADR-008 & Security Guard: Inspect all recipient participants
    for (const auto& participant_id : conv.participants()) {
        if (participant_id == sender_user_id) {
            continue;
        }
        auto contact_res = local_store_.get_contact(participant_id);
        if (contact_res.is_ok()) {
            const auto& contact = contact_res.value();
            if (contact.verification_status() == domain::KeyVerificationStatus::KeyChanged) {
                return ClientResult<domain::Message>::error(
                    ClientError::validation("Outbound messaging suspended: recipient identity key changed (ADR-008)"));
            }
            if (contact.is_blocked()) {
                return ClientResult<domain::Message>::error(
                    ClientError::validation("Cannot send message: recipient is blocked"));
            }
        }
    }

    // If RatchetSessionManager is active, advance Double Ratchet sessions for participants
    if (ratchet_session_manager_ != nullptr) {
        std::span<const uint8_t> pt_bytes(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
        auto fan_res = ratchet_session_manager_->encrypt_fanout_for_participants(conv.participants(), pt_bytes);
        if (fan_res.is_error()) {
            return ClientResult<domain::Message>::error(fan_res.error());
        }
    }

    // 3. Construct Message with deterministic idempotency key and initial delivery state
    const domain::MessageId mid(generate_unique_id("msg"));
    const std::string idem_key = generate_unique_id("idem");
    const std::string disp_name = sender_display_name.empty() ? std::string(sender_user_id.str()) : sender_display_name;

    domain::Message msg(mid, conversation_id, sender_user_id, sender_device_id, domain::DeliveryState::Accepted,
                        std::chrono::system_clock::now(), std::string(plaintext), priority, disp_name, idem_key,
                        /*emergency_acknowledged=*/false, attachment_name, attachment_size, attachment_hash);

    const auto save_res = local_store_.save_message(msg);
    if (save_res.is_error()) {
        return ClientResult<domain::Message>::error(save_res.error());
    }

    // 4. Update Conversation last activity timestamp
    auto updated_conv = conv;
    updated_conv.set_last_activity_at(msg.sent_at());
    (void)local_store_.save_conversation(updated_conv);

    return ClientResult<domain::Message>::ok(std::move(msg));
}

ClientResult<domain::Message> MessagingManager::retry_failed_message(const domain::ConversationId& conversation_id,
                                                                     const domain::MessageId& message_id) {
    if (conversation_id.empty() || message_id.empty()) {
        return ClientResult<domain::Message>::error(ClientError::validation("Conversation ID and Message ID required"));
    }

    auto msg_res = local_store_.get_message(conversation_id, message_id);
    if (msg_res.is_error()) {
        return ClientResult<domain::Message>::error(msg_res.error());
    }

    auto msg = msg_res.value();
    if (msg.delivery_state() != domain::DeliveryState::Failed) {
        return ClientResult<domain::Message>::error(
            ClientError::validation("Cannot retry message that is not in Failed state"));
    }

    // Preserve original idempotency_key per detailed-design.md §2.8 and ADR-007
    msg.set_delivery_state(domain::DeliveryState::Accepted);

    const auto update_res = local_store_.update_message(msg);
    if (update_res.is_error()) {
        return ClientResult<domain::Message>::error(update_res.error());
    }

    return ClientResult<domain::Message>::ok(std::move(msg));
}

ClientResult<void> MessagingManager::update_message_delivery_state(const domain::ConversationId& conversation_id,
                                                                   const domain::MessageId& message_id,
                                                                   domain::DeliveryState new_state) {
    if (conversation_id.empty() || message_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Conversation ID and Message ID required"));
    }

    auto msg_res = local_store_.get_message(conversation_id, message_id);
    if (msg_res.is_error()) {
        return ClientResult<void>::error(msg_res.error());
    }

    auto msg = msg_res.value();
    msg.set_delivery_state(new_state);
    return local_store_.update_message(msg);
}

ClientResult<void> MessagingManager::discard_failed_message(const domain::ConversationId& conversation_id,
                                                            const domain::MessageId& message_id) {
    if (conversation_id.empty() || message_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Conversation ID and Message ID required"));
    }

    auto msg_res = local_store_.get_message(conversation_id, message_id);
    if (msg_res.is_error()) {
        return ClientResult<void>::error(msg_res.error());
    }

    // Mark as failed/discarded
    auto msg = msg_res.value();
    msg.set_delivery_state(domain::DeliveryState::Failed);
    return local_store_.update_message(msg);
}

ClientResult<std::vector<domain::Message>>
MessagingManager::get_conversation_messages(const domain::ConversationId& conversation_id, std::size_t limit) {
    return local_store_.get_messages(conversation_id, limit);
}

ClientResult<domain::Message> MessagingManager::process_inbound_message(
    const domain::ConversationId& conversation_id, const domain::UserId& sender_user_id,
    const domain::DeviceId& sender_device_id, const domain::crypto::PerDeviceDeliveryPayload& payload, int32_t priority,
    const std::string& sender_display_name) {
    if (conversation_id.empty() || sender_user_id.empty() || sender_device_id.empty()) {
        return ClientResult<domain::Message>::error(
            ClientError::validation("Conversation ID, Sender User ID, and Sender Device ID are required"));
    }

    std::string decrypted_plaintext;
    if (ratchet_session_manager_ != nullptr) {
        auto dec_res = ratchet_session_manager_->decrypt_payload_from_device(sender_user_id, sender_device_id, payload);
        if (dec_res.is_error()) {
            return ClientResult<domain::Message>::error(dec_res.error());
        }
        decrypted_plaintext = dec_res.value().expose_unredacted_secret();
    } else {
        auto dec_res = crypto_provider_.decrypt_message(sender_device_id, payload.ciphertext_blob);
        if (dec_res.is_error()) {
            return ClientResult<domain::Message>::error(dec_res.error());
        }
        decrypted_plaintext = dec_res.value();
    }

    const domain::MessageId mid(generate_unique_id("msg-in"));
    const std::string idem_key = generate_unique_id("idem-in");
    const std::string disp_name = sender_display_name.empty() ? std::string(sender_user_id.str()) : sender_display_name;

    domain::Message msg(mid, conversation_id, sender_user_id, sender_device_id, domain::DeliveryState::Delivered,
                        std::chrono::system_clock::now(), std::move(decrypted_plaintext), priority, disp_name,
                        idem_key);

    const auto save_res = local_store_.save_message(msg);
    if (save_res.is_error()) {
        return ClientResult<domain::Message>::error(save_res.error());
    }

    auto conv_res = local_store_.get_conversation(conversation_id);
    if (conv_res.is_ok()) {
        auto conv = conv_res.value();
        conv.set_last_activity_at(msg.sent_at());
        conv.set_unread_count(conv.unread_count() + 1);
        (void)local_store_.save_conversation(conv);
    }

    return ClientResult<domain::Message>::ok(std::move(msg));
}

ClientResult<domain::Message> MessagingManager::process_inbound_message(
    const domain::ConversationId& conversation_id, const domain::UserId& sender_user_id,
    const domain::DeviceId& sender_device_id, const domain::crypto::EncryptedMessageEnvelope& envelope,
    int32_t priority, const std::string& sender_display_name) {
    if (conversation_id.empty() || sender_user_id.empty() || sender_device_id.empty()) {
        return ClientResult<domain::Message>::error(
            ClientError::validation("Conversation ID, Sender User ID, and Sender Device ID are required"));
    }
    if (!ratchet_session_manager_) {
        return ClientResult<domain::Message>::error(
            ClientError::crypto("RatchetSessionManager required to decrypt EncryptedMessageEnvelope"));
    }

    auto dec_res = ratchet_session_manager_->decrypt_from_device(sender_user_id, sender_device_id, envelope);
    if (dec_res.is_error()) {
        return ClientResult<domain::Message>::error(dec_res.error());
    }

    const std::string decrypted_plaintext = dec_res.value().expose_unredacted_secret();
    const domain::MessageId mid(generate_unique_id("msg-in"));
    const std::string idem_key = generate_unique_id("idem-in");
    const std::string disp_name = sender_display_name.empty() ? std::string(sender_user_id.str()) : sender_display_name;

    domain::Message msg(mid, conversation_id, sender_user_id, sender_device_id, domain::DeliveryState::Delivered,
                        std::chrono::system_clock::now(), std::move(decrypted_plaintext), priority, disp_name,
                        idem_key);

    const auto save_res = local_store_.save_message(msg);
    if (save_res.is_error()) {
        return ClientResult<domain::Message>::error(save_res.error());
    }

    auto conv_res = local_store_.get_conversation(conversation_id);
    if (conv_res.is_ok()) {
        auto conv = conv_res.value();
        conv.set_last_activity_at(msg.sent_at());
        conv.set_unread_count(conv.unread_count() + 1);
        (void)local_store_.save_conversation(conv);
    }

    return ClientResult<domain::Message>::ok(std::move(msg));
}

} // namespace securecloud::client::application::managers
