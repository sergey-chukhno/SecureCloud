#include "application/managers/messaging_manager.hpp"

#include "application/managers/ratchet_session_manager.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/crypto/sender_key_engine.hpp"
#include "domain/crypto/sender_key_models.hpp"
#include "domain/file_transfer.hpp"
#include "domain/offline_sync_models.hpp"

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

std::string bytes_to_hex(std::span<const uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(kHex[(b >> 4) & 0x0Fu]);
        out.push_back(kHex[b & 0x0Fu]);
    }
    return out;
}

std::optional<std::vector<uint8_t>> hex_to_bytes(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return 10 + (c - 'a');
        }
        if (c >= 'A' && c <= 'F') {
            return 10 + (c - 'A');
        }
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

ClientResult<void> save_sender_key_state(interfaces::ISecureStorage& storage,
                                         const domain::crypto::SenderKeyState& state) {
    const auto serialized = state.serialize();
    return storage.store_secret(state.id.storage_key(), common::configuration::SecretString(bytes_to_hex(serialized)));
}

ClientResult<domain::crypto::SenderKeyState> load_sender_key_state(interfaces::ISecureStorage& storage,
                                                                   const domain::crypto::SenderKeyId& id) {
    auto res = storage.get_secret(id.storage_key());
    if (res.is_error()) {
        return ClientResult<domain::crypto::SenderKeyState>::error(res.error());
    }
    const auto bytes_opt = hex_to_bytes(res.value().expose_unredacted_secret());
    if (!bytes_opt.has_value()) {
        return ClientResult<domain::crypto::SenderKeyState>::error(
            ClientError::crypto("Corrupt hex encoding for stored SenderKeyState"));
    }
    return domain::crypto::SenderKeyState::deserialize(*bytes_opt);
}

int64_t current_unix_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string message_outbox_id(const domain::MessageId& message_id) {
    return "msg-" + message_id.value();
}

std::string skd_outbox_id(const domain::MessageId& message_id) {
    return "skd-" + message_id.value();
}

std::string ack_outbox_id(const domain::MessageId& message_id, const domain::DeviceId& device_id) {
    return "ack-" + message_id.value() + "-" + device_id.value();
}

std::string receipt_outbox_id(const domain::ConversationId& conversation_id, const domain::MessageId& message_id,
                              const domain::DeviceId& device_id) {
    return "rcpt-" + conversation_id.value() + "-" + message_id.value() + "-" + device_id.value();
}

domain::OfflineOutboxFanOutPayload to_outbox_fanout_payload(const interfaces::FanOutSubmissionRequest& req) {
    return domain::OfflineOutboxFanOutPayload{
        .conversation_id = req.conversation_id,
        .idempotency_key = req.idempotency_key,
        .device_payloads = req.device_payloads,
        .group_envelope_bytes = req.group_envelope_bytes,
        .priority = req.priority,
    };
}

interfaces::FanOutSubmissionRequest from_outbox_fanout_payload(const domain::OfflineOutboxFanOutPayload& payload) {
    return interfaces::FanOutSubmissionRequest{
        .conversation_id = payload.conversation_id,
        .idempotency_key = payload.idempotency_key,
        .device_payloads = payload.device_payloads,
        .group_envelope_bytes = payload.group_envelope_bytes,
        .priority = payload.priority,
    };
}

bool is_outbox_record_expired(const domain::OfflineOutboxRecord& rec, const domain::RetryPolicyConfig& cfg,
                              int64_t now_ms) noexcept {
    if (rec.expires_at_ms > 0 && now_ms >= rec.expires_at_ms) {
        return true;
    }
    return rec.attempt_count >= cfg.max_attempts;
}

} // namespace

MessagingManager::MessagingManager(interfaces::IGatewayClient& gateway, interfaces::ILocalStore& local_store,
                                   interfaces::ICryptoProvider& crypto_provider,
                                   RatchetSessionManager* ratchet_session_manager,
                                   interfaces::ISecureStorage* secure_storage)
    : gateway_(gateway), local_store_(local_store), crypto_provider_(crypto_provider),
      ratchet_session_manager_(ratchet_session_manager), secure_storage_(secure_storage) {
    hydrate_read_receipt_policy();
    (void)hydrate_offline_outbox();
}

void MessagingManager::set_ratchet_session_manager(RatchetSessionManager* ratchet_session_manager) noexcept {
    ratchet_session_manager_ = ratchet_session_manager;
}

RatchetSessionManager* MessagingManager::ratchet_session_manager() noexcept {
    return ratchet_session_manager_;
}

void MessagingManager::set_secure_storage(interfaces::ISecureStorage* secure_storage) noexcept {
    secure_storage_ = secure_storage;
    hydrate_read_receipt_policy();
}

void MessagingManager::set_local_device_id(const domain::DeviceId& device_id) {
    local_device_id_ = device_id;
}

const domain::DeviceId& MessagingManager::local_device_id() const noexcept {
    return local_device_id_;
}

void MessagingManager::hydrate_read_receipt_policy() {
    if (!secure_storage_) {
        return;
    }
    auto has_res = secure_storage_->has_secret(domain::ReadReceiptPolicy::kStorageKey);
    if (has_res.is_ok() && has_res.value()) {
        auto val_res = secure_storage_->get_secret(domain::ReadReceiptPolicy::kStorageKey);
        if (val_res.is_ok()) {
            const std::string raw = val_res.value().expose_unredacted_secret();
            read_receipt_policy_.send_read_receipts_enabled = (raw != "false" && raw != "0");
        }
    }
}

ClientResult<void> MessagingManager::set_read_receipts_enabled(bool enabled) {
    read_receipt_policy_.send_read_receipts_enabled = enabled;
    if (!enabled) {
        purge_queued_read_receipts();
    }
    if (!secure_storage_) {
        return ClientResult<void>::ok();
    }
    return secure_storage_->store_secret(domain::ReadReceiptPolicy::kStorageKey,
                                         common::configuration::SecretString(enabled ? "true" : "false"));
}

bool MessagingManager::read_receipts_enabled() const noexcept {
    return read_receipt_policy_.send_read_receipts_enabled;
}

void MessagingManager::purge_queued_read_receipts() {
    const auto list_res = local_store_.list_outbox_records();
    if (list_res.is_error()) {
        return;
    }
    for (const auto& rec : list_res.value()) {
        if (rec.operation_type == domain::OfflineOutboxOperationType::ReadReceipt) {
            (void)local_store_.delete_outbox_record(rec.outbox_id);
        }
    }
}

void MessagingManager::dispatch_delivery_ack_if_configured(const domain::ConversationId& conversation_id,
                                                           const domain::MessageId& message_id) {
    if (local_device_id_.empty() || message_id.empty()) {
        return;
    }
    const int64_t now_ms = current_unix_ms();
    bool should_queue = offline_mode_;
    std::string last_error = offline_mode_ ? "Queued delivery ACK while offline" : "";
    if (!should_queue) {
        const auto ack_res = gateway_.acknowledge_delivery(message_id, local_device_id_, now_ms);
        if (ack_res.is_error() && ack_res.error().category() == ClientErrorCategory::Network) {
            should_queue = true;
            last_error = ack_res.error().user_message();
        }
    }
    if (should_queue && !conversation_id.empty()) {
        const std::string ob_id = ack_outbox_id(message_id, local_device_id_);
        const domain::OfflineOutboxDeliveryAckPayload payload{
            .message_id = message_id,
            .recipient_device_id = local_device_id_,
            .delivered_at_ms = now_ms,
        };
        const auto cfg = retry_engine_.config();
        domain::OfflineOutboxRecord rec;
        rec.outbox_id = ob_id;
        rec.operation_type = domain::OfflineOutboxOperationType::DeliveryAck;
        rec.conversation_id = conversation_id;
        rec.message_id = message_id;
        rec.idempotency_key = ob_id;
        rec.priority = 0;
        rec.payload_json = payload.to_json();
        rec.attempt_count = 1U;
        rec.created_at_ms = now_ms;
        rec.next_retry_at_ms = now_ms;
        rec.expires_at_ms = now_ms + cfg.expiration_ttl.count();
        rec.last_error = std::move(last_error);
        (void)local_store_.save_outbox_record(rec);
    }
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
    conv.set_participant_role(creator, domain::ParticipantRole::Admin);

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

ClientResult<void> MessagingManager::add_group_participant(const domain::ConversationId& conversation_id,
                                                           const domain::UserId& actor_user_id,
                                                           const domain::UserId& target_user_id) {
    if (conversation_id.empty() || actor_user_id.empty() || target_user_id.empty()) {
        return ClientResult<void>::error(
            ClientError::validation("Conversation ID, actor User ID, and target User ID are required"));
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
    if (!conv.is_admin(actor_user_id)) {
        return ClientResult<void>::error(ClientError::validation("Only group admins can add participants"));
    }

    conv.add_participant(target_user_id, domain::ParticipantRole::Member);
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
    conv.increment_sender_key_epoch();
    conv.set_last_activity_at(std::chrono::system_clock::now());
    return local_store_.save_conversation(conv);
}

ClientResult<void> MessagingManager::remove_group_participant(const domain::ConversationId& conversation_id,
                                                              const domain::UserId& actor_user_id,
                                                              const domain::UserId& target_user_id) {
    if (conversation_id.empty() || actor_user_id.empty() || target_user_id.empty()) {
        return ClientResult<void>::error(
            ClientError::validation("Conversation ID, actor User ID, and target User ID are required"));
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
    if (actor_user_id != target_user_id && !conv.is_admin(actor_user_id)) {
        return ClientResult<void>::error(ClientError::validation("Only group admins can remove other participants"));
    }

    conv.remove_participant(target_user_id);
    conv.increment_sender_key_epoch();
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

ClientResult<void> MessagingManager::mark_conversation_read(const domain::ConversationId& conversation_id,
                                                            const domain::UserId& local_user_id,
                                                            const domain::DeviceId& reader_device_id) {
    if (conversation_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Conversation ID cannot be empty"));
    }

    auto conv_res = local_store_.get_conversation(conversation_id);
    if (conv_res.is_error()) {
        return ClientResult<void>::error(conv_res.error());
    }

    auto conv = conv_res.value();
    conv.set_unread_count(0);
    auto save_conv_res = local_store_.save_conversation(conv);
    if (save_conv_res.is_error()) {
        return save_conv_res;
    }

    const domain::DeviceId effective_device_id = !reader_device_id.empty() ? reader_device_id : local_device_id_;
    if (!read_receipt_policy_.send_read_receipts_enabled || effective_device_id.empty()) {
        return ClientResult<void>::ok();
    }

    auto msgs_res = local_store_.get_messages(conversation_id, 200);
    if (msgs_res.is_ok()) {
        const int64_t now_ms = current_unix_ms();
        const auto cfg = retry_engine_.config();
        for (const auto& msg : msgs_res.value()) {
            const bool is_peer_msg = local_user_id.empty() || (msg.sender_user_id() != local_user_id);
            if (is_peer_msg && msg.delivery_state() != domain::DeliveryState::Read) {
                (void)update_message_delivery_state(conversation_id, msg.message_id(), domain::DeliveryState::Read);
                bool should_queue = offline_mode_;
                std::string last_error = offline_mode_ ? "Queued read receipt while offline" : "";
                if (!should_queue) {
                    const auto rcpt_res =
                        gateway_.send_read_receipt(conversation_id, msg.message_id(), effective_device_id, now_ms);
                    if (rcpt_res.is_error() && rcpt_res.error().category() == ClientErrorCategory::Network) {
                        should_queue = true;
                        last_error = rcpt_res.error().user_message();
                    }
                }
                if (should_queue) {
                    const std::string ob_id = receipt_outbox_id(conversation_id, msg.message_id(), effective_device_id);
                    const domain::OfflineOutboxReadReceiptPayload payload{
                        .conversation_id = conversation_id,
                        .message_id = msg.message_id(),
                        .reader_device_id = effective_device_id,
                        .read_at_ms = now_ms,
                    };
                    domain::OfflineOutboxRecord rec;
                    rec.outbox_id = ob_id;
                    rec.operation_type = domain::OfflineOutboxOperationType::ReadReceipt;
                    rec.conversation_id = conversation_id;
                    rec.message_id = msg.message_id();
                    rec.idempotency_key = ob_id;
                    rec.priority = 0;
                    rec.payload_json = payload.to_json();
                    rec.attempt_count = 1U;
                    rec.created_at_ms = now_ms;
                    rec.next_retry_at_ms = now_ms;
                    rec.expires_at_ms = now_ms + cfg.expiration_ttl.count();
                    rec.last_error = std::move(last_error);
                    (void)local_store_.save_outbox_record(rec);
                }
            }
        }
    }

    return ClientResult<void>::ok();
}

ClientResult<domain::Message> MessagingManager::send_message(const domain::ConversationId& conversation_id,
                                                             const domain::UserId& sender_user_id,
                                                             const domain::DeviceId& sender_device_id,
                                                             const domain::DeviceId& recipient_device_id,
                                                             std::string_view plaintext) {
    if (conversation_id.empty()) {
        return ClientResult<domain::Message>::error(ClientError::validation("Conversation ID cannot be empty"));
    }

    auto conv_lookup = local_store_.get_conversation(conversation_id);
    if (conv_lookup.is_ok()) {
        const auto guard_res = validate_recipients_can_receive(conv_lookup.value(), sender_user_id);
        if (guard_res.is_error()) {
            return ClientResult<domain::Message>::error(guard_res.error());
        }
    }

    std::string ciphertext;
    if (ratchet_session_manager_ != nullptr) {
        domain::UserId peer_user_id;
        if (conv_lookup.is_ok()) {
            for (const auto& p : conv_lookup.value().participants()) {
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
    const auto guard_res = validate_recipients_can_receive(conv, sender_user_id);
    if (guard_res.is_error()) {
        return ClientResult<domain::Message>::error(guard_res.error());
    }

    const domain::MessageId mid(generate_unique_id("msg"));
    const std::string idem_key = generate_unique_id("idem");
    const bool is_file_key_envelope = domain::FileAttachmentKeyEnvelope::is_file_attachment_envelope(plaintext);
    const auto msg_op_type = is_file_key_envelope ? domain::OfflineOutboxOperationType::FileKeyEnvelopeSubmission
                                                  : domain::OfflineOutboxOperationType::EncryptedMessageSubmission;
    std::optional<uint64_t> group_epoch_used = std::nullopt;
    domain::DeliveryState initial_state = domain::DeliveryState::Accepted;
    std::optional<interfaces::FanOutSubmissionRequest> pending_skd_req;
    std::optional<interfaces::FanOutSubmissionRequest> pending_retry_req;
    std::string queued_error;

    if (conv.type() == domain::ConversationType::Group && ratchet_session_manager_ != nullptr &&
        secure_storage_ != nullptr) {
        const domain::crypto::SenderKeyId sk_id{
            .conversation_id = conversation_id,
            .sender_user_id = sender_user_id,
            .sender_device_id = sender_device_id,
            .key_epoch = conv.sender_key_epoch(),
        };
        auto state_res = load_sender_key_state(*secure_storage_, sk_id);
        if (state_res.is_error()) {
            auto dist_res = distribute_sender_key(conversation_id, sender_user_id, sender_device_id);
            if (dist_res.is_error()) {
                return ClientResult<domain::Message>::error(dist_res.error());
            }
            if (!dist_res.value().empty()) {
                interfaces::FanOutSubmissionRequest dist_req{
                    .conversation_id = conversation_id,
                    .idempotency_key = idem_key + "-skd",
                    .device_payloads = std::move(dist_res.value()),
                    .group_envelope_bytes = std::nullopt,
                    .priority = priority,
                };
                if (offline_mode_) {
                    pending_skd_req = std::move(dist_req);
                    queued_error = "Queued while offline";
                } else {
                    auto dist_submit = gateway_.submit_encrypted_message(dist_req);
                    if (dist_submit.is_error()) {
                        if (dist_submit.error().category() == ClientErrorCategory::Network) {
                            pending_skd_req = std::move(dist_req);
                            queued_error = dist_submit.error().user_message();
                        } else {
                            return ClientResult<domain::Message>::error(dist_submit.error());
                        }
                    }
                }
            }
            state_res = load_sender_key_state(*secure_storage_, sk_id);
            if (state_res.is_error()) {
                return ClientResult<domain::Message>::error(state_res.error());
            }
        }

        auto sender_state = std::move(state_res.value());
        std::span<const uint8_t> pt_bytes(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
        auto env_res = domain::crypto::SenderKeyEngine::encrypt(crypto_provider_, sender_state, pt_bytes);
        if (env_res.is_error()) {
            return ClientResult<domain::Message>::error(env_res.error());
        }

        auto save_sk_res = save_sender_key_state(*secure_storage_, sender_state);
        if (save_sk_res.is_error()) {
            return ClientResult<domain::Message>::error(save_sk_res.error());
        }

        interfaces::FanOutSubmissionRequest group_req{
            .conversation_id = conversation_id,
            .idempotency_key = idem_key,
            .device_payloads = {},
            .group_envelope_bytes = env_res.value().serialize(),
            .priority = priority,
        };
        if (offline_mode_ || pending_skd_req.has_value()) {
            initial_state = domain::DeliveryState::LocalPending;
            pending_retry_req = std::move(group_req);
            if (queued_error.empty()) {
                queued_error = "Queued while offline";
            }
        } else {
            auto submit_res = gateway_.submit_encrypted_message(group_req);
            if (submit_res.is_error()) {
                if (submit_res.error().category() == ClientErrorCategory::Network) {
                    initial_state = domain::DeliveryState::LocalPending;
                    pending_retry_req = std::move(group_req);
                    queued_error = submit_res.error().user_message();
                } else {
                    return ClientResult<domain::Message>::error(submit_res.error());
                }
            }
        }
        group_epoch_used = conv.sender_key_epoch();
    } else if (ratchet_session_manager_ != nullptr) {
        std::span<const uint8_t> pt_bytes(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
        auto fan_res = ratchet_session_manager_->encrypt_fanout_for_participants(conv.participants(), pt_bytes);
        if (fan_res.is_error()) {
            return ClientResult<domain::Message>::error(fan_res.error());
        }
        if (!fan_res.value().empty()) {
            interfaces::FanOutSubmissionRequest req{
                .conversation_id = conversation_id,
                .idempotency_key = idem_key,
                .device_payloads = std::move(fan_res.value()),
                .group_envelope_bytes = std::nullopt,
                .priority = priority,
            };
            if (offline_mode_) {
                initial_state = domain::DeliveryState::LocalPending;
                pending_retry_req = std::move(req);
                queued_error = "Queued while offline";
            } else {
                auto submit_res = gateway_.submit_encrypted_message(req);
                if (submit_res.is_error()) {
                    if (submit_res.error().category() == ClientErrorCategory::Network) {
                        initial_state = domain::DeliveryState::LocalPending;
                        pending_retry_req = std::move(req);
                        queued_error = submit_res.error().user_message();
                    } else {
                        return ClientResult<domain::Message>::error(submit_res.error());
                    }
                }
            }
        }
    } else if (offline_mode_) {
        const auto enc_res = crypto_provider_.encrypt_message(sender_device_id, plaintext);
        if (enc_res.is_error()) {
            return ClientResult<domain::Message>::error(enc_res.error());
        }
        domain::UserId recipient_uid = sender_user_id;
        for (const auto& p : conv.participants()) {
            if (p != sender_user_id) {
                recipient_uid = p;
                break;
            }
        }
        interfaces::FanOutSubmissionRequest req{
            .conversation_id = conversation_id,
            .idempotency_key = idem_key,
            .device_payloads = {domain::crypto::PerDeviceDeliveryPayload{
                .recipient_user_id = recipient_uid,
                .recipient_device_id = sender_device_id,
                .ciphertext_blob = enc_res.value(),
                .algorithm = "AES-256-GCM",
            }},
            .group_envelope_bytes = std::nullopt,
            .priority = priority,
        };
        initial_state = domain::DeliveryState::LocalPending;
        pending_retry_req = std::move(req);
        queued_error = "Queued while offline";
    }

    // 3. Construct Message with deterministic idempotency key and initial delivery state
    const std::string disp_name = sender_display_name.empty() ? std::string(sender_user_id.str()) : sender_display_name;

    domain::Message msg(mid, conversation_id, sender_user_id, sender_device_id, initial_state,
                        std::chrono::system_clock::now(), std::string(plaintext), priority, disp_name, idem_key,
                        /*emergency_acknowledged=*/false, attachment_name, attachment_size, attachment_hash);
    if (group_epoch_used.has_value()) {
        msg.set_sender_key_epoch(*group_epoch_used);
    }

    const auto save_res = local_store_.save_message(msg);
    if (save_res.is_error()) {
        return ClientResult<domain::Message>::error(save_res.error());
    }

    const int64_t now_ms = current_unix_ms();
    const auto retry_cfg = retry_engine_.config();
    const int64_t initial_backoff_ms = retry_engine_.compute_backoff(1U).count();

    if (pending_skd_req.has_value()) {
        domain::OfflineOutboxRecord skd_rec;
        skd_rec.outbox_id = skd_outbox_id(mid);
        skd_rec.operation_type = domain::OfflineOutboxOperationType::EncryptedMessageSubmission;
        skd_rec.conversation_id = conversation_id;
        skd_rec.message_id = mid;
        skd_rec.idempotency_key = pending_skd_req->idempotency_key;
        skd_rec.priority = priority;
        skd_rec.payload_json = to_outbox_fanout_payload(*pending_skd_req).to_json();
        skd_rec.attempt_count = 1U;
        skd_rec.created_at_ms = now_ms - 1LL;
        skd_rec.next_retry_at_ms = now_ms + initial_backoff_ms;
        skd_rec.expires_at_ms = now_ms + retry_cfg.expiration_ttl.count();
        skd_rec.last_error = queued_error;
        (void)local_store_.save_outbox_record(skd_rec);
    }

    if (pending_retry_req.has_value()) {
        const std::string ob_id = message_outbox_id(mid);
        domain::OfflineOutboxRecord msg_rec;
        msg_rec.outbox_id = ob_id;
        msg_rec.operation_type = msg_op_type;
        msg_rec.conversation_id = conversation_id;
        msg_rec.message_id = mid;
        msg_rec.idempotency_key = pending_retry_req->idempotency_key;
        msg_rec.priority = priority;
        msg_rec.payload_json = to_outbox_fanout_payload(*pending_retry_req).to_json();
        msg_rec.attempt_count = 1U;
        msg_rec.created_at_ms = now_ms;
        msg_rec.next_retry_at_ms = now_ms + initial_backoff_ms;
        msg_rec.expires_at_ms = now_ms + retry_cfg.expiration_ttl.count();
        msg_rec.last_error = queued_error;
        (void)local_store_.save_outbox_record(msg_rec);

        retry_engine_.enqueue(conversation_id, mid, std::move(*pending_retry_req), std::chrono::steady_clock::now(),
                              ob_id);
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

    const auto conv_res = local_store_.get_conversation(conversation_id);
    if (conv_res.is_ok()) {
        const auto guard_res = validate_recipients_can_receive(conv_res.value(), msg.sender_user_id());
        if (guard_res.is_error()) {
            return ClientResult<domain::Message>::error(guard_res.error());
        }
    }

    // If a pre-encrypted outbox payload was persisted, replay it directly without re-stepping ratchets (ADR-008)
    const std::string skd_id = skd_outbox_id(message_id);
    const auto skd_res = local_store_.get_outbox_record(skd_id);
    if (skd_res.is_ok()) {
        const auto skd_payload = domain::OfflineOutboxFanOutPayload::from_json(skd_res.value().payload_json);
        if (skd_payload.has_value()) {
            const auto skd_submit = gateway_.submit_encrypted_message(from_outbox_fanout_payload(*skd_payload));
            if (skd_submit.is_error()) {
                return ClientResult<domain::Message>::error(skd_submit.error());
            }
            (void)local_store_.delete_outbox_record(skd_id);
        }
    }

    const std::string ob_id = message_outbox_id(message_id);
    const auto outbox_res = local_store_.get_outbox_record(ob_id);
    if (outbox_res.is_ok()) {
        const auto fanout_opt = domain::OfflineOutboxFanOutPayload::from_json(outbox_res.value().payload_json);
        if (!fanout_opt.has_value()) {
            return ClientResult<domain::Message>::error(
                ClientError::storage("Corrupt offline outbox payload for manual retry"));
        }
        const auto submit_res = gateway_.submit_encrypted_message(from_outbox_fanout_payload(*fanout_opt));
        if (submit_res.is_error()) {
            return ClientResult<domain::Message>::error(submit_res.error());
        }
        (void)local_store_.delete_outbox_record(ob_id);
        (void)retry_engine_.remove(message_id);
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
                                                                   domain::DeliveryState new_state,
                                                                   uint64_t server_sequence_number) {
    if (conversation_id.empty() || message_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Conversation ID and Message ID required"));
    }

    auto msg_res = local_store_.get_message(conversation_id, message_id);
    if (msg_res.is_error()) {
        return ClientResult<void>::error(msg_res.error());
    }

    auto msg = msg_res.value();
    bool changed = false;
    if (domain::can_transition_delivery_state(msg.delivery_state(), new_state) && msg.delivery_state() != new_state) {
        msg.set_delivery_state(new_state);
        changed = true;
    }
    if (server_sequence_number > msg.server_sequence_number()) {
        msg.set_server_sequence_number(server_sequence_number);
        changed = true;
    }
    if (!changed) {
        return ClientResult<void>::ok();
    }
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

    // Mark as failed/discarded and remove from retry queue and durable outbox
    (void)retry_engine_.remove(message_id);
    (void)local_store_.delete_outbox_record(message_outbox_id(message_id));
    (void)local_store_.delete_outbox_record(skd_outbox_id(message_id));
    auto msg = msg_res.value();
    msg.set_delivery_state(domain::DeliveryState::Failed);
    return local_store_.update_message(msg);
}

void MessagingManager::set_retry_policy(const domain::RetryPolicyConfig& config) {
    retry_engine_.set_config(config);
}

std::size_t MessagingManager::pending_retry_count() const {
    return retry_engine_.pending_count();
}

void MessagingManager::set_offline_mode(bool offline) noexcept {
    offline_mode_ = offline;
}

bool MessagingManager::is_offline_mode() const noexcept {
    return offline_mode_;
}

std::size_t MessagingManager::hydrate_offline_outbox() {
    const auto list_res = local_store_.list_outbox_records();
    if (list_res.is_error()) {
        return 0U;
    }

    const int64_t now_ms = current_unix_ms();
    const auto steady_now = std::chrono::steady_clock::now();
    const auto cfg = retry_engine_.config();
    std::size_t hydrated_count = 0U;

    for (const auto& rec : list_res.value()) {
        if (rec.operation_type != domain::OfflineOutboxOperationType::EncryptedMessageSubmission &&
            rec.operation_type != domain::OfflineOutboxOperationType::FileKeyEnvelopeSubmission) {
            continue;
        }
        if (rec.outbox_id != message_outbox_id(rec.message_id)) {
            continue;
        }
        if (is_outbox_record_expired(rec, cfg, now_ms)) {
            continue;
        }
        const auto msg_res = local_store_.get_message(rec.conversation_id, rec.message_id);
        if (msg_res.is_ok() && msg_res.value().delivery_state() == domain::DeliveryState::Failed) {
            continue;
        }

        const auto fanout_opt = domain::OfflineOutboxFanOutPayload::from_json(rec.payload_json);
        if (!fanout_opt.has_value()) {
            continue;
        }

        const int64_t retry_delta_ms = rec.next_retry_at_ms - now_ms;
        const int64_t expire_delta_ms =
            rec.expires_at_ms > 0 ? (rec.expires_at_ms - now_ms) : cfg.expiration_ttl.count();
        const int64_t created_delta_ms = rec.created_at_ms - now_ms;

        retry_engine_.hydrate_entry(RetryQueueEntry{
            .conversation_id = rec.conversation_id,
            .message_id = rec.message_id,
            .request = from_outbox_fanout_payload(*fanout_opt),
            .priority = rec.priority,
            .outbox_id = rec.outbox_id,
            .attempt_count = rec.attempt_count > 0 ? rec.attempt_count : 1U,
            .enqueued_at = steady_now + std::chrono::milliseconds(created_delta_ms),
            .next_retry_at = steady_now + std::chrono::milliseconds(retry_delta_ms),
            .expires_at = steady_now + std::chrono::milliseconds(expire_delta_ms),
        });
        ++hydrated_count;
    }

    return hydrated_count;
}

std::size_t MessagingManager::pending_outbox_count() const {
    const auto list_res = local_store_.list_outbox_records();
    if (list_res.is_error()) {
        return 0U;
    }

    const int64_t now_ms = current_unix_ms();
    const auto cfg = retry_engine_.config();
    std::size_t count = 0U;
    for (const auto& rec : list_res.value()) {
        if (rec.operation_type == domain::OfflineOutboxOperationType::ReadReceipt &&
            !read_receipt_policy_.send_read_receipts_enabled) {
            continue;
        }
        if (is_outbox_record_expired(rec, cfg, now_ms)) {
            continue;
        }
        if (rec.outbox_id == message_outbox_id(rec.message_id)) {
            const auto msg_res = local_store_.get_message(rec.conversation_id, rec.message_id);
            if (msg_res.is_ok() && msg_res.value().delivery_state() == domain::DeliveryState::Failed) {
                continue;
            }
        }
        ++count;
    }
    return count;
}

std::size_t MessagingManager::flush_offline_outbox(std::chrono::system_clock::time_point now, bool ignore_backoff) {
    const auto list_res = local_store_.list_outbox_records();
    if (list_res.is_error()) {
        return 0U;
    }

    const int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    const auto cfg = retry_engine_.config();
    std::size_t flushed_count = 0U;

    for (auto rec : list_res.value()) {
        if (rec.operation_type == domain::OfflineOutboxOperationType::ReadReceipt &&
            !read_receipt_policy_.send_read_receipts_enabled) {
            (void)local_store_.delete_outbox_record(rec.outbox_id);
            continue;
        }

        const bool is_msg_record =
            (rec.operation_type == domain::OfflineOutboxOperationType::EncryptedMessageSubmission ||
             rec.operation_type == domain::OfflineOutboxOperationType::FileKeyEnvelopeSubmission) &&
            rec.outbox_id == message_outbox_id(rec.message_id);

        if (is_msg_record) {
            const auto msg_res = local_store_.get_message(rec.conversation_id, rec.message_id);
            if (msg_res.is_ok() && msg_res.value().delivery_state() == domain::DeliveryState::Failed) {
                continue;
            }
        }

        if (is_outbox_record_expired(rec, cfg, now_ms)) {
            if (is_msg_record) {
                (void)update_message_delivery_state(rec.conversation_id, rec.message_id, domain::DeliveryState::Failed);
                (void)retry_engine_.remove(rec.message_id);
                rec.attempt_count = cfg.max_attempts;
                (void)local_store_.save_outbox_record(rec);
            } else {
                (void)local_store_.delete_outbox_record(rec.outbox_id);
            }
            continue;
        }

        if (!ignore_backoff && rec.next_retry_at_ms > now_ms) {
            continue;
        }

        switch (rec.operation_type) {
        case domain::OfflineOutboxOperationType::EncryptedMessageSubmission:
        case domain::OfflineOutboxOperationType::FileKeyEnvelopeSubmission: {
            const auto fanout_opt = domain::OfflineOutboxFanOutPayload::from_json(rec.payload_json);
            if (!fanout_opt.has_value()) {
                if (is_msg_record) {
                    (void)update_message_delivery_state(rec.conversation_id, rec.message_id,
                                                        domain::DeliveryState::Failed);
                    (void)retry_engine_.remove(rec.message_id);
                }
                (void)local_store_.delete_outbox_record(rec.outbox_id);
                continue;
            }

            // Re-validate ADR-008 recipient eligibility before flushing queued ciphertext
            const auto conv_res = local_store_.get_conversation(rec.conversation_id);
            const auto msg_res = local_store_.get_message(rec.conversation_id, rec.message_id);
            if (conv_res.is_ok() && msg_res.is_ok()) {
                const auto guard_res =
                    validate_recipients_can_receive(conv_res.value(), msg_res.value().sender_user_id());
                if (guard_res.is_error()) {
                    (void)update_message_delivery_state(rec.conversation_id, rec.message_id,
                                                        domain::DeliveryState::Failed);
                    (void)retry_engine_.remove(rec.message_id);
                    rec.attempt_count = cfg.max_attempts;
                    rec.last_error = guard_res.error().user_message();
                    (void)local_store_.save_outbox_record(rec);
                    continue;
                }
            }

            const auto submit_res = gateway_.submit_encrypted_message(from_outbox_fanout_payload(*fanout_opt));
            if (submit_res.is_ok()) {
                (void)local_store_.delete_outbox_record(rec.outbox_id);
                if (is_msg_record) {
                    (void)retry_engine_.remove(rec.message_id);
                    (void)update_message_delivery_state(rec.conversation_id, rec.message_id,
                                                        domain::DeliveryState::Accepted);
                }
                ++flushed_count;
                continue;
            }

            ++rec.attempt_count;
            rec.last_error = submit_res.error().user_message();
            if (submit_res.error().category() != ClientErrorCategory::Network ||
                is_outbox_record_expired(rec, cfg, now_ms)) {
                rec.attempt_count = std::max(rec.attempt_count, cfg.max_attempts);
                if (is_msg_record) {
                    (void)update_message_delivery_state(rec.conversation_id, rec.message_id,
                                                        domain::DeliveryState::Failed);
                    (void)retry_engine_.remove(rec.message_id);
                    (void)local_store_.save_outbox_record(rec);
                } else {
                    (void)local_store_.delete_outbox_record(rec.outbox_id);
                }
                if (submit_res.error().category() == ClientErrorCategory::Network) {
                    return flushed_count;
                }
                continue;
            }

            const auto delay = retry_engine_.compute_backoff(rec.attempt_count);
            rec.next_retry_at_ms = now_ms + delay.count();
            (void)local_store_.save_outbox_record(rec);
            return flushed_count;
        }
        case domain::OfflineOutboxOperationType::DeliveryAck: {
            const auto ack_opt = domain::OfflineOutboxDeliveryAckPayload::from_json(rec.payload_json);
            if (!ack_opt.has_value()) {
                (void)local_store_.delete_outbox_record(rec.outbox_id);
                continue;
            }
            const auto ack_res = gateway_.acknowledge_delivery(ack_opt->message_id, ack_opt->recipient_device_id,
                                                               ack_opt->delivered_at_ms);
            if (ack_res.is_ok()) {
                (void)local_store_.delete_outbox_record(rec.outbox_id);
                ++flushed_count;
                continue;
            }
            if (ack_res.error().category() == ClientErrorCategory::Network) {
                ++rec.attempt_count;
                rec.last_error = ack_res.error().user_message();
                const auto delay = retry_engine_.compute_backoff(rec.attempt_count);
                rec.next_retry_at_ms = now_ms + delay.count();
                (void)local_store_.save_outbox_record(rec);
                return flushed_count;
            }
            (void)local_store_.delete_outbox_record(rec.outbox_id);
            continue;
        }
        case domain::OfflineOutboxOperationType::ReadReceipt: {
            const auto rcpt_opt = domain::OfflineOutboxReadReceiptPayload::from_json(rec.payload_json);
            if (!rcpt_opt.has_value()) {
                (void)local_store_.delete_outbox_record(rec.outbox_id);
                continue;
            }
            const auto rcpt_res = gateway_.send_read_receipt(rcpt_opt->conversation_id, rcpt_opt->message_id,
                                                             rcpt_opt->reader_device_id, rcpt_opt->read_at_ms);
            if (rcpt_res.is_ok()) {
                (void)local_store_.delete_outbox_record(rec.outbox_id);
                ++flushed_count;
                continue;
            }
            if (rcpt_res.error().category() == ClientErrorCategory::Network) {
                ++rec.attempt_count;
                rec.last_error = rcpt_res.error().user_message();
                const auto delay = retry_engine_.compute_backoff(rec.attempt_count);
                rec.next_retry_at_ms = now_ms + delay.count();
                (void)local_store_.save_outbox_record(rec);
                return flushed_count;
            }
            (void)local_store_.delete_outbox_record(rec.outbox_id);
            continue;
        }
        }
    }

    return flushed_count;
}

std::size_t MessagingManager::process_retry_queue(std::chrono::steady_clock::time_point now) {
    return retry_engine_.process_due(
        now,
        [this](const interfaces::FanOutSubmissionRequest& req) -> ClientResult<std::string> {
            auto res = gateway_.submit_encrypted_message(req);
            if (res.is_ok()) {
                // Find matching LocalPending message with this idempotency_key to mark Accepted
                auto msgs_res = local_store_.get_messages(req.conversation_id, 200);
                if (msgs_res.is_ok()) {
                    for (const auto& m : msgs_res.value()) {
                        if (m.idempotency_key() == req.idempotency_key) {
                            (void)update_message_delivery_state(req.conversation_id, m.message_id(),
                                                                domain::DeliveryState::Accepted);
                            (void)local_store_.delete_outbox_record(message_outbox_id(m.message_id()));
                            break;
                        }
                    }
                }
            }
            return res;
        },
        [this](const domain::ConversationId& cid, const domain::MessageId& mid) {
            (void)update_message_delivery_state(cid, mid, domain::DeliveryState::Failed);
            const std::string ob_id = message_outbox_id(mid);
            auto rec_res = local_store_.get_outbox_record(ob_id);
            if (rec_res.is_ok()) {
                auto rec = rec_res.value();
                rec.attempt_count = retry_engine_.config().max_attempts;
                (void)local_store_.save_outbox_record(rec);
            }
        },
        [this, now](const RetryQueueEntry& entry, const ClientError& err) {
            const std::string ob_id = entry.outbox_id.empty() ? message_outbox_id(entry.message_id) : entry.outbox_id;
            auto rec_res = local_store_.get_outbox_record(ob_id);
            if (rec_res.is_ok()) {
                auto rec = rec_res.value();
                rec.attempt_count = entry.attempt_count;
                const auto remaining_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(entry.next_retry_at - now).count();
                rec.next_retry_at_ms = current_unix_ms() + std::max<int64_t>(0LL, remaining_ms);
                rec.last_error = err.user_message();
                (void)local_store_.save_outbox_record(rec);
            }
        });
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

    const auto sender_contact = local_store_.get_contact(sender_user_id);
    if (sender_contact.is_ok() && sender_contact.value().is_blocked()) {
        return ClientResult<domain::Message>::error(
            ClientError::validation("Inbound message dropped: sender is blocked"));
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

    const auto sender_contact = local_store_.get_contact(sender_user_id);
    if (sender_contact.is_ok() && sender_contact.value().is_blocked()) {
        return ClientResult<domain::Message>::error(
            ClientError::validation("Inbound message dropped: sender is blocked"));
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

ClientResult<void> MessagingManager::check_conversation_send_eligibility(const domain::ConversationId& conversation_id,
                                                                         const domain::UserId& sender_user_id) const {
    if (conversation_id.empty() || sender_user_id.empty()) {
        return ClientResult<void>::error(
            ClientError::validation("Conversation ID and sender User ID are required for eligibility check"));
    }
    const auto conv_res = local_store_.get_conversation(conversation_id);
    if (conv_res.is_error()) {
        return ClientResult<void>::error(conv_res.error());
    }
    return validate_recipients_can_receive(conv_res.value(), sender_user_id);
}

ClientResult<void> MessagingManager::validate_recipients_can_receive(const domain::Conversation& conv,
                                                                     const domain::UserId& sender_user_id) const {
    for (const auto& participant_id : conv.participants()) {
        if (participant_id == sender_user_id) {
            continue;
        }
        auto contact_res = local_store_.get_contact(participant_id);
        if (contact_res.is_ok()) {
            const auto& contact = contact_res.value();
            if (contact.verification_status() == domain::KeyVerificationStatus::KeyChanged) {
                return ClientResult<void>::error(
                    ClientError::validation("Outbound messaging suspended: recipient identity key changed (ADR-008)"));
            }
            if (contact.is_blocked()) {
                return ClientResult<void>::error(ClientError::validation("Cannot send message: recipient is blocked"));
            }
        }
    }

    return ClientResult<void>::ok();
}

ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>
MessagingManager::distribute_sender_key(const domain::ConversationId& conversation_id,
                                        const domain::UserId& sender_user_id,
                                        const domain::DeviceId& sender_device_id) {
    if (conversation_id.empty() || sender_user_id.empty() || sender_device_id.empty()) {
        return ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>::error(
            ClientError::validation("Conversation ID, sender User ID, and sender Device ID are required"));
    }
    if (!ratchet_session_manager_ || !secure_storage_) {
        return ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>::error(
            ClientError::crypto("RatchetSessionManager and ISecureStorage required for Sender Key distribution"));
    }

    auto conv_res = local_store_.get_conversation(conversation_id);
    if (conv_res.is_error()) {
        return ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>::error(conv_res.error());
    }
    const auto& conv = conv_res.value();
    if (conv.type() != domain::ConversationType::Group) {
        return ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>::error(
            ClientError::validation("Sender Key distribution is only valid for group conversations"));
    }

    const auto guard_res = validate_recipients_can_receive(conv, sender_user_id);
    if (guard_res.is_error()) {
        return ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>::error(guard_res.error());
    }

    const domain::crypto::SenderKeyId sk_id{
        .conversation_id = conversation_id,
        .sender_user_id = sender_user_id,
        .sender_device_id = sender_device_id,
        .key_epoch = conv.sender_key_epoch(),
    };

    auto state_res = load_sender_key_state(*secure_storage_, sk_id);
    if (state_res.is_error()) {
        state_res = domain::crypto::SenderKeyEngine::create_sender_key(sk_id);
        if (state_res.is_error()) {
            return ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>::error(state_res.error());
        }
        auto save_res = save_sender_key_state(*secure_storage_, state_res.value());
        if (save_res.is_error()) {
            return ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>::error(save_res.error());
        }
    }

    auto dist_res = domain::crypto::SenderKeyEngine::create_distribution_message(state_res.value());
    if (dist_res.is_error()) {
        return ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>::error(dist_res.error());
    }

    const auto dist_bytes = dist_res.value().serialize();
    return ratchet_session_manager_->encrypt_fanout_for_participants(conv.participants(), dist_bytes);
}

ClientResult<void> MessagingManager::process_inbound_sender_key_distribution(
    const domain::UserId& sender_user_id, const domain::DeviceId& sender_device_id,
    const domain::crypto::SenderKeyDistributionMessage& distribution) {
    if (sender_user_id.empty() || sender_device_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Sender User ID and Device ID are required"));
    }
    if (!secure_storage_) {
        return ClientResult<void>::error(
            ClientError::crypto("ISecureStorage required to store inbound Sender Key state"));
    }

    const auto sender_contact = local_store_.get_contact(sender_user_id);
    if (sender_contact.is_ok() && sender_contact.value().is_blocked()) {
        return ClientResult<void>::error(
            ClientError::validation("Inbound Sender Key distribution dropped: sender is blocked"));
    }

    if (distribution.id.sender_user_id != sender_user_id || distribution.id.sender_device_id != sender_device_id) {
        return ClientResult<void>::error(ClientError::crypto("SenderKeyDistributionMessage sender identity mismatch"));
    }

    auto state_res = domain::crypto::SenderKeyEngine::process_distribution_message(distribution);
    if (state_res.is_error()) {
        return ClientResult<void>::error(state_res.error());
    }

    return save_sender_key_state(*secure_storage_, state_res.value());
}

ClientResult<domain::Message> MessagingManager::process_inbound_group_message(
    const domain::ConversationId& conversation_id, const domain::UserId& sender_user_id,
    const domain::DeviceId& sender_device_id, std::span<const uint8_t> group_envelope_bytes, int32_t priority,
    const std::string& sender_display_name) {
    if (conversation_id.empty() || sender_user_id.empty() || sender_device_id.empty()) {
        return ClientResult<domain::Message>::error(
            ClientError::validation("Conversation ID, Sender User ID, and Sender Device ID are required"));
    }
    if (!secure_storage_) {
        return ClientResult<domain::Message>::error(
            ClientError::crypto("ISecureStorage required to decrypt group message"));
    }

    const auto sender_contact = local_store_.get_contact(sender_user_id);
    if (sender_contact.is_ok() && sender_contact.value().is_blocked()) {
        return ClientResult<domain::Message>::error(
            ClientError::validation("Inbound group message dropped: sender is blocked"));
    }

    auto env_res = domain::crypto::GroupEncryptedEnvelope::deserialize(group_envelope_bytes);
    if (env_res.is_error()) {
        return ClientResult<domain::Message>::error(env_res.error());
    }
    const auto& env = env_res.value();

    if (env.id.conversation_id != conversation_id || env.id.sender_user_id != sender_user_id ||
        env.id.sender_device_id != sender_device_id) {
        return ClientResult<domain::Message>::error(
            ClientError::crypto("GroupEncryptedEnvelope identity or conversation mismatch"));
    }

    auto state_res = load_sender_key_state(*secure_storage_, env.id);
    if (state_res.is_error()) {
        return ClientResult<domain::Message>::error(state_res.error());
    }

    auto sender_state = std::move(state_res.value());
    auto dec_res = domain::crypto::SenderKeyEngine::decrypt(crypto_provider_, sender_state, env);
    if (dec_res.is_error()) {
        return ClientResult<domain::Message>::error(dec_res.error());
    }

    auto save_sk_res = save_sender_key_state(*secure_storage_, sender_state);
    if (save_sk_res.is_error()) {
        return ClientResult<domain::Message>::error(save_sk_res.error());
    }

    const std::string decrypted_plaintext = dec_res.value().expose_unredacted_secret();
    const domain::MessageId mid(generate_unique_id("msg-grp-in"));
    const std::string idem_key = generate_unique_id("idem-grp-in");
    const std::string disp_name = sender_display_name.empty() ? std::string(sender_user_id.str()) : sender_display_name;

    domain::Message msg(mid, conversation_id, sender_user_id, sender_device_id, domain::DeliveryState::Delivered,
                        std::chrono::system_clock::now(), decrypted_plaintext, priority, disp_name, idem_key);
    msg.set_sender_key_epoch(env.id.key_epoch);

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

ClientResult<domain::Message> MessagingManager::persist_inbound_message(domain::Message msg) {
    const auto save_res = local_store_.save_message(msg);
    if (save_res.is_error()) {
        return ClientResult<domain::Message>::error(save_res.error());
    }

    auto conv_res = local_store_.get_conversation(msg.conversation_id());
    if (conv_res.is_ok()) {
        auto conv = conv_res.value();
        conv.set_last_activity_at(msg.sent_at());
        conv.set_unread_count(conv.unread_count() + 1);
        (void)local_store_.save_conversation(conv);
    }

    return ClientResult<domain::Message>::ok(std::move(msg));
}

ClientResult<std::optional<domain::Message>>
MessagingManager::process_inbound_realtime_event(const domain::RealtimeEvent& event) {
    switch (event.type) {
    case domain::RealtimeEventType::InboundDirectMessage: {
        if (event.conversation_id.empty() || event.actor_user_id.empty() || event.actor_device_id.empty() ||
            !event.direct_payload.has_value()) {
            return ClientResult<std::optional<domain::Message>>::error(
                ClientError::validation("Incomplete inbound direct message event"));
        }
        if (!event.message_id.empty()) {
            auto existing = local_store_.get_message(event.conversation_id, event.message_id);
            if (existing.is_ok()) {
                dispatch_delivery_ack_if_configured(event.conversation_id, existing.value().message_id());
                return ClientResult<std::optional<domain::Message>>::ok(existing.value());
            }
        }
        const auto sender_contact = local_store_.get_contact(event.actor_user_id);
        if (sender_contact.is_ok() && sender_contact.value().is_blocked()) {
            return ClientResult<std::optional<domain::Message>>::error(
                ClientError::validation("Inbound message dropped: sender is blocked"));
        }

        std::string decrypted_plaintext;
        if (ratchet_session_manager_ != nullptr) {
            auto dec_res = ratchet_session_manager_->decrypt_payload_from_device(
                event.actor_user_id, event.actor_device_id, *event.direct_payload);
            if (dec_res.is_error()) {
                return ClientResult<std::optional<domain::Message>>::error(dec_res.error());
            }
            decrypted_plaintext = dec_res.value().expose_unredacted_secret();
        } else {
            auto dec_res =
                crypto_provider_.decrypt_message(event.actor_device_id, event.direct_payload->ciphertext_blob);
            if (dec_res.is_error()) {
                return ClientResult<std::optional<domain::Message>>::error(dec_res.error());
            }
            decrypted_plaintext = dec_res.value();
        }

        const domain::MessageId mid =
            event.message_id.empty() ? domain::MessageId(generate_unique_id("msg-in")) : event.message_id;
        domain::Message msg(mid, event.conversation_id, event.actor_user_id, event.actor_device_id,
                            domain::DeliveryState::Delivered, std::chrono::system_clock::now(),
                            std::move(decrypted_plaintext), event.priority, std::string(event.actor_user_id.str()),
                            mid.value());
        msg.set_server_sequence_number(event.server_sequence_number);

        auto saved = persist_inbound_message(std::move(msg));
        if (saved.is_error()) {
            return ClientResult<std::optional<domain::Message>>::error(saved.error());
        }
        dispatch_delivery_ack_if_configured(event.conversation_id, saved.value().message_id());
        return ClientResult<std::optional<domain::Message>>::ok(saved.value());
    }
    case domain::RealtimeEventType::InboundGroupMessage: {
        if (event.conversation_id.empty() || event.actor_user_id.empty() || event.actor_device_id.empty() ||
            !event.group_envelope_bytes.has_value()) {
            return ClientResult<std::optional<domain::Message>>::error(
                ClientError::validation("Incomplete inbound group message event"));
        }
        if (!event.message_id.empty()) {
            auto existing = local_store_.get_message(event.conversation_id, event.message_id);
            if (existing.is_ok()) {
                dispatch_delivery_ack_if_configured(event.conversation_id, existing.value().message_id());
                return ClientResult<std::optional<domain::Message>>::ok(existing.value());
            }
        }
        if (!secure_storage_) {
            return ClientResult<std::optional<domain::Message>>::error(
                ClientError::crypto("ISecureStorage required to decrypt group message"));
        }
        const auto sender_contact = local_store_.get_contact(event.actor_user_id);
        if (sender_contact.is_ok() && sender_contact.value().is_blocked()) {
            return ClientResult<std::optional<domain::Message>>::error(
                ClientError::validation("Inbound group message dropped: sender is blocked"));
        }

        auto env_res = domain::crypto::GroupEncryptedEnvelope::deserialize(*event.group_envelope_bytes);
        if (env_res.is_error()) {
            return ClientResult<std::optional<domain::Message>>::error(env_res.error());
        }
        const auto& env = env_res.value();
        if (env.id.conversation_id != event.conversation_id || env.id.sender_user_id != event.actor_user_id ||
            env.id.sender_device_id != event.actor_device_id) {
            return ClientResult<std::optional<domain::Message>>::error(
                ClientError::crypto("GroupEncryptedEnvelope identity or conversation mismatch"));
        }

        auto state_res = load_sender_key_state(*secure_storage_, env.id);
        if (state_res.is_error()) {
            return ClientResult<std::optional<domain::Message>>::error(state_res.error());
        }
        auto sender_state = std::move(state_res.value());
        auto dec_res = domain::crypto::SenderKeyEngine::decrypt(crypto_provider_, sender_state, env);
        if (dec_res.is_error()) {
            return ClientResult<std::optional<domain::Message>>::error(dec_res.error());
        }
        auto save_sk_res = save_sender_key_state(*secure_storage_, sender_state);
        if (save_sk_res.is_error()) {
            return ClientResult<std::optional<domain::Message>>::error(save_sk_res.error());
        }

        const domain::MessageId mid =
            event.message_id.empty() ? domain::MessageId(generate_unique_id("msg-grp-in")) : event.message_id;
        domain::Message msg(mid, event.conversation_id, event.actor_user_id, event.actor_device_id,
                            domain::DeliveryState::Delivered, std::chrono::system_clock::now(),
                            dec_res.value().expose_unredacted_secret(), event.priority,
                            std::string(event.actor_user_id.str()), mid.value());
        msg.set_sender_key_epoch(env.id.key_epoch);
        msg.set_server_sequence_number(event.server_sequence_number);

        auto saved = persist_inbound_message(std::move(msg));
        if (saved.is_error()) {
            return ClientResult<std::optional<domain::Message>>::error(saved.error());
        }
        dispatch_delivery_ack_if_configured(event.conversation_id, saved.value().message_id());
        return ClientResult<std::optional<domain::Message>>::ok(saved.value());
    }
    case domain::RealtimeEventType::InboundSenderKeyDistribution: {
        if (!event.sender_key_distribution.has_value()) {
            return ClientResult<std::optional<domain::Message>>::error(
                ClientError::validation("SenderKeyDistributionMessage missing in event"));
        }
        auto sk_res = process_inbound_sender_key_distribution(event.actor_user_id, event.actor_device_id,
                                                              *event.sender_key_distribution);
        if (sk_res.is_error()) {
            return ClientResult<std::optional<domain::Message>>::error(sk_res.error());
        }
        return ClientResult<std::optional<domain::Message>>::ok(std::nullopt);
    }
    case domain::RealtimeEventType::DeliveryAck: {
        auto upd = update_message_delivery_state(event.conversation_id, event.message_id,
                                                 domain::DeliveryState::Delivered, event.server_sequence_number);
        if (upd.is_error()) {
            return ClientResult<std::optional<domain::Message>>::error(upd.error());
        }
        return ClientResult<std::optional<domain::Message>>::ok(std::nullopt);
    }
    case domain::RealtimeEventType::ReadReceipt: {
        auto upd = update_message_delivery_state(event.conversation_id, event.message_id, domain::DeliveryState::Read,
                                                 event.server_sequence_number);
        if (upd.is_error()) {
            return ClientResult<std::optional<domain::Message>>::error(upd.error());
        }
        return ClientResult<std::optional<domain::Message>>::ok(std::nullopt);
    }
    case domain::RealtimeEventType::PresenceUpdate:
        return ClientResult<std::optional<domain::Message>>::ok(std::nullopt);
    }
    return ClientResult<std::optional<domain::Message>>::ok(std::nullopt);
}

} // namespace securecloud::client::application::managers
