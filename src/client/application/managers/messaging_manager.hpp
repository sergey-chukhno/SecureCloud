#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "application/managers/delivery_retry_engine.hpp"
#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/delivery_state.hpp"
#include "domain/message.hpp"
#include "domain/message_id.hpp"
#include "domain/realtime_events.hpp"
#include "domain/user_id.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain::crypto {
struct PerDeviceDeliveryPayload;
struct EncryptedMessageEnvelope;
struct SenderKeyDistributionMessage;
} // namespace securecloud::client::domain::crypto

namespace securecloud::client::application::managers {

class RatchetSessionManager;

class MessagingManager {
  public:
    MessagingManager(interfaces::IGatewayClient& gateway, interfaces::ILocalStore& local_store,
                     interfaces::ICryptoProvider& crypto_provider,
                     RatchetSessionManager* ratchet_session_manager = nullptr,
                     interfaces::ISecureStorage* secure_storage = nullptr);
    ~MessagingManager() = default;

    MessagingManager(const MessagingManager&) = delete;
    MessagingManager& operator=(const MessagingManager&) = delete;

    void set_ratchet_session_manager(RatchetSessionManager* ratchet_session_manager) noexcept;
    [[nodiscard]] RatchetSessionManager* ratchet_session_manager() noexcept;
    void set_secure_storage(interfaces::ISecureStorage* secure_storage) noexcept;
    void set_local_device_id(const domain::DeviceId& device_id);
    [[nodiscard]] const domain::DeviceId& local_device_id() const noexcept;

    ClientResult<void> set_read_receipts_enabled(bool enabled);
    [[nodiscard]] bool read_receipts_enabled() const noexcept;

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
    ClientResult<void> add_group_participant(const domain::ConversationId& conversation_id,
                                             const domain::UserId& actor_user_id, const domain::UserId& target_user_id);
    ClientResult<void> remove_group_participant(const domain::ConversationId& conversation_id,
                                                const domain::UserId& user_id);
    ClientResult<void> remove_group_participant(const domain::ConversationId& conversation_id,
                                                const domain::UserId& actor_user_id,
                                                const domain::UserId& target_user_id);
    ClientResult<void> leave_conversation(const domain::ConversationId& conversation_id,
                                          const domain::UserId& local_user_id);
    ClientResult<void> delete_conversation(const domain::ConversationId& conversation_id);
    ClientResult<void> mark_conversation_read(const domain::ConversationId& conversation_id,
                                              const domain::UserId& local_user_id = {},
                                              const domain::DeviceId& reader_device_id = {});

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
                                                     domain::DeliveryState new_state,
                                                     uint64_t server_sequence_number = 0);

    ClientResult<void> discard_failed_message(const domain::ConversationId& conversation_id,
                                              const domain::MessageId& message_id);

    void set_retry_policy(const domain::RetryPolicyConfig& config);
    std::size_t process_retry_queue(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
    [[nodiscard]] std::size_t pending_retry_count() const;

    ClientResult<std::vector<domain::Message>> get_conversation_messages(const domain::ConversationId& conversation_id,
                                                                         std::size_t limit = 50);

    // Inbound Message Decryption & Processing (Double Ratchet)
    ClientResult<domain::Message> process_inbound_message(const domain::ConversationId& conversation_id,
                                                          const domain::UserId& sender_user_id,
                                                          const domain::DeviceId& sender_device_id,
                                                          const domain::crypto::PerDeviceDeliveryPayload& payload,
                                                          int32_t priority = 0,
                                                          const std::string& sender_display_name = "");

    ClientResult<domain::Message> process_inbound_message(const domain::ConversationId& conversation_id,
                                                          const domain::UserId& sender_user_id,
                                                          const domain::DeviceId& sender_device_id,
                                                          const domain::crypto::EncryptedMessageEnvelope& envelope,
                                                          int32_t priority = 0,
                                                          const std::string& sender_display_name = "");

    // Group Sender Key Distribution & Encrypted Group Message Processing
    ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>
    distribute_sender_key(const domain::ConversationId& conversation_id, const domain::UserId& sender_user_id,
                          const domain::DeviceId& sender_device_id);

    ClientResult<void>
    process_inbound_sender_key_distribution(const domain::UserId& sender_user_id,
                                            const domain::DeviceId& sender_device_id,
                                            const domain::crypto::SenderKeyDistributionMessage& distribution);

    ClientResult<domain::Message> process_inbound_group_message(const domain::ConversationId& conversation_id,
                                                                const domain::UserId& sender_user_id,
                                                                const domain::DeviceId& sender_device_id,
                                                                std::span<const uint8_t> group_envelope_bytes,
                                                                int32_t priority = 0,
                                                                const std::string& sender_display_name = "");

    ClientResult<std::optional<domain::Message>> process_inbound_realtime_event(const domain::RealtimeEvent& event);

    [[nodiscard]] ClientResult<void> check_conversation_send_eligibility(const domain::ConversationId& conversation_id,
                                                                         const domain::UserId& sender_user_id) const;

  private:
    ClientResult<void> validate_recipients_can_receive(const domain::Conversation& conv,
                                                       const domain::UserId& sender_user_id) const;
    ClientResult<domain::Message> persist_inbound_message(domain::Message msg);
    void dispatch_delivery_ack_if_configured(const domain::MessageId& message_id);
    void hydrate_read_receipt_policy();

    interfaces::IGatewayClient& gateway_;
    interfaces::ILocalStore& local_store_;
    interfaces::ICryptoProvider& crypto_provider_;
    RatchetSessionManager* ratchet_session_manager_{nullptr};
    interfaces::ISecureStorage* secure_storage_{nullptr};
    DeliveryRetryEngine retry_engine_;
    domain::DeviceId local_device_id_;
    domain::ReadReceiptPolicy read_receipt_policy_;
};

} // namespace securecloud::client::application::managers
