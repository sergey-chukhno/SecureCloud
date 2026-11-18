#pragma once

#include "application/client_config.hpp"
#include "application/interfaces/i_gateway_client.hpp"

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::client::infrastructure::adapters {

class DefaultGatewayClient final : public application::interfaces::IGatewayClient {
  public:
    explicit DefaultGatewayClient(const application::ClientConfig& config);
    ~DefaultGatewayClient() override = default;

    DefaultGatewayClient(const DefaultGatewayClient&) = delete;
    DefaultGatewayClient& operator=(const DefaultGatewayClient&) = delete;

    application::ClientResult<bool> probe_gateway(std::string_view path = "/health") override;
    application::ClientResult<std::string> send_message(const domain::ConversationId& conversation_id,
                                                        std::string_view encrypted_envelope) override;
    application::ClientResult<std::string>
    submit_encrypted_message(const application::interfaces::FanOutSubmissionRequest& request) override;
    application::ClientResult<std::vector<std::string>> sync_messages(std::string_view cursor) override;
    application::ClientResult<domain::DeliveryState> acknowledge_delivery(const domain::MessageId& message_id,
                                                                          const domain::DeviceId& recipient_device_id,
                                                                          int64_t delivered_at_ms) override;
    application::ClientResult<domain::DeliveryState> send_read_receipt(const domain::ConversationId& conversation_id,
                                                                       const domain::MessageId& message_id,
                                                                       const domain::DeviceId& reader_device_id,
                                                                       int64_t read_at_ms) override;
    application::ClientResult<domain::MessageDeliveryStatusInfo>
    get_message_delivery_status(const domain::ConversationId& conversation_id,
                                const domain::MessageId& message_id) override;
    application::ClientResult<domain::ConversationMessagesPage>
    fetch_conversation_messages(const domain::ConversationId& conversation_id,
                                const domain::DeviceId& recipient_device_id, uint64_t since_sequence,
                                std::size_t max_results = 50) override;
    uint64_t subscribe_realtime_events(RealtimeEventHandler handler) override;
    void unsubscribe_realtime_events(uint64_t subscription_id) override;
    application::ClientResult<bool> validate_token(std::string_view token) override;
    application::ClientResult<void> disconnect() override;

    application::ClientResult<application::interfaces::DeviceRegistrationResult>
    register_device(const domain::UserId& user_id, const domain::PrekeyBundle& bundle) override;

    application::ClientResult<application::interfaces::PrekeyUpdateResult>
    update_crypto_prekeys(const domain::DeviceId& device_id, std::optional<std::vector<uint8_t>> signed_prekey,
                          std::optional<std::vector<uint8_t>> signed_prekey_signature,
                          std::vector<domain::OneTimePrekeyRecord> one_time_prekeys) override;

    application::ClientResult<domain::PrekeyInventoryStatus>
    get_prekey_inventory_status(const domain::DeviceId& device_id) override;

    application::ClientResult<std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>
    get_device_crypto_directory(const domain::UserId& user_id,
                                const std::vector<domain::DeviceId>& device_ids = {}) override;

    application::ClientResult<application::interfaces::PairingInitiationResult>
    initiate_device_pairing(const domain::DeviceId& device_id) override;

    application::ClientResult<void> authorize_device_pairing(const domain::DeviceId& device_id,
                                                             std::string_view pairing_code,
                                                             std::string_view mfa_token) override;

    application::ClientResult<std::vector<domain::Device>> list_user_devices(const domain::UserId& user_id) override;

    application::ClientResult<void> revoke_device(const domain::DeviceId& device_id,
                                                  std::string_view mfa_token = "") override;

    application::ClientResult<std::vector<domain::DirectoryUserEntry>>
    search_directory_users(std::string_view query, std::size_t limit = 20) override;

    application::ClientResult<domain::DirectoryUserEntry> lookup_user_identity(const domain::UserId& user_id) override;

    // Test Hooks for deterministic simulation
    void set_simulated_inventory_status(domain::PrekeyInventoryStatus status);
    void set_simulated_registration_status(domain::DeviceAuthorizationStatus status, std::string pairing_code = "");
    void set_simulated_directory(std::vector<application::interfaces::DeviceCryptoDirectoryEntry> directory);
    void set_simulated_user_directory(const domain::UserId& user_id,
                                      std::vector<application::interfaces::DeviceCryptoDirectoryEntry> directory);
    void set_simulated_pairing_result(application::interfaces::PairingInitiationResult result);
    void set_simulated_user_devices(const domain::UserId& user_id, std::vector<domain::Device> devices);
    void set_simulated_directory_users(std::vector<domain::DirectoryUserEntry> users);
    void set_simulated_authorization_mfa_requirement(bool require_mfa);
    void set_simulated_revocation_mfa_requirement(bool require_mfa);
    void set_simulated_failure(bool fail, std::string error_message = "Simulated network failure");
    void set_simulated_submission_failure(bool fail, std::string error_message = "Simulated submission failure");
    [[nodiscard]] const std::vector<application::interfaces::FanOutSubmissionRequest>&
    submitted_fanouts() const noexcept {
        return submitted_fanouts_;
    }
    void clear_submitted_fanouts() noexcept { submitted_fanouts_.clear(); }
    void emit_realtime_event(const domain::RealtimeEvent& event);
    void set_simulated_delivery_status(const domain::MessageId& message_id, domain::MessageDeliveryStatusInfo status);
    void set_simulated_conversation_messages(const domain::ConversationId& conversation_id,
                                             std::vector<domain::RealtimeEvent> events);
    [[nodiscard]] const std::vector<domain::DeliveryAckRecord>& sent_delivery_acks() const noexcept {
        return sent_delivery_acks_;
    }
    [[nodiscard]] const std::vector<domain::ReadReceiptRecord>& sent_read_receipts() const noexcept {
        return sent_read_receipts_;
    }
    void clear_sent_receipts() noexcept {
        sent_delivery_acks_.clear();
        sent_read_receipts_.clear();
    }

  private:
    std::string endpoint_;
    bool connected_{false};
    uint64_t device_registration_counter_{1};
    uint64_t message_submission_counter_{1};
    std::vector<application::interfaces::FanOutSubmissionRequest> submitted_fanouts_;

    bool simulate_failure_{false};
    std::string failure_message_;
    bool simulate_submission_failure_{false};
    std::string submission_failure_message_;

    std::optional<domain::PrekeyInventoryStatus> simulated_inventory_;
    std::optional<domain::DeviceAuthorizationStatus> simulated_reg_status_;
    std::string simulated_pairing_code_;
    std::vector<application::interfaces::DeviceCryptoDirectoryEntry> simulated_directory_;
    std::unordered_map<domain::UserId, std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>
        simulated_user_directories_;

    std::optional<application::interfaces::PairingInitiationResult> simulated_pairing_result_;
    std::unordered_map<domain::UserId, std::vector<domain::Device>> simulated_user_devices_;
    std::vector<domain::DirectoryUserEntry> simulated_directory_users_;
    bool require_mfa_for_authorization_{true};
    bool require_mfa_for_revocation_{false};

    std::mutex event_mutex_;
    uint64_t next_subscription_id_{1};
    std::unordered_map<uint64_t, RealtimeEventHandler> event_subscribers_;
    std::vector<domain::DeliveryAckRecord> sent_delivery_acks_;
    std::vector<domain::ReadReceiptRecord> sent_read_receipts_;
    std::unordered_map<domain::MessageId, domain::MessageDeliveryStatusInfo> simulated_delivery_statuses_;
    std::unordered_map<domain::ConversationId, std::vector<domain::RealtimeEvent>> simulated_conversation_messages_;
};

} // namespace securecloud::client::infrastructure::adapters
