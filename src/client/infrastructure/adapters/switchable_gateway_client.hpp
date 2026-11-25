#pragma once

#include "application/client_config.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "domain/diagnostics_models.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/qt_http_gateway_client.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>

namespace securecloud::client::infrastructure::adapters {

/// Hot-switchable IGatewayClient delegating seamlessly between offline simulated mode
/// (`DefaultGatewayClient`) and production live TLS 1.3 (`QtHttpGatewayClient`) without
/// invalidating manager references held inside ClientBootstrap.
class SwitchableGatewayClient final : public application::interfaces::IGatewayClient {
  public:
    explicit SwitchableGatewayClient(const application::ClientConfig& config,
                                     QtHttpGatewayClient::BearerTokenProvider token_provider = {});
    ~SwitchableGatewayClient() override = default;

    SwitchableGatewayClient(const SwitchableGatewayClient&) = delete;
    SwitchableGatewayClient& operator=(const SwitchableGatewayClient&) = delete;

    void reconfigure(const application::ClientConfig& config);

    [[nodiscard]] bool is_live_transport_active() const noexcept { return use_live_.load(); }
    [[nodiscard]] application::interfaces::IGatewayClient& active_gateway() noexcept;
    [[nodiscard]] const application::interfaces::IGatewayClient& active_gateway() const noexcept;
    [[nodiscard]] DefaultGatewayClient& simulated_gateway() noexcept { return *simulated_; }
    [[nodiscard]] QtHttpGatewayClient& live_gateway() noexcept { return *live_; }
    [[nodiscard]] domain::GatewayTransportMetrics transport_metrics() const noexcept;

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
    application::ClientResult<domain::SyncCursorRecord>
    get_sync_cursor(const domain::DeviceId& device_id, const domain::ConversationId& conversation_id) override;
    application::ClientResult<domain::SyncCursorRecord>
    update_sync_cursor(const domain::SyncCursorRecord& cursor) override;
    application::ClientResult<std::vector<domain::RemoteConversationSummary>>
    list_remote_conversations(const domain::UserId& user_id, std::size_t max_results = 100) override;
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

    application::ClientResult<application::interfaces::FileUploadInitResult>
    init_file_upload(const application::interfaces::FileUploadInitRequest& request) override;

    application::ClientResult<application::interfaces::FileChunkUploadResult>
    upload_file_chunk(const application::interfaces::FileChunkUploadRequest& request) override;

    application::ClientResult<application::interfaces::FileUploadFinalizeResult>
    finalize_file_upload(const application::interfaces::FileUploadFinalizeRequest& request) override;

    application::ClientResult<void> cancel_file_upload(std::string_view upload_id,
                                                       std::string_view reason = "") override;

    application::ClientResult<application::interfaces::RemoteFileMetadata>
    get_file_metadata(std::string_view file_id) override;

    application::ClientResult<application::interfaces::FileChunkDownloadResult>
    download_file_chunk(std::string_view file_id, uint32_t chunk_index) override;

    application::ClientResult<void> delete_file(std::string_view file_id) override;

    application::ClientResult<domain::UserProfile> get_user_profile(const domain::UserId& user_id) override;

    application::ClientResult<application::interfaces::UserProfileSyncResult>
    update_user_profile(const domain::UserProfile& public_profile) override;

    application::ClientResult<application::interfaces::TlsCertificateInfo>
    inspect_tls_certificate(std::string_view host, uint16_t port) override;

    application::ClientResult<application::interfaces::AuthSessionResult>
    authenticate_user(std::string_view identifier, std::string_view credential,
                      std::string_view device_id = "") override;

    application::ClientResult<application::interfaces::AuthSessionResult>
    refresh_session(std::string_view refresh_token, std::string_view device_id = "") override;

    application::ClientResult<void> revoke_session(std::string_view session_id,
                                                   std::string_view reason = "user_logout") override;

    application::ClientResult<application::interfaces::ConversationCreateResult>
    create_direct_conversation(const domain::UserId& peer_user_id) override;

    application::ClientResult<void> update_presence(std::string_view status,
                                                    std::string_view custom_status_message = "") override;

    application::ClientResult<std::vector<application::interfaces::IGatewayClient::PeerPresenceInfo>>
    batch_get_presence(const std::vector<domain::UserId>& user_ids) override;

  private:
    enum class TargetAdapter { Simulated, Live };

    std::unique_ptr<DefaultGatewayClient> simulated_;
    std::unique_ptr<QtHttpGatewayClient> live_;
    std::atomic<bool> use_live_{false};

    mutable std::mutex subscription_mutex_;
    uint64_t next_wrapper_sub_id_{1};
    std::unordered_map<uint64_t, std::pair<TargetAdapter, uint64_t>> subscription_map_;
};

} // namespace securecloud::client::infrastructure::adapters
