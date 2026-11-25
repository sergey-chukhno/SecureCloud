#pragma once

#include "application/client_config.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "domain/diagnostics_models.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::infrastructure::adapters {

/// Production live HTTPS TLS 1.3 gateway transport adapter backed by Qt6::Network.
/// Enforces fail-closed TLS 1.3 + SPKI SHA-256 certificate pinning, HTTP/SOCKS5 proxy
/// routing, bounded timeouts/reads, and thread-safe marshaling onto an internal Qt thread.
class QtHttpGatewayClient final : public application::interfaces::IGatewayClient {
  public:
    using BearerTokenProvider = std::function<std::optional<common::configuration::SecretString>()>;

    struct EffectiveProxySnapshot {
        domain::ProxyType type{domain::ProxyType::None};
        std::string host{};
        uint16_t port{0};
        std::string username{};
        bool has_password{false};

        bool operator==(const EffectiveProxySnapshot& other) const noexcept = default;
    };

    static constexpr std::size_t kMaxJsonResponseBytes = 4U * 1024U * 1024U;
    static constexpr std::size_t kMaxBinaryResponseBytes = 32U * 1024U * 1024U;

    explicit QtHttpGatewayClient(application::ClientConfig config, BearerTokenProvider token_provider = {});
    ~QtHttpGatewayClient() override;

    QtHttpGatewayClient(const QtHttpGatewayClient&) = delete;
    QtHttpGatewayClient& operator=(const QtHttpGatewayClient&) = delete;
    QtHttpGatewayClient(QtHttpGatewayClient&&) = delete;
    QtHttpGatewayClient& operator=(QtHttpGatewayClient&&) = delete;

    void reconfigure(const application::ClientConfig& config);
    [[nodiscard]] application::ClientConfig current_config_snapshot() const;
    [[nodiscard]] EffectiveProxySnapshot effective_proxy_snapshot() const;
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

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace securecloud::client::infrastructure::adapters
