#pragma once

#include "application/client_error.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/device.hpp"
#include "domain/device_id.hpp"
#include "domain/directory_user_entry.hpp"
#include "domain/file_transfer.hpp"
#include "domain/offline_sync_models.hpp"
#include "domain/one_time_prekey_record.hpp"
#include "domain/prekey_bundle.hpp"
#include "domain/prekey_inventory_status.hpp"
#include "domain/realtime_events.hpp"
#include "domain/user_id.hpp"
#include "domain/user_profile.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::application::interfaces {

struct DeviceRegistrationResult {
    domain::DeviceId device_id;
    domain::DeviceAuthorizationStatus status{domain::DeviceAuthorizationStatus::Authorized};
    std::chrono::system_clock::time_point registered_at{std::chrono::system_clock::now()};
    std::string pairing_code;
    std::chrono::system_clock::time_point pairing_code_expires_at{};
};

struct PrekeyUpdateResult {
    int32_t active_one_time_prekey_count{0};
    std::chrono::system_clock::time_point updated_at{std::chrono::system_clock::now()};
};

struct PairingInitiationResult {
    domain::DeviceId device_id;
    std::string pairing_code;
    std::chrono::system_clock::time_point expires_at{std::chrono::system_clock::now() + std::chrono::minutes(10)};
};

struct DeviceCryptoDirectoryEntry {
    domain::DeviceId device_id;
    std::vector<uint8_t> identity_key;
    std::vector<uint8_t> signed_prekey;
    std::vector<uint8_t> signed_prekey_signature;
    std::optional<std::vector<uint8_t>> one_time_prekey;
    std::string one_time_prekey_id;
    domain::DeviceAuthorizationStatus status{domain::DeviceAuthorizationStatus::Authorized};
    std::string identity_key_fingerprint;
    int32_t remaining_one_time_prekeys{0};
    std::chrono::system_clock::time_point signed_prekey_created_at{std::chrono::system_clock::now()};
};

struct FanOutSubmissionRequest {
    domain::ConversationId conversation_id;
    std::string idempotency_key;
    std::vector<domain::crypto::PerDeviceDeliveryPayload> device_payloads;
    std::optional<std::vector<uint8_t>> group_envelope_bytes;
    int32_t priority{0};
};

struct FileUploadInitRequest {
    std::string file_id;
    domain::UserId owner_user_id;
    domain::DeviceId owner_device_id;
    domain::ConversationId conversation_id;
    uint64_t encrypted_size_bytes{0};
    uint32_t expected_chunk_count{0};
    std::string encryption_version{"v1"};
    std::string client_crypto_metadata;
};

struct FileUploadInitResult {
    std::string upload_id;
    std::string file_id;
    std::string status{"TRANSFER_STATUS_PENDING"};
    int64_t expires_at_unix_ms{0};
};

struct FileChunkUploadRequest {
    std::string upload_id;
    uint32_t chunk_index{0};
    std::vector<uint8_t> encrypted_data;
    std::string ciphertext_sha256;
};

struct FileChunkUploadResult {
    std::string upload_id;
    uint32_t chunk_index{0};
    bool accepted{false};
    std::string received_sha256;
};

struct FileUploadFinalizeRequest {
    std::string upload_id;
    std::string file_id;
    std::string expected_ciphertext_sha256;
};

struct FileUploadFinalizeResult {
    std::string file_id;
    std::string lifecycle_state{"FILE_LIFECYCLE_STATE_AVAILABLE"};
    int64_t available_at_unix_ms{0};
};

struct RemoteFileMetadata {
    std::string file_id;
    domain::UserId owner_user_id;
    domain::ConversationId conversation_id;
    std::string lifecycle_state;
    uint64_t encrypted_size_bytes{0};
    uint32_t chunk_count{0};
    std::string encryption_version{"v1"};
    std::string ciphertext_integrity_hash;
    int64_t created_at_unix_ms{0};
    int64_t available_at_unix_ms{0};
};

struct FileChunkDownloadResult {
    std::string file_id;
    uint32_t chunk_index{0};
    std::vector<uint8_t> encrypted_data;
    std::string ciphertext_sha256;
};

enum class ProfileSyncStatus {
    Synced,
    LocalOnlyServerUnsupported,
    SyncDisabledByPrivacyPolicy,
};

struct UserProfileSyncResult {
    domain::UserProfile profile{};
    ProfileSyncStatus sync_status{ProfileSyncStatus::Synced};

    bool operator==(const UserProfileSyncResult& other) const noexcept = default;
};

struct TlsCertificateInfo {
    std::string host{};
    uint16_t port{8443};
    std::string subject_cn{};
    std::string issuer_cn{};
    std::string spki_sha256_hex{};
    int64_t valid_from_ms{0};
    int64_t valid_until_ms{0};
    bool matches_pinned_key{true};
    bool has_pinned_key{false};

    bool operator==(const TlsCertificateInfo& other) const noexcept = default;
};

struct AuthSessionResult {
    domain::UserId user_id{};
    std::string device_id{};
    std::string session_id{};
    common::configuration::SecretString access_token{};
    common::configuration::SecretString refresh_token{};
    std::string authentication_level{};
    int64_t expires_at_epoch_ms{0};
    bool mfa_required{false};
    std::string mfa_challenge_id{};
};

struct ConversationCreateResult {
    domain::ConversationId conversation_id{};
    domain::ConversationType type{domain::ConversationType::Direct};
    std::string title{};
    domain::UserId creator_user_id{};
    int64_t created_at_ms{0};
    std::vector<domain::UserId> participant_user_ids{};
};

class IGatewayClient {
  public:
    using RealtimeEventHandler = std::function<void(const domain::RealtimeEvent&)>;

    virtual ~IGatewayClient() = default;

    virtual ClientResult<bool> probe_gateway(std::string_view path = "/health") = 0;
    virtual ClientResult<std::string> send_message(const domain::ConversationId& conversation_id,
                                                   std::string_view encrypted_envelope) = 0;
    virtual ClientResult<std::string> submit_encrypted_message(const FanOutSubmissionRequest& request) = 0;
    virtual ClientResult<std::vector<std::string>> sync_messages(std::string_view cursor) = 0;
    virtual ClientResult<domain::DeliveryState> acknowledge_delivery(const domain::MessageId& message_id,
                                                                     const domain::DeviceId& recipient_device_id,
                                                                     int64_t delivered_at_ms) = 0;
    virtual ClientResult<domain::DeliveryState> send_read_receipt(const domain::ConversationId& conversation_id,
                                                                  const domain::MessageId& message_id,
                                                                  const domain::DeviceId& reader_device_id,
                                                                  int64_t read_at_ms) = 0;
    virtual ClientResult<domain::MessageDeliveryStatusInfo>
    get_message_delivery_status(const domain::ConversationId& conversation_id, const domain::MessageId& message_id) = 0;
    virtual ClientResult<domain::ConversationMessagesPage>
    fetch_conversation_messages(const domain::ConversationId& conversation_id,
                                const domain::DeviceId& recipient_device_id, uint64_t since_sequence,
                                std::size_t max_results = 50) = 0;
    virtual ClientResult<domain::SyncCursorRecord> get_sync_cursor(const domain::DeviceId& device_id,
                                                                   const domain::ConversationId& conversation_id) = 0;
    virtual ClientResult<domain::SyncCursorRecord> update_sync_cursor(const domain::SyncCursorRecord& cursor) = 0;
    virtual ClientResult<std::vector<domain::RemoteConversationSummary>>
    list_remote_conversations(const domain::UserId& user_id, std::size_t max_results = 100) = 0;
    virtual uint64_t subscribe_realtime_events(RealtimeEventHandler handler) = 0;
    virtual void unsubscribe_realtime_events(uint64_t subscription_id) = 0;
    virtual ClientResult<bool> validate_token(std::string_view token) = 0;
    virtual ClientResult<void> disconnect() = 0;

    virtual ClientResult<DeviceRegistrationResult> register_device(const domain::UserId& user_id,
                                                                   const domain::PrekeyBundle& bundle) = 0;

    virtual ClientResult<PrekeyUpdateResult>
    update_crypto_prekeys(const domain::DeviceId& device_id, std::optional<std::vector<uint8_t>> signed_prekey,
                          std::optional<std::vector<uint8_t>> signed_prekey_signature,
                          std::vector<domain::OneTimePrekeyRecord> one_time_prekeys) = 0;

    virtual ClientResult<domain::PrekeyInventoryStatus>
    get_prekey_inventory_status(const domain::DeviceId& device_id) = 0;

    virtual ClientResult<std::vector<DeviceCryptoDirectoryEntry>>
    get_device_crypto_directory(const domain::UserId& user_id,
                                const std::vector<domain::DeviceId>& device_ids = {}) = 0;

    virtual ClientResult<PairingInitiationResult> initiate_device_pairing(const domain::DeviceId& device_id) = 0;

    virtual ClientResult<void> authorize_device_pairing(const domain::DeviceId& device_id,
                                                        std::string_view pairing_code, std::string_view mfa_token) = 0;

    virtual ClientResult<std::vector<domain::Device>> list_user_devices(const domain::UserId& user_id) = 0;

    virtual ClientResult<void> revoke_device(const domain::DeviceId& device_id, std::string_view mfa_token = "") = 0;

    virtual ClientResult<std::vector<domain::DirectoryUserEntry>> search_directory_users(std::string_view query,
                                                                                         std::size_t limit = 20) = 0;

    virtual ClientResult<domain::DirectoryUserEntry> lookup_user_identity(const domain::UserId& user_id) = 0;

    virtual ClientResult<FileUploadInitResult> init_file_upload(const FileUploadInitRequest& request) = 0;

    virtual ClientResult<FileChunkUploadResult> upload_file_chunk(const FileChunkUploadRequest& request) = 0;

    virtual ClientResult<FileUploadFinalizeResult> finalize_file_upload(const FileUploadFinalizeRequest& request) = 0;

    virtual ClientResult<void> cancel_file_upload(std::string_view upload_id, std::string_view reason = "") = 0;

    virtual ClientResult<RemoteFileMetadata> get_file_metadata(std::string_view file_id) = 0;

    virtual ClientResult<FileChunkDownloadResult> download_file_chunk(std::string_view file_id,
                                                                      uint32_t chunk_index) = 0;

    virtual ClientResult<void> delete_file(std::string_view file_id) = 0;

    virtual ClientResult<domain::UserProfile> get_user_profile(const domain::UserId& user_id) = 0;

    virtual ClientResult<UserProfileSyncResult> update_user_profile(const domain::UserProfile& public_profile) = 0;

    virtual ClientResult<TlsCertificateInfo> inspect_tls_certificate(std::string_view host, uint16_t port) = 0;

    virtual ClientResult<AuthSessionResult> authenticate_user(std::string_view identifier,
                                                              std::string_view /*credential*/,
                                                              std::string_view /*device_id*/ = "") {
        const auto probe = probe_gateway("/health");
        if (probe.is_error()) {
            return ClientResult<AuthSessionResult>::error(probe.error());
        }
        AuthSessionResult synthetic;
        synthetic.user_id = domain::UserId(std::string(identifier));
        synthetic.session_id = "sim-session-" + std::string(identifier);
        synthetic.access_token = common::configuration::SecretString("session-token-for-" + std::string(identifier));
        synthetic.refresh_token = common::configuration::SecretString("refresh-token-for-" + std::string(identifier));
        return ClientResult<AuthSessionResult>::ok(std::move(synthetic));
    }

    virtual ClientResult<AuthSessionResult> refresh_session(std::string_view refresh_token,
                                                            std::string_view /*device_id*/ = "") {
        if (refresh_token.empty()) {
            return ClientResult<AuthSessionResult>::error(ClientError::validation("Refresh token cannot be empty"));
        }
        AuthSessionResult synthetic;
        synthetic.session_id = "sim-session-refreshed";
        synthetic.access_token = common::configuration::SecretString("refreshed-session-token");
        synthetic.refresh_token = common::configuration::SecretString("rotated-refresh-token");
        return ClientResult<AuthSessionResult>::ok(std::move(synthetic));
    }

    virtual ClientResult<void> revoke_session(std::string_view /*session_id*/,
                                              std::string_view /*reason*/ = "user_logout") {
        return ClientResult<void>::ok();
    }

    virtual ClientResult<ConversationCreateResult> create_direct_conversation(const domain::UserId& peer_user_id) {
        if (peer_user_id.empty()) {
            return ClientResult<ConversationCreateResult>::error(
                ClientError::validation("Peer user ID cannot be empty"));
        }
        ConversationCreateResult synthetic;
        synthetic.conversation_id = domain::ConversationId("conv-direct-" + peer_user_id.value());
        synthetic.type = domain::ConversationType::Direct;
        synthetic.participant_user_ids.push_back(peer_user_id);
        synthetic.created_at_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        return ClientResult<ConversationCreateResult>::ok(std::move(synthetic));
    }

    struct PeerPresenceInfo {
        domain::UserId user_id;
        std::string status{"offline"};
        int64_t last_active_unix_ms{0};
        std::string custom_status_message;
    };

    virtual ClientResult<void> update_presence(std::string_view /*status*/,
                                               std::string_view /*custom_status_message*/ = "") {
        return ClientResult<void>::ok();
    }

    virtual ClientResult<std::vector<PeerPresenceInfo>>
    batch_get_presence(const std::vector<domain::UserId>& /*user_ids*/) {
        return ClientResult<std::vector<PeerPresenceInfo>>::ok({});
    }
};

} // namespace securecloud::client::application::interfaces
