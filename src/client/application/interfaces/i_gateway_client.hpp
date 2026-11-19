#pragma once

#include "application/client_error.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/device.hpp"
#include "domain/device_id.hpp"
#include "domain/directory_user_entry.hpp"
#include "domain/file_transfer.hpp"
#include "domain/one_time_prekey_record.hpp"
#include "domain/prekey_bundle.hpp"
#include "domain/prekey_inventory_status.hpp"
#include "domain/realtime_events.hpp"
#include "domain/user_id.hpp"

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
};

} // namespace securecloud::client::application::interfaces
