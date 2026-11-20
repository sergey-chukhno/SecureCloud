#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/conversation_id.hpp"
#include "domain/device_id.hpp"
#include "domain/file_transfer.hpp"
#include "domain/message.hpp"
#include "domain/user_id.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace securecloud::client::application::managers {

class MessagingManager;

struct FileUploadRequest {
    domain::ConversationId conversation_id;
    domain::UserId owner_user_id;
    domain::DeviceId owner_device_id;
    domain::UserId peer_user_id;
    std::string local_file_path;
    std::string mime_type{"application/octet-stream"};
    std::string sender_display_name;
    int32_t priority{0};
    bool dispatch_key_envelope{true};
};

struct FileUploadResult {
    domain::FileTransferRecord record;
    std::optional<domain::FileAttachmentKeyEnvelope> key_envelope;
    std::optional<domain::Message> dispatched_message;
};

class FileManager {
  public:
    using ProgressCallback = std::function<void(const domain::FileTransferRecord&)>;

    FileManager(interfaces::IGatewayClient& gateway, interfaces::ICryptoProvider& crypto_provider,
                interfaces::ILocalStore* local_store = nullptr, interfaces::ISecureStorage* secure_storage = nullptr,
                MessagingManager* messaging_manager = nullptr);
    ~FileManager() = default;

    FileManager(const FileManager&) = delete;
    FileManager& operator=(const FileManager&) = delete;

    void set_local_store(interfaces::ILocalStore* local_store) noexcept;
    void set_secure_storage(interfaces::ISecureStorage* secure_storage) noexcept;
    void set_messaging_manager(MessagingManager* messaging_manager) noexcept;
    void set_local_identity(const domain::UserId& user_id, const domain::DeviceId& device_id);
    ClientResult<void> set_wire_chunk_size(uint32_t wire_chunk_size);
    [[nodiscard]] uint32_t wire_chunk_size() const noexcept;
    void set_progress_callback(ProgressCallback callback);

    [[nodiscard]] static std::string file_key_storage_id(std::string_view file_id);

    ClientResult<FileUploadResult> start_upload(const FileUploadRequest& request);
    ClientResult<FileUploadResult> resume_upload(std::string_view transfer_id, const domain::UserId& owner_user_id = {},
                                                 const domain::DeviceId& owner_device_id = {},
                                                 const std::string& sender_display_name = "", int32_t priority = 0,
                                                 bool dispatch_key_envelope = true);

    ClientResult<domain::FileTransferRecord>
    ingest_inbound_key_envelope(const domain::ConversationId& conversation_id, const domain::UserId& peer_user_id,
                                const domain::FileAttachmentKeyEnvelope& envelope);
    ClientResult<domain::FileTransferRecord>
    ingest_inbound_key_envelope_json(const domain::ConversationId& conversation_id, const domain::UserId& peer_user_id,
                                     std::string_view decrypted_payload_json);

    ClientResult<domain::FileTransferRecord> start_download(std::string_view transfer_id,
                                                            std::string_view destination_path);
    ClientResult<domain::FileTransferRecord> resume_download(std::string_view transfer_id);
    ClientResult<domain::FileTransferRecord> resume_transfer(std::string_view transfer_id);
    ClientResult<std::size_t> resume_interrupted_transfers();

    ClientResult<void> pause_transfer(std::string_view transfer_id);
    ClientResult<void> cancel_transfer(std::string_view transfer_id);

    ClientResult<domain::FileTransferRecord> get_transfer(std::string_view transfer_id);
    ClientResult<std::vector<domain::FileTransferRecord>>
    list_transfers(const domain::ConversationId& conversation_id = {});

    // Legacy compatibility helper retained for pre-T05 WorkspaceViewModel calls
    ClientResult<std::string> prepare_encrypted_upload(std::string_view local_file_path);

    [[nodiscard]] interfaces::ICryptoProvider& crypto_provider() noexcept { return crypto_provider_; }

  private:
    enum class ControlAction { None, Pause, Cancel };

    class ActiveTransferGuard final {
      public:
        ActiveTransferGuard(FileManager& owner, std::string transfer_id);
        ~ActiveTransferGuard();

        ActiveTransferGuard(const ActiveTransferGuard&) = delete;
        ActiveTransferGuard& operator=(const ActiveTransferGuard&) = delete;

      private:
        FileManager& owner_;
        std::string transfer_id_;
    };

    ClientResult<FileUploadResult> execute_upload_loop(domain::FileTransferRecord record,
                                                       const domain::UserId& owner_user_id,
                                                       const domain::DeviceId& owner_device_id,
                                                       const std::string& sender_display_name, int32_t priority,
                                                       bool dispatch_key_envelope);

    ClientResult<domain::FileTransferRecord> execute_download_loop(domain::FileTransferRecord record);

    ClientResult<void> ensure_stateful_storage() const;
    ClientResult<void> persist_and_notify(domain::FileTransferRecord& record) const;
    void notify_progress(const domain::FileTransferRecord& record) const;
    [[nodiscard]] ControlAction poll_control_action(std::string_view transfer_id) const;
    ClientResult<void> abort_and_mark_cancelled(domain::FileTransferRecord& record);

    interfaces::IGatewayClient& gateway_;
    interfaces::ICryptoProvider& crypto_provider_;
    interfaces::ILocalStore* local_store_{nullptr};
    interfaces::ISecureStorage* secure_storage_{nullptr};
    MessagingManager* messaging_manager_{nullptr};

    mutable std::mutex control_mutex_;
    domain::UserId local_user_id_;
    domain::DeviceId local_device_id_;
    uint32_t wire_chunk_size_{domain::kDefaultFileWireChunkSize};
    ProgressCallback progress_callback_;
    std::unordered_set<std::string> active_transfers_;
    std::unordered_set<std::string> pause_requested_transfers_;
    std::unordered_set<std::string> cancel_requested_transfers_;
};

} // namespace securecloud::client::application::managers
