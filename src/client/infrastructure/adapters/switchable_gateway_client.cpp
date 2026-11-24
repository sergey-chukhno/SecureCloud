#include "infrastructure/adapters/switchable_gateway_client.hpp"

namespace securecloud::client::infrastructure::adapters {

SwitchableGatewayClient::SwitchableGatewayClient(const application::ClientConfig& config,
                                                 QtHttpGatewayClient::BearerTokenProvider token_provider)
    : simulated_(std::make_unique<DefaultGatewayClient>(config)),
      live_(std::make_unique<QtHttpGatewayClient>(config, std::move(token_provider))),
      use_live_(config.use_live_gateway_transport) {}

void SwitchableGatewayClient::reconfigure(const application::ClientConfig& config) {
    live_->reconfigure(config);
    simulated_->set_pinned_tls_spki_sha256(config.pinned_tls_spki_sha256);
    use_live_.store(config.use_live_gateway_transport);
}

application::interfaces::IGatewayClient& SwitchableGatewayClient::active_gateway() noexcept {
    return use_live_.load() ? static_cast<application::interfaces::IGatewayClient&>(*live_)
                            : static_cast<application::interfaces::IGatewayClient&>(*simulated_);
}

const application::interfaces::IGatewayClient& SwitchableGatewayClient::active_gateway() const noexcept {
    return use_live_.load() ? static_cast<const application::interfaces::IGatewayClient&>(*live_)
                            : static_cast<const application::interfaces::IGatewayClient&>(*simulated_);
}

application::ClientResult<bool> SwitchableGatewayClient::probe_gateway(std::string_view path) {
    return active_gateway().probe_gateway(path);
}

application::ClientResult<std::string>
SwitchableGatewayClient::send_message(const domain::ConversationId& conversation_id,
                                      std::string_view encrypted_envelope) {
    return active_gateway().send_message(conversation_id, encrypted_envelope);
}

application::ClientResult<std::string>
SwitchableGatewayClient::submit_encrypted_message(const application::interfaces::FanOutSubmissionRequest& request) {
    return active_gateway().submit_encrypted_message(request);
}

application::ClientResult<std::vector<std::string>> SwitchableGatewayClient::sync_messages(std::string_view cursor) {
    return active_gateway().sync_messages(cursor);
}

application::ClientResult<domain::DeliveryState>
SwitchableGatewayClient::acknowledge_delivery(const domain::MessageId& message_id,
                                              const domain::DeviceId& recipient_device_id, int64_t delivered_at_ms) {
    return active_gateway().acknowledge_delivery(message_id, recipient_device_id, delivered_at_ms);
}

application::ClientResult<domain::DeliveryState>
SwitchableGatewayClient::send_read_receipt(const domain::ConversationId& conversation_id,
                                           const domain::MessageId& message_id,
                                           const domain::DeviceId& reader_device_id, int64_t read_at_ms) {
    return active_gateway().send_read_receipt(conversation_id, message_id, reader_device_id, read_at_ms);
}

application::ClientResult<domain::MessageDeliveryStatusInfo>
SwitchableGatewayClient::get_message_delivery_status(const domain::ConversationId& conversation_id,
                                                     const domain::MessageId& message_id) {
    return active_gateway().get_message_delivery_status(conversation_id, message_id);
}

application::ClientResult<domain::ConversationMessagesPage>
SwitchableGatewayClient::fetch_conversation_messages(const domain::ConversationId& conversation_id,
                                                     const domain::DeviceId& recipient_device_id,
                                                     uint64_t since_sequence, std::size_t max_results) {
    return active_gateway().fetch_conversation_messages(conversation_id, recipient_device_id, since_sequence,
                                                        max_results);
}

application::ClientResult<domain::SyncCursorRecord>
SwitchableGatewayClient::get_sync_cursor(const domain::DeviceId& device_id,
                                         const domain::ConversationId& conversation_id) {
    return active_gateway().get_sync_cursor(device_id, conversation_id);
}

application::ClientResult<domain::SyncCursorRecord>
SwitchableGatewayClient::update_sync_cursor(const domain::SyncCursorRecord& cursor) {
    return active_gateway().update_sync_cursor(cursor);
}

application::ClientResult<std::vector<domain::RemoteConversationSummary>>
SwitchableGatewayClient::list_remote_conversations(const domain::UserId& user_id, std::size_t max_results) {
    return active_gateway().list_remote_conversations(user_id, max_results);
}

uint64_t SwitchableGatewayClient::subscribe_realtime_events(RealtimeEventHandler handler) {
    const TargetAdapter target = use_live_.load() ? TargetAdapter::Live : TargetAdapter::Simulated;
    const uint64_t inner_id = (target == TargetAdapter::Live)
                                  ? live_->subscribe_realtime_events(std::move(handler))
                                  : simulated_->subscribe_realtime_events(std::move(handler));
    std::lock_guard<std::mutex> lock(subscription_mutex_);
    const uint64_t wrapper_id = next_wrapper_sub_id_++;
    subscription_map_.emplace(wrapper_id, std::make_pair(target, inner_id));
    return wrapper_id;
}

void SwitchableGatewayClient::unsubscribe_realtime_events(uint64_t subscription_id) {
    std::optional<std::pair<TargetAdapter, uint64_t>> entry;
    {
        std::lock_guard<std::mutex> lock(subscription_mutex_);
        const auto it = subscription_map_.find(subscription_id);
        if (it != subscription_map_.end()) {
            entry = it->second;
            subscription_map_.erase(it);
        }
    }
    if (!entry.has_value()) {
        return;
    }
    if (entry->first == TargetAdapter::Live) {
        live_->unsubscribe_realtime_events(entry->second);
    } else {
        simulated_->unsubscribe_realtime_events(entry->second);
    }
}

application::ClientResult<bool> SwitchableGatewayClient::validate_token(std::string_view token) {
    return active_gateway().validate_token(token);
}

application::ClientResult<void> SwitchableGatewayClient::disconnect() {
    if (use_live_.load()) {
        (void)simulated_->disconnect();
        return live_->disconnect();
    }
    (void)live_->disconnect();
    return simulated_->disconnect();
}

application::ClientResult<application::interfaces::DeviceRegistrationResult>
SwitchableGatewayClient::register_device(const domain::UserId& user_id, const domain::PrekeyBundle& bundle) {
    return active_gateway().register_device(user_id, bundle);
}

application::ClientResult<application::interfaces::PrekeyUpdateResult>
SwitchableGatewayClient::update_crypto_prekeys(const domain::DeviceId& device_id,
                                               std::optional<std::vector<uint8_t>> signed_prekey,
                                               std::optional<std::vector<uint8_t>> signed_prekey_signature,
                                               std::vector<domain::OneTimePrekeyRecord> one_time_prekeys) {
    return active_gateway().update_crypto_prekeys(device_id, std::move(signed_prekey),
                                                  std::move(signed_prekey_signature), std::move(one_time_prekeys));
}

application::ClientResult<domain::PrekeyInventoryStatus>
SwitchableGatewayClient::get_prekey_inventory_status(const domain::DeviceId& device_id) {
    return active_gateway().get_prekey_inventory_status(device_id);
}

application::ClientResult<std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>
SwitchableGatewayClient::get_device_crypto_directory(const domain::UserId& user_id,
                                                     const std::vector<domain::DeviceId>& device_ids) {
    return active_gateway().get_device_crypto_directory(user_id, device_ids);
}

application::ClientResult<application::interfaces::PairingInitiationResult>
SwitchableGatewayClient::initiate_device_pairing(const domain::DeviceId& device_id) {
    return active_gateway().initiate_device_pairing(device_id);
}

application::ClientResult<void> SwitchableGatewayClient::authorize_device_pairing(const domain::DeviceId& device_id,
                                                                                  std::string_view pairing_code,
                                                                                  std::string_view mfa_token) {
    return active_gateway().authorize_device_pairing(device_id, pairing_code, mfa_token);
}

application::ClientResult<std::vector<domain::Device>>
SwitchableGatewayClient::list_user_devices(const domain::UserId& user_id) {
    return active_gateway().list_user_devices(user_id);
}

application::ClientResult<void> SwitchableGatewayClient::revoke_device(const domain::DeviceId& device_id,
                                                                       std::string_view mfa_token) {
    return active_gateway().revoke_device(device_id, mfa_token);
}

application::ClientResult<std::vector<domain::DirectoryUserEntry>>
SwitchableGatewayClient::search_directory_users(std::string_view query, std::size_t limit) {
    return active_gateway().search_directory_users(query, limit);
}

application::ClientResult<domain::DirectoryUserEntry>
SwitchableGatewayClient::lookup_user_identity(const domain::UserId& user_id) {
    return active_gateway().lookup_user_identity(user_id);
}

application::ClientResult<application::interfaces::FileUploadInitResult>
SwitchableGatewayClient::init_file_upload(const application::interfaces::FileUploadInitRequest& request) {
    return active_gateway().init_file_upload(request);
}

application::ClientResult<application::interfaces::FileChunkUploadResult>
SwitchableGatewayClient::upload_file_chunk(const application::interfaces::FileChunkUploadRequest& request) {
    return active_gateway().upload_file_chunk(request);
}

application::ClientResult<application::interfaces::FileUploadFinalizeResult>
SwitchableGatewayClient::finalize_file_upload(const application::interfaces::FileUploadFinalizeRequest& request) {
    return active_gateway().finalize_file_upload(request);
}

application::ClientResult<void> SwitchableGatewayClient::cancel_file_upload(std::string_view upload_id,
                                                                            std::string_view reason) {
    return active_gateway().cancel_file_upload(upload_id, reason);
}

application::ClientResult<application::interfaces::RemoteFileMetadata>
SwitchableGatewayClient::get_file_metadata(std::string_view file_id) {
    return active_gateway().get_file_metadata(file_id);
}

application::ClientResult<application::interfaces::FileChunkDownloadResult>
SwitchableGatewayClient::download_file_chunk(std::string_view file_id, uint32_t chunk_index) {
    return active_gateway().download_file_chunk(file_id, chunk_index);
}

application::ClientResult<void> SwitchableGatewayClient::delete_file(std::string_view file_id) {
    return active_gateway().delete_file(file_id);
}

application::ClientResult<domain::UserProfile>
SwitchableGatewayClient::get_user_profile(const domain::UserId& user_id) {
    return active_gateway().get_user_profile(user_id);
}

application::ClientResult<application::interfaces::UserProfileSyncResult>
SwitchableGatewayClient::update_user_profile(const domain::UserProfile& public_profile) {
    return active_gateway().update_user_profile(public_profile);
}

application::ClientResult<application::interfaces::TlsCertificateInfo>
SwitchableGatewayClient::inspect_tls_certificate(std::string_view host, uint16_t port) {
    return active_gateway().inspect_tls_certificate(host, port);
}

} // namespace securecloud::client::infrastructure::adapters
