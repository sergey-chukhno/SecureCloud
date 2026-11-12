#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/crypto/ratchet_session_state.hpp"
#include "domain/device_id.hpp"
#include "domain/user_id.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace securecloud::client::application::managers {

class RatchetSessionManager {
  public:
    static constexpr std::string_view kSessionKeyPrefix = "ratchet_session:";
    static constexpr std::string_view kSessionIndexKey = "ratchet_session_index";

    RatchetSessionManager(interfaces::IGatewayClient& gateway, interfaces::ISecureStorage& secure_storage,
                          interfaces::ICryptoProvider& crypto_provider, domain::UserId local_user_id,
                          domain::DeviceId local_device_id);

    ~RatchetSessionManager() = default;

    RatchetSessionManager(const RatchetSessionManager&) = delete;
    RatchetSessionManager& operator=(const RatchetSessionManager&) = delete;

    // Outbound Encryption
    ClientResult<domain::crypto::EncryptedMessageEnvelope> encrypt_for_device(const domain::UserId& peer_user_id,
                                                                              const domain::DeviceId& peer_device_id,
                                                                              std::span<const uint8_t> plaintext);

    ClientResult<domain::crypto::PerDeviceDeliveryPayload>
    encrypt_payload_for_device(const domain::UserId& peer_user_id, const domain::DeviceId& peer_device_id,
                               std::span<const uint8_t> plaintext);

    ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>
    encrypt_fanout(const std::vector<std::pair<domain::UserId, domain::DeviceId>>& targets,
                   std::span<const uint8_t> plaintext);

    ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>
    encrypt_fanout_for_participants(const std::vector<domain::UserId>& participants,
                                    std::span<const uint8_t> plaintext);

    // Inbound Decryption
    ClientResult<securecloud::common::configuration::SecretString>
    decrypt_from_device(const domain::UserId& sender_user_id, const domain::DeviceId& sender_device_id,
                        const domain::crypto::EncryptedMessageEnvelope& envelope);

    ClientResult<securecloud::common::configuration::SecretString>
    decrypt_payload_from_device(const domain::UserId& sender_user_id, const domain::DeviceId& sender_device_id,
                                const domain::crypto::PerDeviceDeliveryPayload& payload);

    // Persistence & Lifecycle
    ClientResult<void> save_session(const domain::UserId& peer_user_id, const domain::DeviceId& peer_device_id);
    ClientResult<void> load_session(const domain::UserId& peer_user_id, const domain::DeviceId& peer_device_id);
    ClientResult<void> load_all_sessions();
    ClientResult<void> terminate_session(const domain::UserId& peer_user_id, const domain::DeviceId& peer_device_id);
    ClientResult<void> purge_device_sessions(const domain::DeviceId& device_id);

    [[nodiscard]] bool has_session(const domain::UserId& peer_user_id, const domain::DeviceId& peer_device_id) const;
    [[nodiscard]] std::optional<std::vector<uint8_t>>
    get_peer_identity_key(const domain::UserId& peer_user_id, const domain::DeviceId& peer_device_id) const;
    [[nodiscard]] std::size_t active_session_count() const noexcept;

    static std::string make_storage_key(const domain::UserId& peer_user_id, const domain::DeviceId& peer_device_id);

  private:
    ClientResult<void> ensure_outbound_session(const domain::UserId& peer_user_id,
                                               const domain::DeviceId& peer_device_id);
    ClientResult<void> persist_session_index();

    interfaces::IGatewayClient& gateway_;
    interfaces::ISecureStorage& secure_storage_;
    interfaces::ICryptoProvider& crypto_provider_;
    domain::UserId local_user_id_;
    domain::DeviceId local_device_id_;

    std::unordered_map<domain::crypto::PeerDeviceKey, domain::crypto::RatchetSession, domain::crypto::PeerDeviceKeyHash>
        sessions_;
};

} // namespace securecloud::client::application::managers
