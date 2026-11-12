#pragma once

#include "application/client_error.hpp"
#include "domain/conversation_id.hpp"
#include "domain/device.hpp"
#include "domain/device_id.hpp"
#include "domain/one_time_prekey_record.hpp"
#include "domain/prekey_bundle.hpp"
#include "domain/prekey_inventory_status.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <cstdint>
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

class IGatewayClient {
  public:
    virtual ~IGatewayClient() = default;

    virtual ClientResult<bool> probe_gateway(std::string_view path = "/health") = 0;
    virtual ClientResult<std::string> send_message(const domain::ConversationId& conversation_id,
                                                   std::string_view encrypted_envelope) = 0;
    virtual ClientResult<std::vector<std::string>> sync_messages(std::string_view cursor) = 0;
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

    virtual ClientResult<PairingInitiationResult>
    initiate_device_pairing(const domain::DeviceId& device_id) = 0;

    virtual ClientResult<void>
    authorize_device_pairing(const domain::DeviceId& device_id, std::string_view pairing_code,
                             std::string_view mfa_token) = 0;

    virtual ClientResult<std::vector<domain::Device>>
    list_user_devices(const domain::UserId& user_id) = 0;

    virtual ClientResult<void>
    revoke_device(const domain::DeviceId& device_id, std::string_view mfa_token = "") = 0;
};

} // namespace securecloud::client::application::interfaces
