#pragma once

#include "application/client_config.hpp"
#include "application/interfaces/i_gateway_client.hpp"

#include <optional>
#include <string>
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
    application::ClientResult<std::vector<std::string>> sync_messages(std::string_view cursor) override;
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

    // Test Hooks for deterministic simulation
    void set_simulated_inventory_status(domain::PrekeyInventoryStatus status);
    void set_simulated_registration_status(domain::DeviceAuthorizationStatus status, std::string pairing_code = "");
    void set_simulated_directory(std::vector<application::interfaces::DeviceCryptoDirectoryEntry> directory);
    void set_simulated_user_directory(const domain::UserId& user_id,
                                      std::vector<application::interfaces::DeviceCryptoDirectoryEntry> directory);
    void set_simulated_failure(bool fail, std::string error_message = "Simulated network failure");

  private:
    std::string endpoint_;
    bool connected_{false};
    uint64_t device_registration_counter_{1};

    bool simulate_failure_{false};
    std::string failure_message_;

    std::optional<domain::PrekeyInventoryStatus> simulated_inventory_;
    std::optional<domain::DeviceAuthorizationStatus> simulated_reg_status_;
    std::string simulated_pairing_code_;
    std::vector<application::interfaces::DeviceCryptoDirectoryEntry> simulated_directory_;
    std::unordered_map<domain::UserId, std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>
        simulated_user_directories_;
};

} // namespace securecloud::client::infrastructure::adapters
