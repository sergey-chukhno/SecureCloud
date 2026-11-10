#include "infrastructure/adapters/default_gateway_client.hpp"

#include "domain/prekey_policy.hpp"

#include <iomanip>
#include <sstream>

namespace securecloud::client::infrastructure::adapters {

DefaultGatewayClient::DefaultGatewayClient(const application::ClientConfig& config) {
    std::ostringstream oss;
    oss << config.gateway_url << ":" << config.gateway_port;
    endpoint_ = oss.str();
}

application::ClientResult<bool> DefaultGatewayClient::probe_gateway(std::string_view /*path*/) {
    if (simulate_failure_) {
        return application::ClientResult<bool>::error(application::ClientError::network(failure_message_));
    }
    connected_ = true;
    return application::ClientResult<bool>::ok(true);
}

application::ClientResult<std::string> DefaultGatewayClient::send_message(const domain::ConversationId& conversation_id,
                                                                          std::string_view /*encrypted_envelope*/) {
    if (simulate_failure_) {
        return application::ClientResult<std::string>::error(application::ClientError::network(failure_message_));
    }
    if (conversation_id.empty()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::validation("Conversation ID cannot be empty"));
    }
    return application::ClientResult<std::string>::ok("msg-server-assigned-id");
}

application::ClientResult<std::vector<std::string>> DefaultGatewayClient::sync_messages(std::string_view /*cursor*/) {
    if (simulate_failure_) {
        return application::ClientResult<std::vector<std::string>>::error(
            application::ClientError::network(failure_message_));
    }
    return application::ClientResult<std::vector<std::string>>::ok(std::vector<std::string>{});
}

application::ClientResult<bool> DefaultGatewayClient::validate_token(std::string_view token) {
    if (simulate_failure_) {
        return application::ClientResult<bool>::error(application::ClientError::network(failure_message_));
    }
    if (token.empty()) {
        return application::ClientResult<bool>::ok(false);
    }
    return application::ClientResult<bool>::ok(true);
}

application::ClientResult<void> DefaultGatewayClient::disconnect() {
    connected_ = false;
    return application::ClientResult<void>::ok();
}

application::ClientResult<application::interfaces::DeviceRegistrationResult>
DefaultGatewayClient::register_device(const domain::UserId& user_id, const domain::PrekeyBundle& bundle) {
    if (simulate_failure_) {
        return application::ClientResult<application::interfaces::DeviceRegistrationResult>::error(
            application::ClientError::network(failure_message_));
    }
    if (user_id.empty()) {
        return application::ClientResult<application::interfaces::DeviceRegistrationResult>::error(
            application::ClientError::validation("User ID cannot be empty for device registration"));
    }
    if (bundle.identity_key().size() != domain::PrekeyPolicy::kEd25519PublicKeySize) {
        return application::ClientResult<application::interfaces::DeviceRegistrationResult>::error(
            application::ClientError::validation("Invalid identity key size in prekey bundle"));
    }
    if (bundle.signed_prekey().size() != domain::PrekeyPolicy::kX25519PublicKeySize) {
        return application::ClientResult<application::interfaces::DeviceRegistrationResult>::error(
            application::ClientError::validation("Invalid signed prekey size in prekey bundle"));
    }
    if (bundle.signed_prekey_signature().size() != domain::PrekeyPolicy::kEd25519SignatureSize) {
        return application::ClientResult<application::interfaces::DeviceRegistrationResult>::error(
            application::ClientError::validation("Invalid signed prekey signature size in prekey bundle"));
    }

    std::ostringstream oss;
    oss << "dev-" << std::setfill('0') << std::setw(6) << device_registration_counter_++;
    const domain::DeviceId assigned_id(oss.str());

    const auto status = simulated_reg_status_.value_or(domain::DeviceAuthorizationStatus::Authorized);
    const auto now = std::chrono::system_clock::now();

    application::interfaces::DeviceRegistrationResult result{
        .device_id = assigned_id,
        .status = status,
        .registered_at = now,
        .pairing_code = simulated_pairing_code_,
        .pairing_code_expires_at = now + std::chrono::minutes(15),
    };

    return application::ClientResult<application::interfaces::DeviceRegistrationResult>::ok(std::move(result));
}

application::ClientResult<application::interfaces::PrekeyUpdateResult>
DefaultGatewayClient::update_crypto_prekeys(const domain::DeviceId& device_id,
                                            std::optional<std::vector<uint8_t>> signed_prekey,
                                            std::optional<std::vector<uint8_t>> signed_prekey_signature,
                                            std::vector<domain::OneTimePrekeyRecord> one_time_prekeys) {
    if (simulate_failure_) {
        return application::ClientResult<application::interfaces::PrekeyUpdateResult>::error(
            application::ClientError::network(failure_message_));
    }
    if (device_id.empty()) {
        return application::ClientResult<application::interfaces::PrekeyUpdateResult>::error(
            application::ClientError::validation("Device ID cannot be empty for prekey update"));
    }

    if (signed_prekey.has_value() && signed_prekey->size() != domain::PrekeyPolicy::kX25519PublicKeySize) {
        return application::ClientResult<application::interfaces::PrekeyUpdateResult>::error(
            application::ClientError::validation("Invalid signed prekey size"));
    }
    if (signed_prekey_signature.has_value() &&
        signed_prekey_signature->size() != domain::PrekeyPolicy::kEd25519SignatureSize) {
        return application::ClientResult<application::interfaces::PrekeyUpdateResult>::error(
            application::ClientError::validation("Invalid signed prekey signature size"));
    }

    application::interfaces::PrekeyUpdateResult result{
        .active_one_time_prekey_count = static_cast<int32_t>(one_time_prekeys.size()),
        .updated_at = std::chrono::system_clock::now(),
    };

    return application::ClientResult<application::interfaces::PrekeyUpdateResult>::ok(std::move(result));
}

application::ClientResult<domain::PrekeyInventoryStatus>
DefaultGatewayClient::get_prekey_inventory_status(const domain::DeviceId& device_id) {
    if (simulate_failure_) {
        return application::ClientResult<domain::PrekeyInventoryStatus>::error(
            application::ClientError::network(failure_message_));
    }
    if (device_id.empty()) {
        return application::ClientResult<domain::PrekeyInventoryStatus>::error(
            application::ClientError::validation("Device ID cannot be empty for inventory status query"));
    }

    if (simulated_inventory_.has_value()) {
        return application::ClientResult<domain::PrekeyInventoryStatus>::ok(*simulated_inventory_);
    }

    // Default healthy status
    domain::PrekeyInventoryStatus default_status(100, 0,
                                                 static_cast<int32_t>(domain::PrekeyPolicy::kLowPrekeyThreshold),
                                                 std::chrono::system_clock::now(), std::chrono::seconds(0), false);
    return application::ClientResult<domain::PrekeyInventoryStatus>::ok(default_status);
}

application::ClientResult<std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>
DefaultGatewayClient::get_device_crypto_directory(const domain::UserId& user_id,
                                                  const std::vector<domain::DeviceId>& /*device_ids*/) {
    if (simulate_failure_) {
        return application::ClientResult<std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>::error(
            application::ClientError::network(failure_message_));
    }
    if (user_id.empty()) {
        return application::ClientResult<std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>::error(
            application::ClientError::validation("User ID cannot be empty for crypto directory query"));
    }

    auto user_it = simulated_user_directories_.find(user_id);
    if (user_it != simulated_user_directories_.end()) {
        return application::ClientResult<std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>::ok(
            user_it->second);
    }

    return application::ClientResult<std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>::ok(
        simulated_directory_);
}

void DefaultGatewayClient::set_simulated_inventory_status(domain::PrekeyInventoryStatus status) {
    simulated_inventory_ = status;
}

void DefaultGatewayClient::set_simulated_registration_status(domain::DeviceAuthorizationStatus status,
                                                             std::string pairing_code) {
    simulated_reg_status_ = status;
    simulated_pairing_code_ = std::move(pairing_code);
}

void DefaultGatewayClient::set_simulated_directory(
    std::vector<application::interfaces::DeviceCryptoDirectoryEntry> directory) {
    simulated_directory_ = std::move(directory);
}

void DefaultGatewayClient::set_simulated_user_directory(
    const domain::UserId& user_id, std::vector<application::interfaces::DeviceCryptoDirectoryEntry> directory) {
    simulated_user_directories_[user_id] = std::move(directory);
}

void DefaultGatewayClient::set_simulated_failure(bool fail, std::string error_message) {
    simulate_failure_ = fail;
    failure_message_ = std::move(error_message);
}

} // namespace securecloud::client::infrastructure::adapters
