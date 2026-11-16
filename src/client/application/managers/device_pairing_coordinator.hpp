#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "application/managers/device_manager.hpp"
#include "domain/device.hpp"
#include "domain/device_id.hpp"
#include "domain/pairing_challenge_payload.hpp"
#include "domain/short_authentication_string.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::application::managers {

struct PairingVerificationPrompt {
    domain::UserId user_id;
    domain::DeviceId device_id;
    std::string display_name;
    std::string pairing_code;
    domain::ShortAuthenticationString sas;
    std::chrono::system_clock::time_point expires_at;
    domain::PairingChallengePayload challenge;

    [[nodiscard]] bool
    is_expired(std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) const noexcept {
        return now >= expires_at;
    }
};

struct CompanionPairingSession {
    domain::UserId user_id;
    domain::DeviceId device_id;
    std::string display_name;
    domain::PairingChallengePayload challenge;
    domain::ShortAuthenticationString expected_sas;
    std::string qr_uri;
    bool is_authorized{false};
};

class DevicePairingCoordinator {
  public:
    DevicePairingCoordinator(interfaces::IGatewayClient& gateway, interfaces::ISecureStorage& secure_storage,
                             interfaces::ICryptoProvider& crypto_provider, DeviceManager& device_manager);

    ~DevicePairingCoordinator() = default;

    DevicePairingCoordinator(const DevicePairingCoordinator&) = delete;
    DevicePairingCoordinator& operator=(const DevicePairingCoordinator&) = delete;

    // Companion Device Role: initiate onboarding & check status
    ClientResult<CompanionPairingSession> initiate_companion_pairing(const domain::UserId& user_id,
                                                                     std::string_view display_name = "");

    ClientResult<bool> poll_companion_authorization(CompanionPairingSession& session);

    // Primary Workstation Role: inspect QR challenge & authorize with MFA
    ClientResult<PairingVerificationPrompt> inspect_pairing_challenge(std::string_view uri_or_payload);

    ClientResult<void> approve_companion_pairing(const PairingVerificationPrompt& prompt, std::string_view mfa_token);

  private:
    interfaces::IGatewayClient& gateway_;
    interfaces::ISecureStorage& secure_storage_;
    interfaces::ICryptoProvider& crypto_provider_;
    DeviceManager& device_manager_;
};

} // namespace securecloud::client::application::managers
