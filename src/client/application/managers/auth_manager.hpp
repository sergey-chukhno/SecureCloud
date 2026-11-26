#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/emergency_models.hpp"
#include "domain/user_id.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace securecloud::client::application::managers {

class EmergencyManager;

enum class AuthOutcome { Authenticated, DuressWipeTriggered };

struct AuthLoginResult {
    AuthOutcome outcome{AuthOutcome::Authenticated};
    domain::PostWipeMode post_wipe_mode{domain::PostWipeMode::EmergencyLocked};
    bool is_decoy_session{false};
    std::optional<domain::EmergencyWipeReport> wipe_report;
    std::string session_id{};
    bool mfa_required{false};
    std::string mfa_challenge_id{};
};

class AuthManager {
  public:
    AuthManager(interfaces::IGatewayClient& gateway, interfaces::ISecureStorage& secure_storage);
    ~AuthManager() = default;

    AuthManager(const AuthManager&) = delete;
    AuthManager& operator=(const AuthManager&) = delete;

    void set_emergency_manager(EmergencyManager* emergency_manager) noexcept;

    ClientResult<AuthLoginResult> authenticate_with_duress_check(std::string_view username, std::string_view password);
    ClientResult<bool> authenticate(std::string_view username, std::string_view password);
    ClientResult<bool> refresh_session(std::string_view device_id = "");
    ClientResult<domain::EmergencyWipeReport> trigger_duress_wipe(std::string_view decoy_username = "");
    ClientResult<void> logout();
    void force_clear_session();

    [[nodiscard]] bool is_authenticated() const noexcept { return is_authenticated_; }
    [[nodiscard]] bool is_decoy_session() const noexcept { return is_decoy_session_; }
    [[nodiscard]] std::optional<AuthOutcome> last_auth_outcome() const noexcept { return last_auth_outcome_; }
    [[nodiscard]] domain::PostWipeMode last_post_wipe_mode() const noexcept { return last_post_wipe_mode_; }
    [[nodiscard]] const domain::UserId& current_user() const noexcept { return current_user_; }
    [[nodiscard]] const std::string& current_session_id() const noexcept { return current_session_id_; }
    [[nodiscard]] const std::string& current_device_id() const noexcept { return current_device_id_; }
    [[nodiscard]] ClientResult<securecloud::common::configuration::SecretString> session_token() const;

  private:
    interfaces::IGatewayClient& gateway_;
    interfaces::ISecureStorage& secure_storage_;
    EmergencyManager* emergency_manager_{nullptr};
    bool is_authenticated_{false};
    bool is_decoy_session_{false};
    std::optional<AuthOutcome> last_auth_outcome_;
    domain::PostWipeMode last_post_wipe_mode_{domain::PostWipeMode::EmergencyLocked};
    domain::UserId current_user_;
    std::string current_session_id_;
    std::string current_device_id_;
};

} // namespace securecloud::client::application::managers
