#include "application/managers/auth_manager.hpp"

#include "application/managers/emergency_manager.hpp"

namespace securecloud::client::application::managers {

AuthManager::AuthManager(interfaces::IGatewayClient& gateway, interfaces::ISecureStorage& secure_storage)
    : gateway_(gateway), secure_storage_(secure_storage) {}

void AuthManager::set_emergency_manager(EmergencyManager* emergency_manager) noexcept {
    emergency_manager_ = emergency_manager;
}

ClientResult<AuthLoginResult> AuthManager::authenticate_with_duress_check(std::string_view username,
                                                                          std::string_view password) {
    if (username.empty() || password.empty()) {
        return ClientResult<AuthLoginResult>::error(ClientError::validation("Username and password cannot be empty"));
    }

    // Duress check runs strictly locally BEFORE any gateway probe or network transmission.
    if (emergency_manager_ != nullptr) {
        const securecloud::common::configuration::SecretString candidate(password);
        const auto duress_res = emergency_manager_->check_and_execute_duress_login(candidate);
        if (duress_res.is_error()) {
            return ClientResult<AuthLoginResult>::error(duress_res.error());
        }
        if (duress_res.value().has_value()) {
            const auto& report = *duress_res.value();
            last_auth_outcome_ = AuthOutcome::DuressWipeTriggered;
            last_post_wipe_mode_ = report.post_wipe_mode;
            if (report.post_wipe_mode == domain::PostWipeMode::DecoyWorkspace) {
                current_user_ = domain::UserId(std::string(username));
                is_authenticated_ = true;
                is_decoy_session_ = true;
            } else {
                current_user_ = domain::UserId{};
                is_authenticated_ = false;
                is_decoy_session_ = false;
            }

            return ClientResult<AuthLoginResult>::ok(AuthLoginResult{
                .outcome = AuthOutcome::DuressWipeTriggered,
                .post_wipe_mode = report.post_wipe_mode,
                .is_decoy_session = is_decoy_session_,
                .wipe_report = report,
            });
        }
    }

    const auto probe_res = gateway_.probe_gateway("/health");
    if (probe_res.is_error()) {
        return ClientResult<AuthLoginResult>::error(probe_res.error());
    }

    securecloud::common::configuration::SecretString token("session-token-for-" + std::string(username));
    const auto store_res = secure_storage_.store_secret("session_auth_token", token);
    if (store_res.is_error()) {
        is_authenticated_ = false;
        is_decoy_session_ = false;
        current_user_ = domain::UserId{};
        last_auth_outcome_.reset();
        return ClientResult<AuthLoginResult>::error(store_res.error());
    }

    current_user_ = domain::UserId(std::string(username));
    is_authenticated_ = true;
    is_decoy_session_ = false;
    last_auth_outcome_ = AuthOutcome::Authenticated;
    last_post_wipe_mode_ = domain::PostWipeMode::EmergencyLocked;

    return ClientResult<AuthLoginResult>::ok(AuthLoginResult{
        .outcome = AuthOutcome::Authenticated,
        .post_wipe_mode = domain::PostWipeMode::EmergencyLocked,
        .is_decoy_session = false,
        .wipe_report = std::nullopt,
    });
}

ClientResult<bool> AuthManager::authenticate(std::string_view username, std::string_view password) {
    const auto res = authenticate_with_duress_check(username, password);
    if (res.is_error()) {
        return ClientResult<bool>::error(res.error());
    }
    const bool session_active = (res.value().outcome == AuthOutcome::Authenticated) || res.value().is_decoy_session;
    return ClientResult<bool>::ok(session_active);
}

ClientResult<domain::EmergencyWipeReport> AuthManager::trigger_duress_wipe(std::string_view decoy_username) {
    if (emergency_manager_ == nullptr) {
        return ClientResult<domain::EmergencyWipeReport>::error(
            ClientError::internal_error("EmergencyManager is not configured"));
    }

    const domain::PostWipeMode mode =
        emergency_manager_->duress_post_wipe_mode().value_or(domain::PostWipeMode::DecoyWorkspace);
    const auto wipe_res = emergency_manager_->execute_panic_wipe(domain::PanicTriggerSource::DuressPin, mode);
    if (wipe_res.is_error()) {
        return wipe_res;
    }

    last_auth_outcome_ = AuthOutcome::DuressWipeTriggered;
    last_post_wipe_mode_ = mode;
    if (mode == domain::PostWipeMode::DecoyWorkspace) {
        current_user_ =
            decoy_username.empty() ? domain::UserId("operator") : domain::UserId(std::string(decoy_username));
        is_authenticated_ = true;
        is_decoy_session_ = true;
    } else {
        current_user_ = domain::UserId{};
        is_authenticated_ = false;
        is_decoy_session_ = false;
    }

    return wipe_res;
}

ClientResult<void> AuthManager::logout() {
    force_clear_session();
    return ClientResult<void>::ok();
}

void AuthManager::force_clear_session() {
    is_authenticated_ = false;
    is_decoy_session_ = false;
    last_auth_outcome_.reset();
    last_post_wipe_mode_ = domain::PostWipeMode::EmergencyLocked;
    current_user_ = domain::UserId{};
    (void)secure_storage_.delete_secret("session_auth_token");
}

ClientResult<securecloud::common::configuration::SecretString> AuthManager::session_token() const {
    if (!is_authenticated_) {
        return ClientResult<securecloud::common::configuration::SecretString>::error(
            ClientError::authentication("Not authenticated"));
    }
    if (is_decoy_session_) {
        return ClientResult<securecloud::common::configuration::SecretString>::error(
            ClientError::authentication("Decoy session has no live credentials"));
    }
    return secure_storage_.get_secret("session_auth_token");
}

} // namespace securecloud::client::application::managers
