#include "application/managers/auth_manager.hpp"

#include "application/managers/emergency_manager.hpp"

namespace securecloud::client::application::managers {

namespace {

[[nodiscard]] std::string resolve_stored_device_id(interfaces::ISecureStorage& secure_storage) {
    const auto local_dev = secure_storage.get_secret("device.local.id");
    if (local_dev.is_ok() && !local_dev.value().empty()) {
        return local_dev.value().expose_unredacted_secret();
    }
    const auto sess_dev = secure_storage.get_secret("session_device_id");
    if (sess_dev.is_ok() && !sess_dev.value().empty()) {
        return sess_dev.value().expose_unredacted_secret();
    }
    return {};
}

} // namespace

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
            current_session_id_.clear();
            current_device_id_.clear();

            return ClientResult<AuthLoginResult>::ok(AuthLoginResult{
                .outcome = AuthOutcome::DuressWipeTriggered,
                .post_wipe_mode = report.post_wipe_mode,
                .is_decoy_session = is_decoy_session_,
                .wipe_report = report,
            });
        }
    }

    const std::string stored_device_id = resolve_stored_device_id(secure_storage_);
    const auto auth_res = gateway_.authenticate_user(username, password, stored_device_id);
    if (auth_res.is_error()) {
        return ClientResult<AuthLoginResult>::error(auth_res.error());
    }

    const auto& session = auth_res.value();
    if (!session.access_token.empty()) {
        const auto store_res = secure_storage_.store_secret("session_auth_token", session.access_token);
        if (store_res.is_error()) {
            is_authenticated_ = false;
            is_decoy_session_ = false;
            current_user_ = domain::UserId{};
            current_session_id_.clear();
            current_device_id_.clear();
            last_auth_outcome_.reset();
            return ClientResult<AuthLoginResult>::error(store_res.error());
        }
    } else if (!session.mfa_required) {
        return ClientResult<AuthLoginResult>::error(
            ClientError::authentication("Gateway returned empty access token on authentication"));
    }

    if (!session.refresh_token.empty()) {
        (void)secure_storage_.store_secret("session_refresh_token", session.refresh_token);
    }
    if (!session.session_id.empty()) {
        (void)secure_storage_.store_secret("session_id",
                                           securecloud::common::configuration::SecretString(session.session_id));
    }

    const std::string resolved_device_id = !session.device_id.empty() ? session.device_id : stored_device_id;
    if (!resolved_device_id.empty()) {
        (void)secure_storage_.store_secret("session_device_id",
                                           securecloud::common::configuration::SecretString(resolved_device_id));
    }

    current_user_ = !session.user_id.empty() ? session.user_id : domain::UserId(std::string(username));
    current_session_id_ = session.session_id;
    current_device_id_ = resolved_device_id;
    is_authenticated_ = !session.mfa_required;
    is_decoy_session_ = false;
    last_auth_outcome_ = AuthOutcome::Authenticated;
    last_post_wipe_mode_ = domain::PostWipeMode::EmergencyLocked;

    return ClientResult<AuthLoginResult>::ok(AuthLoginResult{
        .outcome = AuthOutcome::Authenticated,
        .post_wipe_mode = domain::PostWipeMode::EmergencyLocked,
        .is_decoy_session = false,
        .wipe_report = std::nullopt,
        .session_id = session.session_id,
        .mfa_required = session.mfa_required,
        .mfa_challenge_id = session.mfa_challenge_id,
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

ClientResult<bool> AuthManager::refresh_session(std::string_view device_id) {
    if (!is_authenticated_) {
        return ClientResult<bool>::error(ClientError::authentication("Not authenticated"));
    }
    if (is_decoy_session_) {
        return ClientResult<bool>::error(ClientError::authentication("Decoy session cannot be refreshed remotely"));
    }

    const auto refresh_tok_res = secure_storage_.get_secret("session_refresh_token");
    if (refresh_tok_res.is_error() || refresh_tok_res.value().empty()) {
        return ClientResult<bool>::error(ClientError::authentication("No session refresh token stored"));
    }

    std::string effective_device_id(device_id);
    if (effective_device_id.empty()) {
        effective_device_id = current_device_id_;
    }
    if (effective_device_id.empty()) {
        effective_device_id = resolve_stored_device_id(secure_storage_);
    }

    const auto res = gateway_.refresh_session(refresh_tok_res.value().expose_unredacted_secret(), effective_device_id);
    if (res.is_error()) {
        return ClientResult<bool>::error(res.error());
    }

    const auto& refreshed = res.value();
    if (refreshed.access_token.empty()) {
        return ClientResult<bool>::error(ClientError::authentication("Gateway returned empty refreshed access token"));
    }
    const auto store_res = secure_storage_.store_secret("session_auth_token", refreshed.access_token);
    if (store_res.is_error()) {
        return ClientResult<bool>::error(store_res.error());
    }
    if (!refreshed.refresh_token.empty()) {
        (void)secure_storage_.store_secret("session_refresh_token", refreshed.refresh_token);
    }
    if (!refreshed.session_id.empty()) {
        current_session_id_ = refreshed.session_id;
        (void)secure_storage_.store_secret("session_id",
                                           securecloud::common::configuration::SecretString(refreshed.session_id));
    }

    return ClientResult<bool>::ok(true);
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
    current_session_id_.clear();
    current_device_id_.clear();

    return wipe_res;
}

ClientResult<void> AuthManager::logout() {
    if (is_authenticated_ && !is_decoy_session_) {
        std::string session_id = current_session_id_;
        if (session_id.empty()) {
            const auto sid_res = secure_storage_.get_secret("session_id");
            if (sid_res.is_ok() && !sid_res.value().empty()) {
                session_id = sid_res.value().expose_unredacted_secret();
            }
        }
        if (!session_id.empty()) {
            (void)gateway_.revoke_session(session_id, "user_logout");
        }
    }
    force_clear_session();
    return ClientResult<void>::ok();
}

void AuthManager::force_clear_session() {
    is_authenticated_ = false;
    is_decoy_session_ = false;
    last_auth_outcome_.reset();
    last_post_wipe_mode_ = domain::PostWipeMode::EmergencyLocked;
    current_user_ = domain::UserId{};
    current_session_id_.clear();
    current_device_id_.clear();
    (void)secure_storage_.delete_secret("session_auth_token");
    (void)secure_storage_.delete_secret("session_refresh_token");
    (void)secure_storage_.delete_secret("session_id");
    (void)secure_storage_.delete_secret("session_device_id");
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
