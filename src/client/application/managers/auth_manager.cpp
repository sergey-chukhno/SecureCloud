#include "application/managers/auth_manager.hpp"

namespace securecloud::client::application::managers {

AuthManager::AuthManager(interfaces::IGatewayClient& gateway, interfaces::ISecureStorage& secure_storage)
    : gateway_(gateway), secure_storage_(secure_storage) {}

ClientResult<bool> AuthManager::authenticate(std::string_view username, std::string_view password) {
    if (username.empty() || password.empty()) {
        return ClientResult<bool>::error(ClientError::validation("Username and password cannot be empty"));
    }

    const auto probe_res = gateway_.probe_gateway("/health");
    if (probe_res.is_error()) {
        return ClientResult<bool>::error(probe_res.error());
    }

    current_user_ = domain::UserId(std::string(username));
    is_authenticated_ = true;

    securecloud::common::configuration::SecretString token("session-token-for-" + std::string(username));
    const auto store_res = secure_storage_.store_secret("session_auth_token", token);
    if (store_res.is_error()) {
        return ClientResult<bool>::error(store_res.error());
    }

    return ClientResult<bool>::ok(true);
}

ClientResult<void> AuthManager::logout() {
    is_authenticated_ = false;
    current_user_ = domain::UserId{};
    (void)secure_storage_.delete_secret("session_auth_token");
    return ClientResult<void>::ok();
}

ClientResult<securecloud::common::configuration::SecretString> AuthManager::session_token() const {
    if (!is_authenticated_) {
        return ClientResult<securecloud::common::configuration::SecretString>::error(
            ClientError::authentication("Not authenticated"));
    }
    return secure_storage_.get_secret("session_auth_token");
}

} // namespace securecloud::client::application::managers
