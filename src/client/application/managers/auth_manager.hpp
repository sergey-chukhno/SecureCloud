#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/user_id.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <string_view>

namespace securecloud::client::application::managers {

class AuthManager {
  public:
    AuthManager(interfaces::IGatewayClient& gateway, interfaces::ISecureStorage& secure_storage);
    ~AuthManager() = default;

    AuthManager(const AuthManager&) = delete;
    AuthManager& operator=(const AuthManager&) = delete;

    ClientResult<bool> authenticate(std::string_view username, std::string_view password);
    ClientResult<void> logout();

    [[nodiscard]] bool is_authenticated() const noexcept { return is_authenticated_; }
    [[nodiscard]] const domain::UserId& current_user() const noexcept { return current_user_; }
    [[nodiscard]] ClientResult<securecloud::common::configuration::SecretString> session_token() const;

  private:
    interfaces::IGatewayClient& gateway_;
    interfaces::ISecureStorage& secure_storage_;
    bool is_authenticated_{false};
    domain::UserId current_user_;
};

} // namespace securecloud::client::application::managers
