#pragma once

#include "http/auth/token_validation_result.hpp"
#include "securecloud/auth/v1/auth.pb.h"

#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::gateway::http {

/**
 * @brief Verified caller identity and authorization claims established at the Gateway perimeter.
 *
 * AuthenticatedContext represents the internal trust boundary. Downstream handlers and microservice
 * proxies (Messaging, Files, Auth, Audit) rely exclusively on this immutable context rather than reparsing
 * or re-authenticating client credentials, preventing identity spoofing and claim tampering.
 */
class AuthenticatedContext {
  public:
    AuthenticatedContext() = default;

    AuthenticatedContext(std::string user_id, std::string device_id, std::string session_id,
                         securecloud::auth::v1::AuthenticationLevel auth_level, std::vector<std::string> scopes,
                         int64_t expires_at_epoch_ms);

    [[nodiscard]] const std::string& user_id() const noexcept { return user_id_; }
    [[nodiscard]] const std::string& device_id() const noexcept { return device_id_; }
    [[nodiscard]] const std::string& session_id() const noexcept { return session_id_; }
    [[nodiscard]] securecloud::auth::v1::AuthenticationLevel authentication_level() const noexcept {
        return auth_level_;
    }
    [[nodiscard]] const std::vector<std::string>& scopes() const noexcept { return scopes_; }
    [[nodiscard]] int64_t expires_at_epoch_ms() const noexcept { return expires_at_epoch_ms_; }

    /// Returns true if the session has verified Multi-Factor Authentication (MFA)
    [[nodiscard]] bool is_mfa_verified() const noexcept;

    /// Checks if a specific scope is granted in this context
    [[nodiscard]] bool has_scope(std::string_view required_scope) const noexcept;

    /// Checks if the context has expired relative to a given epoch timestamp in milliseconds
    [[nodiscard]] bool is_expired(int64_t current_epoch_ms) const noexcept;

    /// Checks if the context is valid and active at a given epoch timestamp in milliseconds
    [[nodiscard]] bool is_valid_at(int64_t current_epoch_ms) const noexcept;

    /**
     * @brief Produces a safe structured audit dictionary containing only opaque identifiers and claims.
     *
     * Secret Isolation Invariant:
     * AuthenticatedContext strictly contains opaque identifiers and authorization metadata.
     * It is prohibited from holding raw access tokens, refresh tokens, client secrets,
     * end-to-end encryption private keys (identity keys, signed prekeys, one-time prekeys),
     * or application plaintext payloads.
     */
    [[nodiscard]] nlohmann::json to_audit_info() const;

  private:
    std::string user_id_;
    std::string device_id_;
    std::string session_id_;
    securecloud::auth::v1::AuthenticationLevel auth_level_{
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_UNSPECIFIED};
    std::vector<std::string> scopes_;
    int64_t expires_at_epoch_ms_{0};
};

using AuthenticatedResult = TokenValidationResult<AuthenticatedContext>;

} // namespace securecloud::gateway::http
