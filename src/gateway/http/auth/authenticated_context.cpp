#include "http/auth/authenticated_context.hpp"

#include <algorithm>
#include <utility>

namespace securecloud::gateway::http {

AuthenticatedContext::AuthenticatedContext(std::string user_id, std::string device_id, std::string session_id,
                                           securecloud::auth::v1::AuthenticationLevel auth_level,
                                           std::vector<std::string> scopes, int64_t expires_at_epoch_ms)
    : user_id_(std::move(user_id)), device_id_(std::move(device_id)), session_id_(std::move(session_id)),
      auth_level_(auth_level), scopes_(std::move(scopes)), expires_at_epoch_ms_(expires_at_epoch_ms) {}

bool AuthenticatedContext::is_mfa_verified() const noexcept {
    return auth_level_ == securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED;
}

bool AuthenticatedContext::has_scope(std::string_view required_scope) const noexcept {
    return std::any_of(scopes_.begin(), scopes_.end(),
                       [required_scope](const std::string& scope) { return scope == required_scope; });
}

bool AuthenticatedContext::is_expired(int64_t current_epoch_ms) const noexcept {
    if (expires_at_epoch_ms_ <= 0) {
        return false;
    }
    return current_epoch_ms >= expires_at_epoch_ms_;
}

bool AuthenticatedContext::is_valid_at(int64_t current_epoch_ms) const noexcept {
    return !is_expired(current_epoch_ms);
}

} // namespace securecloud::gateway::http
