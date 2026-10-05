#include "http/auth/authenticated_context.hpp"

#include "http/auth/scope_matcher.hpp"

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
    return ScopeMatcher::has_scope(scopes_, required_scope);
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

nlohmann::json AuthenticatedContext::to_audit_info() const {
    nlohmann::json j;
    j["user_id"] = user_id_;
    j["device_id"] = device_id_;
    j["session_id"] = session_id_;
    j["auth_level"] = securecloud::auth::v1::AuthenticationLevel_Name(auth_level_);
    j["scopes"] = scopes_;
    j["mfa_verified"] = is_mfa_verified();
    j["expires_at_epoch_ms"] = expires_at_epoch_ms_;
    return j;
}

} // namespace securecloud::gateway::http
