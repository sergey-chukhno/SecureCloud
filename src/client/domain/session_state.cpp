#include "domain/session_state.hpp"

#include <utility>

namespace securecloud::client::domain {

std::string_view to_string(SessionStatus status) noexcept {
    switch (status) {
    case SessionStatus::LoggedOut:
        return "LoggedOut";
    case SessionStatus::Authenticating:
        return "Authenticating";
    case SessionStatus::Active:
        return "Active";
    case SessionStatus::Locked:
        return "Locked";
    case SessionStatus::Expired:
        return "Expired";
    }
    return "Unknown";
}

SessionState::SessionState(std::string userId, std::string deviceId, SessionStatus status)
    : userId_(std::move(userId)), deviceId_(std::move(deviceId)), status_(status) {}

const std::string& SessionState::userId() const noexcept {
    return userId_;
}

const std::string& SessionState::deviceId() const noexcept {
    return deviceId_;
}

SessionStatus SessionState::status() const noexcept {
    return status_;
}

bool SessionState::isAuthenticated() const noexcept {
    return status_ == SessionStatus::Active;
}

void SessionState::setStatus(SessionStatus newStatus) noexcept {
    status_ = newStatus;
}

void SessionState::reset() noexcept {
    userId_.clear();
    deviceId_.clear();
    status_ = SessionStatus::LoggedOut;
}

} // namespace securecloud::client::domain
