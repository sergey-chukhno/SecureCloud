#include "ui/navigation_controller.hpp"

namespace securecloud::client::ui {

NavigationController::NavigationController(QObject* parent) : QObject(parent) {}

QString NavigationController::currentViewName() const {
    return to_view_name(currentState_);
}

QString NavigationController::to_view_name(NavigationState state) {
    switch (state) {
    case NavigationState::Unauthenticated:
        return QStringLiteral("Login");
    case NavigationState::MfaVerification:
        return QStringLiteral("MfaVerification");
    case NavigationState::MainWorkspace:
        return QStringLiteral("Workspace");
    case NavigationState::Settings:
        return QStringLiteral("Settings");
    case NavigationState::EmergencyMode:
        return QStringLiteral("Emergency");
    case NavigationState::StyleGuide:
        return QStringLiteral("StyleGuide");
    }
    return QStringLiteral("Unknown");
}

bool NavigationController::is_restricted_state(NavigationState state) const noexcept {
    return state == NavigationState::MainWorkspace || state == NavigationState::Settings;
}

bool NavigationController::navigateTo(NavigationState state) {
    if (state == currentState_) {
        return true;
    }

    if (!isAuthenticated_ && is_restricted_state(state)) {
        emit navigationDenied(state, QStringLiteral("Access denied: User is not authenticated"));
        return false;
    }

    history_.push_back(currentState_);
    currentState_ = state;
    emit stateChanged(currentState_);
    return true;
}

bool NavigationController::navigateBack() {
    if (history_.empty()) {
        return false;
    }

    const NavigationState previousState = history_.back();
    history_.pop_back();

    if (!isAuthenticated_ && is_restricted_state(previousState)) {
        // Drop restricted view from history if no longer authenticated
        return navigateBack();
    }

    currentState_ = previousState;
    emit stateChanged(currentState_);
    return true;
}

void NavigationController::reset(NavigationState initial_state) {
    history_.clear();
    currentState_ = initial_state;
    emit stateChanged(currentState_);
}

void NavigationController::setAuthenticated(bool authenticated) {
    if (isAuthenticated_ == authenticated) {
        return;
    }
    isAuthenticated_ = authenticated;
    emit authenticationChanged(isAuthenticated_);

    if (!isAuthenticated_ && is_restricted_state(currentState_)) {
        reset(NavigationState::Unauthenticated);
    }
}

} // namespace securecloud::client::ui
