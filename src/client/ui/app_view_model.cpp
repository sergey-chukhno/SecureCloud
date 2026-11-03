#include "ui/app_view_model.hpp"

namespace securecloud::client::ui {

AppViewModel::AppViewModel(application::ClientApplication& app, NavigationController& nav_controller, QObject* parent)
    : QObject(parent), app_(app), nav_controller_(nav_controller) {}

QString AppViewModel::connectionStatus() const {
    return connectionStatus_;
}

QString AppViewModel::currentUser() const {
    const auto& user = app_.bootstrap().auth_manager().current_user();
    return QString::fromStdString(user.value());
}

bool AppViewModel::isRunning() const {
    return app_.is_running();
}

bool AppViewModel::isEmergencyWiped() const {
    return app_.bootstrap().emergency_manager().is_wiped();
}

void AppViewModel::requestLogin(const QString& username, const QString& password) {
    const auto auth_res = app_.bootstrap().auth_manager().authenticate(username.toStdString(), password.toStdString());
    if (auth_res.is_error()) {
        emit operationError(QString::fromStdString(auth_res.error().user_message()));
        return;
    }

    nav_controller_.setAuthenticated(true);
    nav_controller_.navigateTo(NavigationController::NavigationState::MainWorkspace);
    emit currentUserChanged();
    emit connectionStatusChanged();
}

void AppViewModel::requestLogout() {
    (void)app_.bootstrap().auth_manager().logout();
    nav_controller_.setAuthenticated(false);
    emit currentUserChanged();
    emit connectionStatusChanged();
}

void AppViewModel::triggerEmergencyWipe() {
    (void)app_.bootstrap().emergency_manager().trigger_emergency_wipe();
    nav_controller_.reset(NavigationController::NavigationState::EmergencyMode);
    emit emergencyWipedChanged();
    emit currentUserChanged();
    emit connectionStatusChanged();
}

} // namespace securecloud::client::ui
