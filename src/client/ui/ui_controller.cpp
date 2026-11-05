#include "ui/ui_controller.hpp"

namespace securecloud::client::ui {

UiController::UiController(application::ClientAppService& appService, QObject* parent)
    : QObject(parent), appService_(appService) {}

QString UiController::statusText() const {
    return statusText_;
}

bool UiController::isAuthenticated() const {
    return appService_.sessionState().isAuthenticated();
}

void UiController::requestLogin(const QString& username) {
    appService_.updateSession(username.toStdString(), "desktop-device-001");
    statusText_ = QStringLiteral("User authenticated");
    emit statusTextChanged();
    emit sessionChanged();
}

void UiController::requestLogout() {
    appService_.logout();
    statusText_ = QStringLiteral("User logged out");
    emit statusTextChanged();
    emit sessionChanged();
}

} // namespace securecloud::client::ui
