#include "ui/app_view_model.hpp"

#include "application/client_error.hpp"

namespace securecloud::client::ui {

AppViewModel::AppViewModel(application::ClientApplication& app, NavigationController& nav_controller, QObject* parent)
    : QObject(parent), app_(app), nav_controller_(nav_controller) {}

QString AppViewModel::connectionStatus() const {
    return connectionStatus_;
}

QString AppViewModel::sessionStatusText() const {
    if (isEmergencyWiped()) {
        return QStringLiteral("Emergency Wipe Active — Local State Zeroized");
    }
    if (!isAuthenticated()) {
        return QStringLiteral("Unauthenticated — Awaiting Credentials");
    }
    return QStringLiteral("Authenticated Session (%1)").arg(currentUser());
}

QString AppViewModel::securityStatusText() const {
    if (isEmergencyWiped()) {
        return QStringLiteral("Local Secrets Zeroized");
    }
    if (!isAuthenticated()) {
        return QStringLiteral("TLS 1.3 Gateway Ready · No Active Session");
    }
    if (is_identity_verified_) {
        return QStringLiteral("Authenticated Session · Identity Verified");
    }
    return QStringLiteral("Authenticated Session · Identity Unverified");
}

QString AppViewModel::securityBadgeType() const {
    if (isEmergencyWiped()) {
        return QStringLiteral("Danger");
    }
    if (!isAuthenticated()) {
        return QStringLiteral("Offline");
    }
    if (is_identity_verified_) {
        return QStringLiteral("Verified");
    }
    return QStringLiteral("Info");
}

void AppViewModel::setIdentityVerified(bool verified) {
    if (is_identity_verified_ == verified) {
        return;
    }
    is_identity_verified_ = verified;
    emit connectionStatusChanged();
}

QString AppViewModel::currentUser() const {
    const auto& user = app_.bootstrap().auth_manager().current_user();
    return QString::fromStdString(user.value());
}

bool AppViewModel::isAuthenticated() const {
    return app_.bootstrap().auth_manager().is_authenticated();
}

bool AppViewModel::isRunning() const {
    return app_.is_running();
}

bool AppViewModel::isEmergencyWiped() const {
    return app_.bootstrap().emergency_manager().is_wiped();
}

void AppViewModel::setError(const QString& category, const QString& message) {
    last_error_category_ = category;
    last_error_message_ = message;
    emit errorStateChanged();
    if (!message.isEmpty()) {
        emit operationError(message);
    }
}

void AppViewModel::clearError() {
    if (last_error_message_.isEmpty() && last_error_category_.isEmpty()) {
        return;
    }
    last_error_category_.clear();
    last_error_message_.clear();
    emit errorStateChanged();
}

void AppViewModel::requestLogin(const QString& username, const QString& password) {
    clearError();
    is_authenticating_ = true;
    emit authenticatingChanged();

    const auto auth_res =
        app_.bootstrap().auth_manager().authenticate(username.trimmed().toStdString(), password.toStdString());

    is_authenticating_ = false;
    emit authenticatingChanged();

    if (auth_res.is_error()) {
        const auto& err = auth_res.error();
        const QString category =
            QString::fromUtf8(application::to_string(err.category()).data(),
                              static_cast<qsizetype>(application::to_string(err.category()).size()));
        setError(category, QString::fromStdString(err.user_message()));
        return;
    }

    pending_username_.clear();
    pending_password_.clear();
    connectionStatus_ = QStringLiteral("Connected");
    nav_controller_.setAuthenticated(true);
    nav_controller_.reset(NavigationController::NavigationState::MainWorkspace);
    emit currentUserChanged();
    emit connectionStatusChanged();
}

void AppViewModel::beginMfaChallenge(const QString& username, const QString& password) {
    clearError();
    if (username.trimmed().isEmpty() || password.isEmpty()) {
        setError(QStringLiteral("Validation"), QStringLiteral("Username and password cannot be empty"));
        return;
    }
    pending_username_ = username.trimmed();
    pending_password_ = password;
    (void)nav_controller_.navigateTo(NavigationController::NavigationState::MfaVerification);
}

void AppViewModel::submitMfaCode(const QString& code) {
    clearError();
    const QString trimmed = code.trimmed();
    if (trimmed.length() != 6) {
        setError(QStringLiteral("Authentication"), QStringLiteral("Enter a valid 6-digit verification code"));
        return;
    }
    for (const QChar ch : trimmed) {
        if (!ch.isDigit()) {
            setError(QStringLiteral("Authentication"), QStringLiteral("Verification code must contain only digits"));
            return;
        }
    }
    requestLogin(pending_username_.isEmpty() ? QStringLiteral("operator") : pending_username_,
                 pending_password_.isEmpty() ? QStringLiteral("mfa-session") : pending_password_);
}

void AppViewModel::cancelMfaChallenge() {
    clearError();
    pending_username_.clear();
    pending_password_.clear();
    nav_controller_.reset(NavigationController::NavigationState::Unauthenticated);
}

void AppViewModel::requestLogout() {
    clearError();
    pending_username_.clear();
    pending_password_.clear();
    (void)app_.bootstrap().auth_manager().logout();
    nav_controller_.setAuthenticated(false);
    nav_controller_.reset(NavigationController::NavigationState::Unauthenticated);
    emit currentUserChanged();
    emit connectionStatusChanged();
}

void AppViewModel::triggerEmergencyWipe() {
    clearError();
    pending_username_.clear();
    pending_password_.clear();
    is_identity_verified_ = false;
    (void)app_.bootstrap().auth_manager().logout();
    (void)app_.bootstrap().emergency_manager().trigger_emergency_wipe();
    connectionStatus_ = QStringLiteral("Offline (Wiped)");
    nav_controller_.setAuthenticated(false);
    nav_controller_.reset(NavigationController::NavigationState::EmergencyMode);
    emit emergencyWipedChanged();
    emit currentUserChanged();
    emit connectionStatusChanged();
}

} // namespace securecloud::client::ui
