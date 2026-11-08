#pragma once

#include "application/client_application.hpp"
#include "ui/navigation_controller.hpp"

#include <QObject>
#include <QString>

namespace securecloud::client::ui {

class AppViewModel : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString connectionStatus READ connectionStatus NOTIFY connectionStatusChanged)
    Q_PROPERTY(QString sessionStatusText READ sessionStatusText NOTIFY connectionStatusChanged)
    Q_PROPERTY(QString securityStatusText READ securityStatusText NOTIFY connectionStatusChanged)
    Q_PROPERTY(QString securityBadgeType READ securityBadgeType NOTIFY connectionStatusChanged)
    Q_PROPERTY(QString currentUser READ currentUser NOTIFY currentUserChanged)
    Q_PROPERTY(bool isAuthenticated READ isAuthenticated NOTIFY currentUserChanged)
    Q_PROPERTY(bool isRunning READ isRunning NOTIFY lifecycleStateChanged)
    Q_PROPERTY(bool isEmergencyWiped READ isEmergencyWiped NOTIFY emergencyWipedChanged)
    Q_PROPERTY(bool isAuthenticating READ isAuthenticating NOTIFY authenticatingChanged)
    Q_PROPERTY(bool isIdentityVerified READ isIdentityVerified NOTIFY connectionStatusChanged)
    Q_PROPERTY(QString lastErrorMessage READ lastErrorMessage NOTIFY errorStateChanged)
    Q_PROPERTY(QString lastErrorCategory READ lastErrorCategory NOTIFY errorStateChanged)

  public:
    AppViewModel(application::ClientApplication& app, NavigationController& nav_controller, QObject* parent = nullptr);
    ~AppViewModel() override = default;

    AppViewModel(const AppViewModel&) = delete;
    AppViewModel& operator=(const AppViewModel&) = delete;

    [[nodiscard]] QString connectionStatus() const;
    [[nodiscard]] QString sessionStatusText() const;
    [[nodiscard]] QString securityStatusText() const;
    [[nodiscard]] QString securityBadgeType() const;
    [[nodiscard]] QString currentUser() const;
    [[nodiscard]] bool isAuthenticated() const;
    [[nodiscard]] bool isRunning() const;
    [[nodiscard]] bool isEmergencyWiped() const;
    [[nodiscard]] bool isAuthenticating() const noexcept { return is_authenticating_; }
    [[nodiscard]] bool isIdentityVerified() const noexcept { return is_identity_verified_; }
    [[nodiscard]] QString lastErrorMessage() const { return last_error_message_; }
    [[nodiscard]] QString lastErrorCategory() const { return last_error_category_; }

    Q_INVOKABLE void setIdentityVerified(bool verified);
    Q_INVOKABLE void requestLogin(const QString& username, const QString& password);
    Q_INVOKABLE void beginMfaChallenge(const QString& username, const QString& password);
    Q_INVOKABLE void submitMfaCode(const QString& code);
    Q_INVOKABLE void cancelMfaChallenge();
    Q_INVOKABLE void clearError();
    Q_INVOKABLE void requestLogout();
    Q_INVOKABLE void triggerEmergencyWipe();

  signals:
    void connectionStatusChanged();
    void currentUserChanged();
    void lifecycleStateChanged();
    void emergencyWipedChanged();
    void authenticatingChanged();
    void errorStateChanged();
    void operationError(const QString& message);

  private:
    void setError(const QString& category, const QString& message);

    application::ClientApplication& app_;
    NavigationController& nav_controller_;
    QString connectionStatus_{QStringLiteral("Connected")};
    QString last_error_message_{};
    QString last_error_category_{};
    QString pending_username_{};
    QString pending_password_{};
    bool is_authenticating_{false};
    bool is_identity_verified_{false};
};

} // namespace securecloud::client::ui
