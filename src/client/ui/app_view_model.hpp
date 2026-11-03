#pragma once

#include "application/client_application.hpp"
#include "ui/navigation_controller.hpp"

#include <QObject>
#include <QString>

namespace securecloud::client::ui {

class AppViewModel : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString connectionStatus READ connectionStatus NOTIFY connectionStatusChanged)
    Q_PROPERTY(QString currentUser READ currentUser NOTIFY currentUserChanged)
    Q_PROPERTY(bool isRunning READ isRunning NOTIFY lifecycleStateChanged)
    Q_PROPERTY(bool isEmergencyWiped READ isEmergencyWiped NOTIFY emergencyWipedChanged)

  public:
    AppViewModel(application::ClientApplication& app, NavigationController& nav_controller, QObject* parent = nullptr);
    ~AppViewModel() override = default;

    AppViewModel(const AppViewModel&) = delete;
    AppViewModel& operator=(const AppViewModel&) = delete;

    [[nodiscard]] QString connectionStatus() const;
    [[nodiscard]] QString currentUser() const;
    [[nodiscard]] bool isRunning() const;
    [[nodiscard]] bool isEmergencyWiped() const;

    Q_INVOKABLE void requestLogin(const QString& username, const QString& password);
    Q_INVOKABLE void requestLogout();
    Q_INVOKABLE void triggerEmergencyWipe();

  signals:
    void connectionStatusChanged();
    void currentUserChanged();
    void lifecycleStateChanged();
    void emergencyWipedChanged();
    void operationError(const QString& message);

  private:
    application::ClientApplication& app_;
    NavigationController& nav_controller_;
    QString connectionStatus_{QStringLiteral("Connected")};
};

} // namespace securecloud::client::ui
