#pragma once

#include "application/client_app_service.hpp"

#include <QObject>
#include <QString>

namespace securecloud::client::ui {

class UiController : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString statusText READ statusText NOTIFY statusTextChanged)
    Q_PROPERTY(bool isAuthenticated READ isAuthenticated NOTIFY sessionChanged)

  public:
    explicit UiController(application::ClientAppService& appService, QObject* parent = nullptr);
    ~UiController() override = default;

    [[nodiscard]] QString statusText() const;
    [[nodiscard]] bool isAuthenticated() const;

    Q_INVOKABLE void requestLogin(const QString& username);
    Q_INVOKABLE void requestLogout();

  signals:
    void statusTextChanged();
    void sessionChanged();

  private:
    application::ClientAppService& appService_;
    QString statusText_{QStringLiteral("Ready")};
};

} // namespace securecloud::client::ui
