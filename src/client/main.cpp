#include "application/client_application.hpp"
#include "application/client_config.hpp"
#include "infrastructure/client_logger.hpp"
#include "securecloud/common/version.hpp"
#include "ui/app_view_model.hpp"
#include "ui/navigation_controller.hpp"

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QUrl>
#include <iostream>
#include <string_view>

int main(int argc, char* argv[]) {
    std::cout << "[SecureCloud Client] Initializing SecureCloud Client v" << securecloud::common::get_version_string()
              << "\n";

    // Qt GUI Application initialization
    QGuiApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("SecureCloud Client"));
    app.setOrganizationName(QStringLiteral("SecureCloud"));
    app.setApplicationVersion(
        QString::fromUtf8(securecloud::common::get_version_string().data(),
                          static_cast<qsizetype>(securecloud::common::get_version_string().size())));

    // Check for non-interactive smoke test flag
    bool isSmokeTest = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--smoke-test") {
            isSmokeTest = true;
            break;
        }
    }

    // Explicit Dependency Wiring across architectural layers
    auto config = securecloud::client::application::ClientConfig::from_environment();
    securecloud::client::application::ClientApplication clientApp(std::move(config));

    const auto init_res = clientApp.initialize();
    if (init_res.is_error()) {
        std::cerr << "[SecureCloud Client] Initialization failed: " << init_res.error().user_message() << "\n";
        return 1;
    }

    const auto start_res = clientApp.start();
    if (start_res.is_error()) {
        std::cerr << "[SecureCloud Client] Start failed: " << start_res.error().user_message() << "\n";
        return 1;
    }

    // UI Controllers and Presentation Wiring
    securecloud::client::ui::NavigationController navController;
    securecloud::client::ui::AppViewModel appViewModel(clientApp, navController);

    // QML Application Engine
    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty(QStringLiteral("navigationController"), &navController);
    engine.rootContext()->setContextProperty(QStringLiteral("appViewModel"), &appViewModel);

    const QUrl url(QStringLiteral("qrc:/qml/Main.qml"));
    QObject::connect(
        &engine, &QQmlApplicationEngine::objectCreated, &app,
        [url](QObject* obj, const QUrl& objUrl) {
            if (!obj && url == objUrl) {
                QCoreApplication::exit(-1);
            }
        },
        Qt::QueuedConnection);

    engine.load(url);

    if (engine.rootObjects().isEmpty()) {
        std::cerr << "[SecureCloud Client] Error: Failed to load root QML component from "
                  << url.toString().toStdString() << "\n";
        return -1;
    }

    if (isSmokeTest) {
        std::cout << "[SecureCloud Client] Smoke test execution passed cleanly (QML engine loaded)\n";
        (void)clientApp.shutdown();
        return 0;
    }

    const int exitCode = app.exec();
    (void)clientApp.shutdown();
    return exitCode;
}
