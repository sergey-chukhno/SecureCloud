#include "application/client_application.hpp"
#include "application/client_config.hpp"
#include "infrastructure/client_logger.hpp"
#include "securecloud/common/version.hpp"
#include "ui/app_view_model.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/ui_theme.hpp"
#include "ui/window_state_manager.hpp"
#include "ui/workspace_view_model.hpp"

#include <QDir>
#include <QGuiApplication>
#include <QImage>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickWindow>
#include <QSGRendererInterface>
#include <QThread>
#include <QUrl>
#include <iostream>
#include <string_view>

int main(int argc, char* argv[]) {
    std::cout << "[SecureCloud Client] Initializing SecureCloud Client v" << securecloud::common::get_version_string()
              << "\n";

    // Check for CLI runtime flags before QGuiApplication construction
    bool isSmokeTest = false;
    bool isGalleryMode = false;
    QString screenshotOutDir;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--smoke-test") {
            isSmokeTest = true;
        } else if (arg == "--gallery" || arg == "--style-guide") {
            isGalleryMode = true;
        } else if (arg == "--capture-screenshots" && (i + 1) < argc) {
            screenshotOutDir = QString::fromUtf8(argv[++i]);
        }
    }

    if (!screenshotOutDir.isEmpty()) {
        qputenv("QT_QPA_PLATFORM", "offscreen");
        QQuickWindow::setGraphicsApi(QSGRendererInterface::Software);
    }

    // Qt GUI Application initialization
    QGuiApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("SecureCloud Client"));
    app.setOrganizationName(QStringLiteral("SecureCloud"));
    app.setApplicationVersion(
        QString::fromUtf8(securecloud::common::get_version_string().data(),
                          static_cast<qsizetype>(securecloud::common::get_version_string().size())));

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
    securecloud::client::ui::WorkspaceViewModel workspaceViewModel(clientApp, navController);
    securecloud::client::ui::UiTheme uiTheme;
    securecloud::client::ui::WindowStateManager windowStateManager;

    QObject::connect(&appViewModel, &securecloud::client::ui::AppViewModel::emergencyWipedChanged, &workspaceViewModel,
                     [&appViewModel, &workspaceViewModel]() {
                         if (appViewModel.isEmergencyWiped()) {
                             workspaceViewModel.resetForEmergencyWipe();
                         }
                     });

    if (isGalleryMode) {
        navController.navigateTo(securecloud::client::ui::NavigationController::NavigationState::StyleGuide);
    }

    // QML Application Engine
    QQmlApplicationEngine engine;
    qmlRegisterSingletonInstance<securecloud::client::ui::UiTheme>("SecureCloud.Theme", 1, 0, "Theme", &uiTheme);
    engine.rootContext()->setContextProperty(QStringLiteral("navigationController"), &navController);
    engine.rootContext()->setContextProperty(QStringLiteral("appViewModel"), &appViewModel);
    engine.rootContext()->setContextProperty(QStringLiteral("workspaceViewModel"), &workspaceViewModel);
    engine.rootContext()->setContextProperty(QStringLiteral("Theme"), &uiTheme);
    engine.rootContext()->setContextProperty(QStringLiteral("windowStateManager"), &windowStateManager);

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

    if (!screenshotOutDir.isEmpty()) {
        QDir dir(screenshotOutDir);
        if (!dir.exists()) {
            (void)dir.mkpath(QStringLiteral("."));
        }
        auto* window = qobject_cast<QQuickWindow*>(engine.rootObjects().first());
        if (!window) {
            std::cerr << "[SecureCloud Client] Root QML object is not a QQuickWindow\n";
            (void)clientApp.shutdown();
            return -1;
        }

        auto pumpEvents = [](int iterations = 12, int sleepMs = 25) {
            for (int i = 0; i < iterations; ++i) {
                QCoreApplication::processEvents();
                QThread::msleep(static_cast<unsigned long>(sleepMs));
                QCoreApplication::processEvents();
            }
        };

        auto captureWindow = [&](const QString& filename, int w, int h) {
            window->setWidth(w);
            window->setHeight(h);
            pumpEvents();
            const QImage image = window->grabWindow();
            const QString filePath = dir.filePath(filename);
            if (!image.save(filePath)) {
                std::cerr << "[SecureCloud Client] Failed to save screenshot: " << filePath.toStdString() << "\n";
            } else {
                std::cout << "[SecureCloud Client] Captured screenshot: " << filePath.toStdString() << " ("
                          << image.width() << "x" << image.height() << ")\n";
            }
        };

        // 1. Login Dark & Light at 1200x800
        uiTheme.setThemeMode(securecloud::client::ui::ThemeMode::Dark);
        captureWindow(QStringLiteral("login-dark-1200x800.png"), 1200, 800);

        uiTheme.setThemeMode(securecloud::client::ui::ThemeMode::Light);
        captureWindow(QStringLiteral("login-light-1200x800.png"), 1200, 800);

        // 2. Login Dark & Light at 960x640
        uiTheme.setThemeMode(securecloud::client::ui::ThemeMode::Dark);
        captureWindow(QStringLiteral("login-dark-960x640.png"), 960, 640);

        uiTheme.setThemeMode(securecloud::client::ui::ThemeMode::Light);
        captureWindow(QStringLiteral("login-light-960x640.png"), 960, 640);

        // 3. Login Validation / Error state (Dark 1200x800)
        uiTheme.setThemeMode(securecloud::client::ui::ThemeMode::Dark);
        appViewModel.requestLogin(QStringLiteral(""), QStringLiteral(""));
        captureWindow(QStringLiteral("login-error-dark-1200x800.png"), 1200, 800);

        // 4. MFA Challenge state (Dark 1200x800)
        appViewModel.beginMfaChallenge(QStringLiteral("alice"), QStringLiteral("password123"));
        captureWindow(QStringLiteral("login-mfa-dark-1200x800.png"), 1200, 800);

        // 5. Authenticated Workspace state — Messages 4-Zone Shell (Dark & Light 1200x800)
        appViewModel.submitMfaCode(QStringLiteral("482910"));
        workspaceViewModel.setActiveSection(QStringLiteral("Messages"));
        workspaceViewModel.setInspectorOpen(true);
        uiTheme.setThemeMode(securecloud::client::ui::ThemeMode::Dark);
        captureWindow(QStringLiteral("workspace-dark-1200x800.png"), 1200, 800);

        uiTheme.setThemeMode(securecloud::client::ui::ThemeMode::Light);
        captureWindow(QStringLiteral("workspace-light-1200x800.png"), 1200, 800);

        // 6. Authenticated Workspace state — Encrypted Files Vault View (Dark & Light 1200x800)
        workspaceViewModel.setActiveSection(QStringLiteral("Files"));
        uiTheme.setThemeMode(securecloud::client::ui::ThemeMode::Dark);
        captureWindow(QStringLiteral("workspace-files-dark-1200x800.png"), 1200, 800);

        uiTheme.setThemeMode(securecloud::client::ui::ThemeMode::Light);
        captureWindow(QStringLiteral("workspace-files-light-1200x800.png"), 1200, 800);

        // 7. Authenticated Settings — Security, Device Trust & Identity Center (Dark & Light 1200x800)
        (void)navController.navigateTo(securecloud::client::ui::NavigationController::NavigationState::Settings);
        uiTheme.setThemeMode(securecloud::client::ui::ThemeMode::Dark);
        captureWindow(QStringLiteral("workspace-settings-dark-1200x800.png"), 1200, 800);

        uiTheme.setThemeMode(securecloud::client::ui::ThemeMode::Light);
        captureWindow(QStringLiteral("workspace-settings-light-1200x800.png"), 1200, 800);

        (void)clientApp.shutdown();
        return 0;
    }

    const int exitCode = app.exec();
    (void)clientApp.shutdown();
    return exitCode;
}
