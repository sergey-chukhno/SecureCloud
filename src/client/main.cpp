#include "application/client_app_service.hpp"
#include "securecloud/common/version.hpp"
#include "ui/ui_controller.hpp"

#include <QGuiApplication>
#include <iostream>
#include <string_view>

int main(int argc, char* argv[]) {
    std::cout << "[SecureCloud Client] Initializing SecureCloud Client v" << securecloud::common::get_version_string()
              << "\n";

    // Qt GUI Application initialization
    QGuiApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("SecureCloud Client"));
    app.setApplicationVersion(
        QString::fromUtf8(securecloud::common::get_version_string().data(),
                          static_cast<qsizetype>(securecloud::common::get_version_string().size())));

    // Explicit Dependency Wiring across architectural layers
    securecloud::client::application::ClientAppService appService;
    if (!appService.initialize()) {
        std::cerr << "[SecureCloud Client] Error: Application service initialization failed\n";
        return 1;
    }

    securecloud::client::ui::UiController uiController(appService);
    std::cout << "[SecureCloud Client] Status: " << uiController.statusText().toStdString() << "\n";

    // Command-line handling: --smoke-test exits immediately after verifying bootstrap
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--smoke-test") {
            std::cout << "[SecureCloud Client] Smoke test execution passed cleanly\n";
            return 0;
        }
    }

    // Foundation verification pass: clean startup and shutdown
    std::cout << "[SecureCloud Client] Application bootstrap complete\n";
    return 0;
}
