#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/managers/diagnostic_sanitizer.hpp"
#include "application/managers/diagnostics_manager.hpp"
#include "application/managers/local_audit_logger.hpp"
#include "application/managers/settings_manager.hpp"
#include "domain/local_audit_event.hpp"
#include "domain/user_id.hpp"
#include "domain/user_profile.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "ui/app_view_model.hpp"
#include "ui/diagnostics_view_model.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/ui_theme.hpp"
#include "ui/window_state_manager.hpp"
#include "ui/workspace_view_model.hpp"

#include <QCoreApplication>
#include <QQmlApplicationEngine>
#include <QQmlComponent>
#include <QQmlContext>
#include <QSignalSpy>
#include <QVariantList>
#include <QVariantMap>
#include <chrono>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::client::ui::test {
namespace {

using namespace securecloud::client::application;
using securecloud::common::configuration::SecretString;

struct DiagnosticsQmlWarningCapture {
    inline static std::vector<std::string> warnings;
    inline static QtMessageHandler previous{nullptr};

    static void handler(QtMsgType type, const QMessageLogContext& context, const QString& msg) {
        if (type == QtWarningMsg || type == QtCriticalMsg || type == QtFatalMsg) {
            const std::string category = (context.category != nullptr) ? std::string(context.category) : std::string{};
            const std::string text = msg.toStdString();
            if (category.find("qt.qpa.fonts") == std::string::npos && text.find("qt.qpa.fonts") == std::string::npos &&
                text.find("Populating font family aliases") == std::string::npos) {
                warnings.push_back(text);
            }
        }
        if (previous != nullptr) {
            previous(type, context, msg);
        }
    }
};

struct ScopedDiagnosticsQmlWarningCapture {
    ScopedDiagnosticsQmlWarningCapture() {
        DiagnosticsQmlWarningCapture::warnings.clear();
        DiagnosticsQmlWarningCapture::previous = qInstallMessageHandler(&DiagnosticsQmlWarningCapture::handler);
    }
    ~ScopedDiagnosticsQmlWarningCapture() { qInstallMessageHandler(DiagnosticsQmlWarningCapture::previous); }
};

class WorkspaceViewModelDiagnosticsTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_vm_diag_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = temp_dir_ / "diag_ui_vault.db";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    std::filesystem::path temp_dir_;
    std::filesystem::path db_path_;
};

TEST_F(WorkspaceViewModelDiagnosticsTest, UnauthenticatedNavigationToDiagnosticsIsDeniedAndLogoutExitsCleanly) {
    NavigationController nav;
    QSignalSpy deniedSpy(&nav, &NavigationController::navigationDenied);
    QSignalSpy stateSpy(&nav, &NavigationController::stateChanged);

    // Route guard must reject unauthenticated navigation to Diagnostics.
    EXPECT_FALSE(nav.navigateTo(NavigationController::NavigationState::Diagnostics));
    EXPECT_EQ(deniedSpy.count(), 1);
    EXPECT_EQ(stateSpy.count(), 0);
    EXPECT_EQ(nav.currentState(), NavigationController::NavigationState::Unauthenticated);
    EXPECT_EQ(nav.currentViewName(), QStringLiteral("Login"));

    ClientConfig cfg = ClientConfig::create_default();
    cfg.database_path = db_path_.string();
    ClientApplication app(cfg);
    ASSERT_TRUE(app.initialize().is_ok());
    ASSERT_TRUE(app.start().is_ok());

    DiagnosticsViewModel diag_vm(app, nav);
    EXPECT_FALSE(diag_vm.autoRefreshActive());

    // Authenticate -> navigate to Settings -> auto-refresh stays off until entering Diagnostics.
    nav.setAuthenticated(true);
    EXPECT_TRUE(nav.navigateTo(NavigationController::NavigationState::Settings));
    EXPECT_FALSE(diag_vm.autoRefreshActive());

    EXPECT_TRUE(nav.navigateTo(NavigationController::NavigationState::Diagnostics));
    EXPECT_EQ(nav.currentViewName(), QStringLiteral("Diagnostics"));
    EXPECT_TRUE(diag_vm.autoRefreshActive());

    // Navigate back to Settings -> visibility-gated timer stops immediately (T05 idle CPU compliance).
    EXPECT_TRUE(nav.navigateBack());
    EXPECT_EQ(nav.currentViewName(), QStringLiteral("Settings"));
    EXPECT_FALSE(diag_vm.autoRefreshActive());

    // Enter Diagnostics again, then log out -> must reset to Unauthenticated & stop polling.
    EXPECT_TRUE(nav.navigateTo(NavigationController::NavigationState::Diagnostics));
    EXPECT_TRUE(diag_vm.autoRefreshActive());
    nav.setAuthenticated(false);
    EXPECT_EQ(nav.currentState(), NavigationController::NavigationState::Unauthenticated);
    EXPECT_FALSE(diag_vm.autoRefreshActive());

    EXPECT_TRUE(app.shutdown().is_ok());
}

TEST_F(WorkspaceViewModelDiagnosticsTest,
       DiagnosticsViewModelActionsRefreshRunSelfTestVerifyAuditAndExportWithoutSecretLeakage) {
    ClientConfig cfg = ClientConfig::create_default();
    cfg.database_path = db_path_.string();
    cfg.proxy_username = "ui_diag_proxy_canary";

    ClientApplication app(cfg);
    ASSERT_TRUE(app.initialize().is_ok());
    ASSERT_TRUE(app.start().is_ok());

    // Cache PII profile fields & inject adversarial secrets into local audit log.
    domain::UserProfile profile;
    profile.user_id = domain::UserId("usr-ui-diag-canary");
    profile.display_name = "Alice UI Canary";
    profile.public_handle = "alice_ui_handle";
    profile.bio_status = "Contact alice.ui@example.org";
    profile.updated_at_ms = 1760000003000LL;
    ASSERT_TRUE(app.bootstrap().settings_manager().update_profile(profile, false).is_ok());

    const std::string canary_password = "UiSecretCanary!9944";
    const std::string canary_email = "alice.ui@example.org";
    ASSERT_TRUE(app.bootstrap()
                    .local_audit_logger()
                    ->record_event(domain::LocalAuditCategory::SettingsNetwork, "ui.diag_canary",
                                   domain::LocalAuditOutcome::Success, canary_email, "dev-target",
                                   "password=" + canary_password + " email=" + canary_email +
                                       " handle=@alice_ui_handle /Users/canary_ui_op/vault.db")
                    .is_ok());

    NavigationController nav;
    DiagnosticsViewModel diag_vm(app, nav);
    diag_vm.refreshDiagnostics();

    EXPECT_GT(diag_vm.rssMegabytes(), 0.0);
    EXPECT_GE(diag_vm.cpuPercent(), 0.0);
    EXPECT_TRUE(diag_vm.selfTestPassed());
    EXPECT_EQ(diag_vm.selfTestChecks().size(), 6);
    EXPECT_TRUE(diag_vm.auditChainValid());
    EXPECT_GE(diag_vm.auditEventCount(), 1);
    EXPECT_FALSE(diag_vm.auditEvents().isEmpty());

    const std::vector<std::string> canaries = {
        canary_password, canary_email, "Alice UI Canary", "alice_ui_handle", "canary_ui_op", "ui_diag_proxy_canary",
    };

    auto assertNoCanaryInVariantList = [&](const QVariantList& rows) {
        for (const QVariant& item : rows) {
            const QVariantMap map = item.toMap();
            for (auto it = map.cbegin(); it != map.cend(); ++it) {
                const std::string val = it.value().toString().toStdString();
                EXPECT_FALSE(application::managers::DiagnosticSanitizer::contains_unredacted_secret_marker(val));
                for (const auto& canary : canaries) {
                    EXPECT_EQ(val.find(canary), std::string::npos) << "Canary leaked into QML property: " << canary;
                }
            }
        }
    };
    assertNoCanaryInVariantList(diag_vm.auditEvents());
    assertNoCanaryInVariantList(diag_vm.selfTestChecks());

    const int before_manual_selftest = diag_vm.auditEventCount();
    EXPECT_TRUE(diag_vm.runCryptoSelfTestNow());
    EXPECT_TRUE(diag_vm.verifyAuditChainNow());
    EXPECT_GT(diag_vm.auditEventCount(), before_manual_selftest);

    // Invalid paths must fail closed without creating files.
    EXPECT_FALSE(diag_vm.exportSanitizedBundle(QStringLiteral("   ")));
    EXPECT_FALSE(diag_vm.lastExportSucceeded());
    EXPECT_FALSE(diag_vm.exportSanitizedBundle(QString::fromStdString(temp_dir_.string())));
    EXPECT_FALSE(diag_vm.lastExportSucceeded());

    // Valid passphrase-protected .scdiag export through ViewModel.
    const std::filesystem::path bundle_path = temp_dir_ / "vm_export.scdiag";
    const QString passphrase = QStringLiteral("BundlePassphraseCanary!2026");
    EXPECT_TRUE(diag_vm.exportSanitizedBundle(QString::fromStdString(bundle_path.string()), passphrase));
    EXPECT_TRUE(diag_vm.lastExportSucceeded());
    EXPECT_EQ(diag_vm.lastExportSha256().size(), 64);
    EXPECT_TRUE(std::filesystem::exists(bundle_path));

    // Export passphrase/keys must never leak into QML state or audit rows.
    EXPECT_EQ(diag_vm.lastExportStatusText().indexOf(passphrase), -1);
    EXPECT_EQ(diag_vm.lastExportPath().indexOf(passphrase), -1);
    for (const QVariant& item : diag_vm.auditEvents()) {
        const QVariantMap map = item.toMap();
        for (auto it = map.cbegin(); it != map.cend(); ++it) {
            EXPECT_EQ(it.value().toString().indexOf(passphrase), -1);
        }
    }

    const auto dec_res = application::managers::DiagnosticsManager::decrypt_and_verify_bundle(
        bundle_path, SecretString(passphrase.toStdString()));
    ASSERT_TRUE(dec_res.is_ok()) << dec_res.error().user_message();
    for (const auto& canary : canaries) {
        EXPECT_EQ(dec_res.value().find(canary), std::string::npos);
    }

    // Emergency wipe clears cached audit/export state cleanly.
    diag_vm.resetForEmergencyWipe();
    EXPECT_TRUE(diag_vm.auditEvents().isEmpty());
    EXPECT_EQ(diag_vm.auditEventCount(), 0);
    EXPECT_TRUE(diag_vm.lastExportPath().isEmpty());
    EXPECT_TRUE(diag_vm.lastExportSha256().isEmpty());
    EXPECT_FALSE(diag_vm.lastExportSucceeded());

    EXPECT_TRUE(app.shutdown().is_ok());
}

TEST_F(WorkspaceViewModelDiagnosticsTest,
       HeadlessDiagnosticsViewAndSettingsEntryLoadWithZeroQmlWarningsAcrossThemesAndFontScales) {
    ScopedDiagnosticsQmlWarningCapture capture;

    ClientConfig cfg = ClientConfig::create_default();
    cfg.database_path = db_path_.string();
    ClientApplication app(cfg);
    ASSERT_TRUE(app.initialize().is_ok());
    ASSERT_TRUE(app.start().is_ok());

    NavigationController nav;
    AppViewModel app_vm(app, nav);
    DiagnosticsViewModel diag_vm(app, nav);
    WorkspaceViewModel workspace_vm(app, nav);
    UiTheme theme;
    WindowStateManager win_state;
    app_vm.setWorkspaceViewModel(&workspace_vm);
    workspace_vm.setUiTheme(&theme);

    nav.setAuthenticated(true);
    diag_vm.refreshDiagnostics();

    QQmlApplicationEngine engine;
    qmlRegisterSingletonInstance<UiTheme>("SecureCloud.Theme", 1, 0, "Theme", &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("navigationController"), &nav);
    engine.rootContext()->setContextProperty(QStringLiteral("appViewModel"), &app_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("diagnosticsViewModel"), &diag_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("workspaceViewModel"), &workspace_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("Theme"), &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("windowStateManager"), &win_state);

    // 1. Verify SettingsPlaceholder.qml contains Advanced -> Diagnostics card + button.
    {
        QQmlComponent settings_comp(&engine, QUrl(QStringLiteral("qrc:/qml/SettingsPlaceholder.qml")));
        ASSERT_TRUE(settings_comp.isReady()) << settings_comp.errorString().toStdString();
        QObject* settings_root = settings_comp.create();
        ASSERT_NE(settings_root, nullptr);
        EXPECT_NE(settings_root->findChild<QObject*>(QStringLiteral("advancedDiagnosticsCard")), nullptr);
        EXPECT_NE(settings_root->findChild<QObject*>(QStringLiteral("openDiagnosticsButton")), nullptr);
        delete settings_root;
        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();
    }

    // 2. Verify NavigationShell.qml lazy-loads DiagnosticsView when navigating to Diagnostics (6).
    {
        QQmlComponent shell_comp(&engine, QUrl(QStringLiteral("qrc:/qml/NavigationShell.qml")));
        ASSERT_TRUE(shell_comp.isReady()) << shell_comp.errorString().toStdString();
        QObject* shell_root = shell_comp.create();
        ASSERT_NE(shell_root, nullptr);

        ASSERT_TRUE(nav.navigateTo(NavigationController::NavigationState::Diagnostics));
        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();

        EXPECT_EQ(nav.currentViewName(), QStringLiteral("Diagnostics"));
        EXPECT_NE(shell_root->findChild<QObject*>(QStringLiteral("diagnosticsSelfTestCard")), nullptr);
        EXPECT_NE(shell_root->findChild<QObject*>(QStringLiteral("diagnosticsTelemetryCard")), nullptr);

        delete shell_root;
        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();
    }

    // 3. Load DiagnosticsView.qml directly & test Dark, Light, High-Contrast AAA, and fontScale extremes.
    {
        QQmlComponent diag_comp(&engine, QUrl(QStringLiteral("qrc:/qml/DiagnosticsView.qml")));
        ASSERT_TRUE(diag_comp.isReady()) << diag_comp.errorString().toStdString();
        QObject* diag_root = diag_comp.create();
        ASSERT_NE(diag_root, nullptr);

        for (const char* obj_name : {
                 "diagnosticsScrollView",    "refreshAllDiagnosticsButton", "backToSettingsButton",
                 "diagnosticsSelfTestCard",  "selfTestStatusBadge",         "runSelfTestButton",
                 "diagnosticsTelemetryCard", "refreshTelemetryButton",      "telemetryRssValue",
                 "telemetryCpuValue",        "telemetrySessionsValue",      "telemetryOutboxValue",
                 "telemetryTransfersValue",  "telemetryRttValue",           "diagnosticsAuditCard",
                 "auditChainStatusBadge",    "verifyAuditChainButton",      "auditEventsListView",
                 "diagnosticsExportCard",    "exportBundlePathField",       "exportPassphraseField",
                 "exportBundleButton",       "exportStatusBanner",
             }) {
            EXPECT_NE(diag_root->findChild<QObject*>(QString::fromUtf8(obj_name)), nullptr)
                << "Missing objectName: " << obj_name;
        }

        // Dark, Light, High-Contrast Dark (1.40x), High-Contrast Light (0.85x)
        EXPECT_TRUE(workspace_vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Dark), 1.0, false));
        QCoreApplication::processEvents();
        EXPECT_TRUE(workspace_vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Light), 1.0, false));
        QCoreApplication::processEvents();
        EXPECT_TRUE(workspace_vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Dark), 1.40, true));
        QCoreApplication::processEvents();
        EXPECT_TRUE(workspace_vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Light), 0.85, true));
        QCoreApplication::processEvents();

        // Trigger live export and audit update while DiagnosticsView is mounted.
        const std::filesystem::path ui_bundle = temp_dir_ / "headless_qml.scdiag";
        EXPECT_TRUE(diag_vm.exportSanitizedBundle(QString::fromStdString(ui_bundle.string())));
        QCoreApplication::processEvents();
        EXPECT_TRUE(diag_vm.lastExportSucceeded());

        delete diag_root;
        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();
    }

    engine.clearComponentCache();
    engine.rootContext()->setContextProperty(QStringLiteral("diagnosticsViewModel"), QVariant());
    engine.rootContext()->setContextProperty(QStringLiteral("workspaceViewModel"), QVariant());
    engine.rootContext()->setContextProperty(QStringLiteral("appViewModel"), QVariant());
    engine.rootContext()->setContextProperty(QStringLiteral("navigationController"), QVariant());
    engine.rootContext()->setContextProperty(QStringLiteral("Theme"), QVariant());
    engine.rootContext()->setContextProperty(QStringLiteral("windowStateManager"), QVariant());
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();

    EXPECT_TRUE(DiagnosticsQmlWarningCapture::warnings.empty())
        << (DiagnosticsQmlWarningCapture::warnings.empty() ? "" : DiagnosticsQmlWarningCapture::warnings.front());

    EXPECT_TRUE(app.shutdown().is_ok());
}

} // namespace
} // namespace securecloud::client::ui::test
