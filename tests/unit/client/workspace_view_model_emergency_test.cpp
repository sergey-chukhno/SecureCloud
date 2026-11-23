#include "application/client_application.hpp"
#include "application/client_config.hpp"
#include "domain/device_private_bundle.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "ui/app_view_model.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/ui_theme.hpp"
#include "ui/window_state_manager.hpp"
#include "ui/workspace_view_model.hpp"

#include <QCoreApplication>
#include <QQmlApplicationEngine>
#include <QQmlComponent>
#include <QQmlContext>
#include <QSignalSpy>
#include <QUrl>
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
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure::adapters;

DeviceCryptoDirectoryEntry seed_device_bundle(ISecureStorage& storage, OpenSslCryptoProvider& crypto,
                                              const DeviceId& did) {
    auto ik = crypto.generate_identity_keypair().value();
    auto spk = crypto.generate_signed_prekey(ik.private_key).value();
    auto otk = crypto.generate_dh_keypair().value();

    DevicePrivateBundle bundle(did, ik.public_key, std::move(ik.private_key), spk.public_key,
                               std::move(spk.private_key), spk.signature);
    bundle.add_one_time_prekey(did.value() + "-otk-1", std::move(otk.private_key));
    EXPECT_TRUE(KeyStorageHelper::save_bundle(storage, bundle).is_ok());

    return DeviceCryptoDirectoryEntry{
        .device_id = did,
        .identity_key = ik.public_key,
        .signed_prekey = spk.public_key,
        .signed_prekey_signature = spk.signature,
        .one_time_prekey = otk.public_key,
        .one_time_prekey_id = did.value() + "-otk-1",
    };
}

struct QmlWarningCapture {
    inline static std::vector<std::string> warnings;
    inline static QtMessageHandler previous{nullptr};

    static void handler(QtMsgType type, const QMessageLogContext& context, const QString& msg) {
        if (type == QtWarningMsg || type == QtCriticalMsg || type == QtFatalMsg) {
            const std::string text = msg.toStdString();
            if (text.find("qt.qpa.fonts") == std::string::npos) {
                warnings.push_back(text);
            }
        }
        if (previous != nullptr) {
            previous(type, context, msg);
        }
    }
};

class WorkspaceViewModelEmergencyTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_ui_emergency_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = temp_dir_ / "vault.db";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    [[nodiscard]] ClientConfig make_config() const {
        ClientConfig cfg = ClientConfig::create_default();
        cfg.database_path = db_path_.string();
        return cfg;
    }

    std::filesystem::path temp_dir_;
    std::filesystem::path db_path_;
};

TEST_F(WorkspaceViewModelEmergencyTest, InstantPanicWipeClearsWorkspacePopulatesSafeSummaryAndResetsCleanly) {
    ClientApplication app(make_config());
    ASSERT_TRUE(app.initialize().is_ok());
    ASSERT_TRUE(app.start().is_ok());

    NavigationController nav;
    AppViewModel app_vm(app, nav);
    WorkspaceViewModel workspace_vm(app, nav);
    app_vm.setWorkspaceViewModel(&workspace_vm);

    app_vm.requestLogin(QStringLiteral("alice"), QStringLiteral("Strong-Password!2026"));
    EXPECT_TRUE(app_vm.isAuthenticated());
    ASSERT_TRUE(workspace_vm.addContact(QStringLiteral("bob@securecloud.org"), QStringLiteral("Bob Operator"),
                                        QStringLiteral("SecOps Lead")));
    ASSERT_FALSE(workspace_vm.conversations().isEmpty());
    const QString first_conv_id =
        workspace_vm.conversations().first().toMap().value(QStringLiteral("conversationId")).toString();
    workspace_vm.selectConversation(first_conv_id);
    ASSERT_TRUE(workspace_vm.sendMessage(QStringLiteral("Confidential operational message")));
    EXPECT_FALSE(workspace_vm.activeMessages().isEmpty());
    EXPECT_TRUE(std::filesystem::exists(db_path_));

    app_vm.triggerInstantPanicWipe(0); // EmergencyLocked

    EXPECT_TRUE(app_vm.isEmergencyWiped());
    EXPECT_FALSE(app_vm.isDecoySession());
    EXPECT_FALSE(app_vm.isAuthenticated());
    EXPECT_EQ(nav.currentState(), NavigationController::NavigationState::EmergencyMode);

    EXPECT_TRUE(workspace_vm.conversations().isEmpty());
    EXPECT_TRUE(workspace_vm.activeMessages().isEmpty());
    EXPECT_TRUE(workspace_vm.fileTransfers().isEmpty());
    EXPECT_TRUE(workspace_vm.devices().isEmpty());
    EXPECT_TRUE(workspace_vm.selectedConversationId().isEmpty());
    EXPECT_FALSE(std::filesystem::exists(db_path_));
    EXPECT_TRUE(app.bootstrap().secure_storage().list_secret_keys().value().empty());

    const QVariantMap summary = app_vm.lastWipeReportSummary();
    EXPECT_TRUE(summary.value(QStringLiteral("hasReport")).toBool());
    EXPECT_TRUE(summary.value(QStringLiteral("allCriticalStepsSucceeded")).toBool());
    EXPECT_LT(summary.value(QStringLiteral("durationMs")).toLongLong(), 500LL);
    EXPECT_GT(summary.value(QStringLiteral("secretsPurgedCount")).toULongLong(), 0ULL);
    EXPECT_EQ(summary.value(QStringLiteral("triggerSource")).toString(), QStringLiteral("UiPanicButton"));
    EXPECT_FALSE(summary.value(QStringLiteral("stepResults")).toList().isEmpty());

    app_vm.resetClientAfterWipe();
    EXPECT_FALSE(app_vm.isEmergencyWiped());
    EXPECT_FALSE(app_vm.isDecoySession());
    EXPECT_EQ(nav.currentState(), NavigationController::NavigationState::Unauthenticated);
    EXPECT_FALSE(app_vm.lastWipeReportSummary().value(QStringLiteral("hasReport")).toBool());

    (void)app.shutdown();
}

TEST_F(WorkspaceViewModelEmergencyTest, BroadcastThenPanicWipeDispatchesPriority3AlertAndShredsVault) {
    ClientApplication app(make_config());
    ASSERT_TRUE(app.initialize().is_ok());
    ASSERT_TRUE(app.start().is_ok());

    const UserId alice_uid("alice");
    const DeviceId alice_did("alice-dev-1");
    const UserId bob_uid("bob");
    const DeviceId bob_did("bob-dev-1");

    OpenSslCryptoProvider crypto;
    const auto alice_dir = seed_device_bundle(app.bootstrap().secure_storage(), crypto, alice_did);
    MemorySecureStorage bob_storage;
    const auto bob_dir = seed_device_bundle(bob_storage, crypto, bob_did);

    auto* sim_gw = dynamic_cast<DefaultGatewayClient*>(&app.bootstrap().gateway());
    ASSERT_NE(sim_gw, nullptr);
    sim_gw->set_simulated_user_directory(alice_uid, {alice_dir});
    sim_gw->set_simulated_user_directory(bob_uid, {bob_dir});

    app.bootstrap().initialize_ratchet_session_manager(alice_uid, alice_did);

    const ConversationId cid("conv-secops");
    ASSERT_TRUE(app.bootstrap()
                    .local_store()
                    .save_conversation(Conversation(cid, ConversationType::Direct, "SecOps Lead", {alice_uid, bob_uid}))
                    .is_ok());

    NavigationController nav;
    AppViewModel app_vm(app, nav);
    WorkspaceViewModel workspace_vm(app, nav);
    app_vm.setWorkspaceViewModel(&workspace_vm);

    app_vm.requestLogin(QStringLiteral("alice"), QStringLiteral("Strong-Password!2026"));
    app_vm.triggerBroadcastAndPanicWipe(QStringLiteral("conv-secops"), QStringLiteral("Compromised laptop"),
                                        QStringLiteral(R"({"lat":46.95,"lon":7.45})"), false);

    ASSERT_EQ(sim_gw->submitted_fanouts().size(), 1U);
    EXPECT_EQ(sim_gw->submitted_fanouts().front().priority, 3);
    EXPECT_FALSE(std::filesystem::exists(db_path_));
    EXPECT_TRUE(app.bootstrap().secure_storage().list_secret_keys().value().empty());
    EXPECT_TRUE(workspace_vm.conversations().isEmpty());
    EXPECT_EQ(nav.currentState(), NavigationController::NavigationState::EmergencyMode);

    const QVariantMap summary = app_vm.lastWipeReportSummary();
    EXPECT_TRUE(summary.value(QStringLiteral("hasReport")).toBool());
    EXPECT_TRUE(summary.value(QStringLiteral("broadcastAttempted")).toBool());

    (void)app.shutdown();
}

TEST_F(WorkspaceViewModelEmergencyTest, DuressPinConfigAndSilentLoginRoutesToBenignDecoyWorkspaceViaLoginAndMfa) {
    // Subcase A: Login route with spaced Option A passphrase
    {
        ClientApplication app(make_config());
        ASSERT_TRUE(app.initialize().is_ok());
        ASSERT_TRUE(app.start().is_ok());

        NavigationController nav;
        AppViewModel app_vm(app, nav);
        WorkspaceViewModel workspace_vm(app, nav);
        app_vm.setWorkspaceViewModel(&workspace_vm);

        EXPECT_FALSE(app_vm.configureDuressPin(QStringLiteral("12345"), 2));
        EXPECT_EQ(app_vm.lastErrorCategory(), QStringLiteral("Validation"));

        const QString duress_pass = QStringLiteral(" Decoy-Pass!42 ");
        EXPECT_TRUE(app_vm.configureDuressPin(duress_pass, 2));
        EXPECT_TRUE(app_vm.hasDuressPinConfigured());
        EXPECT_EQ(app_vm.configuredDuressPostWipeMode(), 2);

        EXPECT_TRUE(app_vm.clearDuressPin());
        EXPECT_FALSE(app_vm.hasDuressPinConfigured());

        EXPECT_TRUE(app_vm.configureDuressPin(duress_pass, 2));
        app_vm.requestLogin(QStringLiteral("alice"), QStringLiteral("Real-Password!2026"));
        ASSERT_TRUE(workspace_vm.addContact(QStringLiteral("bob@securecloud.org"), QStringLiteral("Bob Operator"),
                                            QStringLiteral("SecOps Lead")));
        ASSERT_FALSE(workspace_vm.conversations().isEmpty());
        const QString first_conv_id =
            workspace_vm.conversations().first().toMap().value(QStringLiteral("conversationId")).toString();
        workspace_vm.selectConversation(first_conv_id);
        ASSERT_TRUE(workspace_vm.sendMessage(QStringLiteral("Confidential operational message")));
        EXPECT_FALSE(workspace_vm.activeMessages().isEmpty());
        app_vm.requestLogout();

        app_vm.requestLogin(QStringLiteral("alice"), duress_pass);

        EXPECT_TRUE(app_vm.isAuthenticated());
        EXPECT_TRUE(app_vm.isDecoySession());
        EXPECT_EQ(nav.currentState(), NavigationController::NavigationState::MainWorkspace);
        EXPECT_TRUE(workspace_vm.conversations().isEmpty());
        EXPECT_TRUE(workspace_vm.activeMessages().isEmpty());
        EXPECT_FALSE(app_vm.hasDuressPinConfigured());
        EXPECT_FALSE(std::filesystem::exists(db_path_));

        // OPSEC: Decoy workspace exposes zero wipe or danger indicators.
        EXPECT_TRUE(app_vm.lastWipeReportSummary().isEmpty());
        EXPECT_EQ(app_vm.connectionStatus(), QStringLiteral("Connected"));
        EXPECT_NE(app_vm.securityBadgeType(), QStringLiteral("Danger"));
        EXPECT_TRUE(app_vm.sessionStatusText().contains(QStringLiteral("Authenticated Session")));
        EXPECT_FALSE(app_vm.sessionStatusText().contains(QStringLiteral("Wipe")));

        (void)app.shutdown();
    }

    // Subcase B: MFA button route also intercepts duress credential immediately
    {
        const std::filesystem::path mfa_db = temp_dir_ / "mfa_duress.db";
        ClientConfig cfg = ClientConfig::create_default();
        cfg.database_path = mfa_db.string();

        ClientApplication app(cfg);
        ASSERT_TRUE(app.initialize().is_ok());
        ASSERT_TRUE(app.start().is_ok());

        NavigationController nav;
        AppViewModel app_vm(app, nav);
        WorkspaceViewModel workspace_vm(app, nav);
        app_vm.setWorkspaceViewModel(&workspace_vm);

        ASSERT_TRUE(app_vm.configureDuressPin(QStringLiteral("mfa-duress-77"), 2));
        app_vm.beginMfaChallenge(QStringLiteral("alice"), QStringLiteral("mfa-duress-77"));

        EXPECT_TRUE(app_vm.isAuthenticated());
        EXPECT_TRUE(app_vm.isDecoySession());
        EXPECT_EQ(nav.currentState(), NavigationController::NavigationState::MainWorkspace);
        EXPECT_FALSE(std::filesystem::exists(mfa_db));

        (void)app.shutdown();
    }
}

TEST_F(WorkspaceViewModelEmergencyTest, HeadlessQmlScreensLoadWithZeroWarningsInDarkAndLightThemes) {
    QmlWarningCapture::warnings.clear();
    QmlWarningCapture::previous = qInstallMessageHandler(&QmlWarningCapture::handler);

    ClientApplication app(make_config());
    ASSERT_TRUE(app.initialize().is_ok());
    ASSERT_TRUE(app.start().is_ok());

    NavigationController nav;
    AppViewModel app_vm(app, nav);
    WorkspaceViewModel workspace_vm(app, nav);
    app_vm.setWorkspaceViewModel(&workspace_vm);
    UiTheme theme;
    WindowStateManager win_state;

    QQmlApplicationEngine engine;
    qmlRegisterSingletonInstance<UiTheme>("SecureCloud.Theme", 1, 0, "Theme", &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("navigationController"), &nav);
    engine.rootContext()->setContextProperty(QStringLiteral("appViewModel"), &app_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("workspaceViewModel"), &workspace_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("Theme"), &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("windowStateManager"), &win_state);

    for (const char* qrc_url :
         {"qrc:/qml/Main.qml", "qrc:/qml/EmergencyPlaceholder.qml", "qrc:/qml/SettingsPlaceholder.qml"}) {
        QQmlComponent component(&engine, QUrl(QString::fromUtf8(qrc_url)));
        ASSERT_TRUE(component.isReady()) << qrc_url << ": " << component.errorString().toStdString();
        QObject* obj = component.create();
        ASSERT_NE(obj, nullptr) << qrc_url;

        if (std::string_view(qrc_url) == "qrc:/qml/Main.qml") {
            EXPECT_NE(obj->findChild<QObject*>(QStringLiteral("emergencyPanicModal")), nullptr);
        } else if (std::string_view(qrc_url) == "qrc:/qml/EmergencyPlaceholder.qml") {
            EXPECT_NE(obj->findChild<QObject*>(QStringLiteral("resetAfterWipeButton")), nullptr);
        } else if (std::string_view(qrc_url) == "qrc:/qml/SettingsPlaceholder.qml") {
            EXPECT_NE(obj->findChild<QObject*>(QStringLiteral("duressPolicyCard")), nullptr);
            EXPECT_NE(obj->findChild<QObject*>(QStringLiteral("duressPinField")), nullptr);
            EXPECT_NE(obj->findChild<QObject*>(QStringLiteral("saveDuressPinButton")), nullptr);
        }

        theme.setThemeMode(ThemeMode::Dark);
        QCoreApplication::processEvents();
        theme.setThemeMode(ThemeMode::Light);
        QCoreApplication::processEvents();

        delete obj;
        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();
    }

    qInstallMessageHandler(QmlWarningCapture::previous);
    EXPECT_TRUE(QmlWarningCapture::warnings.empty())
        << (QmlWarningCapture::warnings.empty() ? "" : QmlWarningCapture::warnings.front());

    (void)app.shutdown();
}

} // namespace
} // namespace securecloud::client::ui::test
