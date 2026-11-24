#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto/recovery_phrase_engine.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "ui/app_view_model.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/ui_theme.hpp"
#include "ui/window_state_manager.hpp"
#include "ui/workspace_view_model.hpp"

#include <QCoreApplication>
#include <QMetaObject>
#include <QQmlApplicationEngine>
#include <QQmlComponent>
#include <QQmlContext>
#include <QSignalSpy>
#include <QStringList>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::client::ui::test {
namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure::adapters;

class ForwardingSecureStorage final : public ISecureStorage {
  public:
    explicit ForwardingSecureStorage(std::shared_ptr<MemorySecureStorage> inner) : inner_(std::move(inner)) {}

    ClientResult<void> store_secret(std::string_view key_id,
                                    const common::configuration::SecretString& secret) override {
        return inner_->store_secret(key_id, secret);
    }

    ClientResult<common::configuration::SecretString> get_secret(std::string_view key_id) override {
        return inner_->get_secret(key_id);
    }

    ClientResult<void> delete_secret(std::string_view key_id) override { return inner_->delete_secret(key_id); }

    ClientResult<bool> has_secret(std::string_view key_id) override { return inner_->has_secret(key_id); }

    ClientResult<std::vector<std::string>> list_secret_keys() override { return inner_->list_secret_keys(); }

    ClientResult<std::size_t> purge_all_secrets() override { return inner_->purge_all_secrets(); }

  private:
    std::shared_ptr<MemorySecureStorage> inner_;
};

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

struct ScopedQmlWarningCapture {
    ScopedQmlWarningCapture() {
        QmlWarningCapture::warnings.clear();
        QmlWarningCapture::previous = qInstallMessageHandler(&QmlWarningCapture::handler);
    }
    ~ScopedQmlWarningCapture() { qInstallMessageHandler(QmlWarningCapture::previous); }
};

class WorkspaceViewModelSettingsTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_vm_settings_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = temp_dir_ / "vault.db";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    std::unique_ptr<ClientApplication> create_persistent_app(std::shared_ptr<MemorySecureStorage> shared_storage,
                                                             DefaultGatewayClient** out_gateway = nullptr) {
        ClientConfig config = ClientConfig::create_default();
        config.database_path = db_path_.string();

        auto gateway = std::make_unique<DefaultGatewayClient>(config);
        if (out_gateway != nullptr) {
            *out_gateway = gateway.get();
        }
        auto crypto = std::make_unique<OpenSslCryptoProvider>();
        auto secure_storage = std::make_unique<ForwardingSecureStorage>(shared_storage);
        auto local_store = std::make_unique<SqlCipherLocalStore>(*shared_storage, *crypto);

        auto bootstrap =
            ClientBootstrap::create_with_adapters(std::move(config), std::move(gateway), std::move(local_store),
                                                  std::move(secure_storage), std::move(crypto));
        auto app = std::make_unique<ClientApplication>(std::move(bootstrap));
        EXPECT_TRUE(app->initialize().is_ok());
        EXPECT_TRUE(app->start().is_ok());
        return app;
    }

    std::filesystem::path temp_dir_;
    std::filesystem::path db_path_;
};

TEST_F(WorkspaceViewModelSettingsTest, PersistsAppearanceMfaAndReadReceiptsAcrossRestart) {
    auto shared_storage = std::make_shared<MemorySecureStorage>();

    {
        auto app = create_persistent_app(shared_storage);
        NavigationController nav;
        UiTheme theme;
        WorkspaceViewModel vm(*app, nav);
        vm.setUiTheme(&theme);

        ASSERT_TRUE(vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Light), 1.25, true));
        EXPECT_EQ(theme.themeMode(), ThemeMode::Light);
        EXPECT_FALSE(theme.isDark());
        EXPECT_DOUBLE_EQ(theme.fontScale(), 1.25);
        EXPECT_TRUE(theme.highContrastEnabled());
        EXPECT_EQ(theme.backgroundPrimary(), QStringLiteral("#FFFFFF"));

        vm.setMfaRequiredOnLogin(false);
        vm.setHardwareKeyEnforced(false);
        vm.setReadReceiptsEnabled(false);

        EXPECT_FALSE(vm.mfaRequiredOnLogin());
        EXPECT_FALSE(vm.hardwareKeyEnforced());
        EXPECT_FALSE(vm.readReceiptsEnabled());

        (void)app->shutdown();
    }

    // Reopen fresh ClientApplication & WorkspaceViewModel + UiTheme against the same SQLCipher database.
    {
        auto app2 = create_persistent_app(shared_storage);
        NavigationController nav2;
        UiTheme theme2;
        WorkspaceViewModel vm2(*app2, nav2);
        vm2.setUiTheme(&theme2);

        EXPECT_EQ(vm2.themeMode(), static_cast<int>(ThemeMode::Light));
        EXPECT_DOUBLE_EQ(vm2.fontScale(), 1.25);
        EXPECT_TRUE(vm2.highContrastEnabled());
        EXPECT_FALSE(vm2.mfaRequiredOnLogin());
        EXPECT_FALSE(vm2.hardwareKeyEnforced());
        EXPECT_FALSE(vm2.readReceiptsEnabled());

        EXPECT_EQ(theme2.themeMode(), ThemeMode::Light);
        EXPECT_DOUBLE_EQ(theme2.fontScale(), 1.25);
        EXPECT_TRUE(theme2.highContrastEnabled());
        EXPECT_EQ(theme2.textPrimary(), QStringLiteral("#000000"));
        EXPECT_GT(theme2.fontBody(), 13);

        (void)app2->shutdown();
    }
}

TEST_F(WorkspaceViewModelSettingsTest, UserProfileSavePrivacyGateAndEncryptedAvatarUpload) {
    auto shared_storage = std::make_shared<MemorySecureStorage>();
    auto app = create_persistent_app(shared_storage);

    NavigationController nav;
    AppViewModel app_vm(*app, nav);
    WorkspaceViewModel vm(*app, nav);
    app_vm.setWorkspaceViewModel(&vm);
    app_vm.requestLogin(QStringLiteral("alice"), QStringLiteral("Strong-Password!2026"));

    // Privacy gate disabled -> profile remains local only.
    EXPECT_TRUE(vm.saveUserProfile(QStringLiteral("Alice Operator"), QStringLiteral("@alice.secops"),
                                   QStringLiteral("Endpoint Security Lead"), false, true));
    EXPECT_EQ(vm.profileDisplayName(), QStringLiteral("Alice Operator"));
    EXPECT_EQ(vm.profileHandle(), QStringLiteral("alice.secops"));
    EXPECT_EQ(vm.profileBio(), QStringLiteral("Endpoint Security Lead"));
    EXPECT_FALSE(vm.profileAllowDiscovery());
    EXPECT_EQ(vm.profileSyncStatusText(), QStringLiteral("Local Only (Discovery Disabled)"));

    // Discovery opt-in enabled -> syncs with DefaultGatewayClient cleanly.
    EXPECT_TRUE(vm.saveUserProfile(QStringLiteral("Alice Operator"), QStringLiteral("alice.secops"),
                                   QStringLiteral("Endpoint Security Lead"), true, true));
    EXPECT_TRUE(vm.profileAllowDiscovery());
    EXPECT_EQ(vm.profileSyncStatusText(), QStringLiteral("Synced with Gateway"));

    // Create sample local PNG file and upload as encrypted E2EE avatar.
    const std::filesystem::path avatar_path = temp_dir_ / "operator_avatar.png";
    {
        std::ofstream ofs(avatar_path, std::ios::binary);
        const std::string fake_png = "\x89PNG\r\n\x1a\nPLACEHOLDER_AVATAR_BYTES";
        ofs.write(fake_png.data(), static_cast<std::streamsize>(fake_png.size()));
    }

    EXPECT_TRUE(vm.uploadAvatarImage(QUrl::fromLocalFile(QString::fromStdString(avatar_path.string())).toString()));
    EXPECT_FALSE(vm.profileAvatarFileId().isEmpty());
    EXPECT_EQ(vm.profileAvatarSha256().size(), 64);

    // Invalid extension is rejected without clearing existing avatar.
    const std::filesystem::path bad_path = temp_dir_ / "script.sh";
    {
        std::ofstream ofs(bad_path);
        ofs << "#!/bin/sh\necho nope\n";
    }
    const QString prev_avatar_id = vm.profileAvatarFileId();
    EXPECT_FALSE(vm.uploadAvatarImage(QString::fromStdString(bad_path.string())));
    EXPECT_EQ(vm.profileAvatarFileId(), prev_avatar_id);

    (void)app->shutdown();
}

TEST_F(WorkspaceViewModelSettingsTest, NetworkProxyAndTlsPinConfigPersistsAndTracksLiveProxyPasswordState) {
    auto shared_storage = std::make_shared<MemorySecureStorage>();
    auto app = create_persistent_app(shared_storage);

    NavigationController nav;
    WorkspaceViewModel vm(*app, nav);

    EXPECT_FALSE(vm.hasProxyPassword());

    const QString sample_pin = QString(64, QLatin1Char('a'));
    ASSERT_TRUE(vm.saveNetworkAndProxyConfig(false, QStringLiteral("https://gw.corp.internal:9443"), 9443,
                                             static_cast<int>(ProxyType::Http), QStringLiteral("proxy.corp.internal"),
                                             8080, QStringLiteral("proxy-alice"), QStringLiteral("Proxy-Secret!42"),
                                             false, sample_pin, true));

    EXPECT_EQ(vm.gatewayHost(), QStringLiteral("gw.corp.internal"));
    EXPECT_EQ(vm.gatewayPort(), 9443);
    EXPECT_EQ(vm.proxyType(), static_cast<int>(ProxyType::Http));
    EXPECT_EQ(vm.proxyHost(), QStringLiteral("proxy.corp.internal"));
    EXPECT_EQ(vm.proxyPort(), 8080);
    EXPECT_EQ(vm.proxyUsername(), QStringLiteral("proxy-alice"));
    EXPECT_TRUE(vm.hasProxyPassword());
    EXPECT_EQ(vm.tlsPinnedFingerprint(), sample_pin);
    EXPECT_TRUE(vm.tlsEnforceStrictPinning());

    // Inspect Gateway TLS fingerprint & pin observed SPKI SHA-256.
    const QVariantMap inspected = vm.inspectGatewayTlsFingerprint(QStringLiteral("gw.corp.internal"), 9443, true);
    const QString observed_spki = inspected.value(QStringLiteral("spkiSha256")).toString();
    EXPECT_EQ(observed_spki.size(), 64);
    EXPECT_EQ(vm.tlsPinnedFingerprint(), observed_spki);
    EXPECT_TRUE(vm.tlsPinMatches());

    // Clear saved proxy password explicitly while retaining proxy configuration.
    ASSERT_TRUE(vm.saveNetworkAndProxyConfig(false, QStringLiteral("gw.corp.internal"), 9443,
                                             static_cast<int>(ProxyType::Http), QStringLiteral("proxy.corp.internal"),
                                             8080, QStringLiteral("proxy-alice"), QString(), true, observed_spki,
                                             true));
    EXPECT_FALSE(vm.hasProxyPassword());

    (void)app->shutdown();
}

TEST_F(WorkspaceViewModelSettingsTest, DisappearingTimersUpdateWorkspaceDefaultAndActiveConversation) {
    auto shared_storage = std::make_shared<MemorySecureStorage>();
    auto app = create_persistent_app(shared_storage);

    NavigationController nav;
    WorkspaceViewModel vm(*app, nav);

    ASSERT_TRUE(vm.addContact(QStringLiteral("bob@securecloud.org"), QStringLiteral("Bob SecOps"),
                              QStringLiteral("Incident Lead")));
    ASSERT_FALSE(vm.conversations().isEmpty());
    const QString cid = vm.conversations().first().toMap().value(QStringLiteral("conversationId")).toString();
    vm.selectConversation(cid);

    EXPECT_EQ(vm.defaultDisappearingTtlSeconds(), 0LL);
    EXPECT_EQ(vm.activeConversationDisappearingTtlSeconds(), 0LL);

    // Unsupported workspace default preset is rejected cleanly.
    EXPECT_FALSE(vm.setDefaultDisappearingTimer(42));
    EXPECT_EQ(vm.defaultDisappearingTtlSeconds(), 0LL);

    EXPECT_TRUE(vm.setDefaultDisappearingTimer(3600));
    EXPECT_EQ(vm.defaultDisappearingTtlSeconds(), 3600LL);
    EXPECT_EQ(app->bootstrap().messaging_manager().default_disappearing_ttl_seconds(), 3600LL);

    EXPECT_TRUE(vm.setConversationDisappearingTimer(cid, 86400));
    EXPECT_EQ(vm.activeConversationDisappearingTtlSeconds(), 86400LL);

    const auto conv_res = app->bootstrap().messaging_manager().get_conversation(ConversationId(cid.toStdString()));
    ASSERT_TRUE(conv_res.is_ok());
    EXPECT_EQ(conv_res.value().disappearing_ttl_seconds(), 86400LL);

    (void)app->shutdown();
}

TEST_F(WorkspaceViewModelSettingsTest, EndpointOnlyBip39Recovery12DefaultAnd24WordFlowAndEmergencyWipeCleanup) {
    auto shared_storage = std::make_shared<MemorySecureStorage>();
    DefaultGatewayClient* raw_gw = nullptr;
    auto app = create_persistent_app(shared_storage, &raw_gw);
    ASSERT_NE(raw_gw, nullptr);

    NavigationController nav;
    WorkspaceViewModel vm(*app, nav);

    EXPECT_FALSE(vm.recoveryPhraseVerified());
    EXPECT_EQ(vm.recoveryPhraseStatusText(), QStringLiteral("Not Backed Up"));

    const std::size_t calls_before = raw_gw->submitted_fanouts().size() + raw_gw->sent_delivery_acks().size() +
                                     raw_gw->sent_read_receipts().size() + raw_gw->profile_update_call_count();

    // Default 12-word BIP-39 flow.
    const QVariantMap payload12 = vm.generateRecoveryPhraseWords(false);
    const QStringList words12 = payload12.value(QStringLiteral("words")).toStringList();
    const QVariantList indices12 = payload12.value(QStringLiteral("challengeIndices")).toList();
    ASSERT_EQ(words12.size(), 12);
    ASSERT_EQ(indices12.size(), 3);
    EXPECT_EQ(vm.recoveryPhraseStatusText(), QStringLiteral("Awaiting 3-Word Confirmation"));

    // Wrong confirmation answers must fail cleanly without marking backed up.
    const QVariantList wrong_answers{QStringLiteral("wrong"), QStringLiteral("words"), QStringLiteral("here")};
    EXPECT_FALSE(vm.confirmRecoveryPhraseChallenge(indices12, wrong_answers));
    EXPECT_FALSE(vm.recoveryPhraseVerified());

    // Exact challenge answers confirm backup locally.
    QVariantList exact_answers12;
    for (const auto& idxVar : indices12) {
        exact_answers12.append(words12[idxVar.toInt()]);
    }
    EXPECT_TRUE(vm.confirmRecoveryPhraseChallenge(indices12, exact_answers12));
    EXPECT_TRUE(vm.recoveryPhraseVerified());
    EXPECT_EQ(vm.recoveryPhraseStatusText(), QStringLiteral("Verified (Local Only)"));

    EXPECT_TRUE(vm.verifyRecoveryPhraseInput(words12.join(QLatin1Char(' '))));
    QStringList tampered = words12;
    tampered[0] = (tampered[0] == QStringLiteral("abandon")) ? QStringLiteral("ability") : QStringLiteral("abandon");
    EXPECT_FALSE(vm.verifyRecoveryPhraseInput(tampered.join(QLatin1Char(' '))));

    // Optional 24-word BIP-39 flow.
    const QVariantMap payload24 = vm.generateRecoveryPhraseWords(true);
    const QStringList words24 = payload24.value(QStringLiteral("words")).toStringList();
    const QVariantList indices24 = payload24.value(QStringLiteral("challengeIndices")).toList();
    ASSERT_EQ(words24.size(), 24);
    ASSERT_EQ(indices24.size(), 3);

    QVariantList exact_answers24;
    for (const auto& idxVar : indices24) {
        exact_answers24.append(words24[idxVar.toInt()]);
    }
    EXPECT_TRUE(vm.confirmRecoveryPhraseChallenge(indices24, exact_answers24));
    EXPECT_TRUE(vm.verifyRecoveryPhraseInput(words24.join(QLatin1Char(' '))));

    const std::size_t calls_after = raw_gw->submitted_fanouts().size() + raw_gw->sent_delivery_acks().size() +
                                    raw_gw->sent_read_receipts().size() + raw_gw->profile_update_call_count();
    EXPECT_EQ(calls_after, calls_before);

    // Emergency wipe clears ViewModel volatile profile/settings/pending recovery state.
    EXPECT_TRUE(vm.saveUserProfile(QStringLiteral("Alice Confidential"), QStringLiteral("alice.ops"),
                                   QStringLiteral("Sensitive status"), false, false));
    (void)vm.generateRecoveryPhraseWords(false);
    vm.resetForEmergencyWipe();
    EXPECT_TRUE(vm.profileDisplayName().isEmpty());
    EXPECT_EQ(vm.profileSyncStatusText(), QStringLiteral("Cleared"));
    EXPECT_TRUE(vm.pendingRecoveryChallengeIndices().isEmpty());

    (void)app->shutdown();
}

TEST_F(WorkspaceViewModelSettingsTest,
       HeadlessSettingsPlaceholderLoadsAllSevenCardsWithZeroWarningsAcrossThemesAndFontScales) {
    ScopedQmlWarningCapture capture;

    auto shared_storage = std::make_shared<MemorySecureStorage>();
    auto app = create_persistent_app(shared_storage);

    NavigationController nav;
    AppViewModel app_vm(*app, nav);
    WorkspaceViewModel workspace_vm(*app, nav);
    UiTheme theme;
    WindowStateManager win_state;
    app_vm.setWorkspaceViewModel(&workspace_vm);
    workspace_vm.setUiTheme(&theme);

    QQmlApplicationEngine engine;
    qmlRegisterSingletonInstance<UiTheme>("SecureCloud.Theme", 1, 0, "Theme", &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("navigationController"), &nav);
    engine.rootContext()->setContextProperty(QStringLiteral("appViewModel"), &app_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("workspaceViewModel"), &workspace_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("Theme"), &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("windowStateManager"), &win_state);

    QQmlComponent component(&engine, QUrl(QStringLiteral("qrc:/qml/SettingsPlaceholder.qml")));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();
    QObject* root = component.create();
    ASSERT_NE(root, nullptr);

    // Verify all 7 cards + modal overlay + preserved CLIENT-010/013 hooks.
    for (const char* obj_name : {
             "settingsScrollView",
             "profileCard",
             "profileSyncStatusBadge",
             "profileDisplayNameField",
             "profileHandleField",
             "profileBioField",
             "profileAllowDiscoverySwitch",
             "saveProfileButton",
             "profileAvatarPathField",
             "uploadAvatarButton",
             "localIdentityCard",
             "linkedDevicesCard",
             "securityPrivacyCard",
             "readReceiptsSwitch",
             "defaultTimerOffButton",
             "defaultTimer1hButton",
             "defaultTimer24hButton",
             "defaultTimer7dButton",
             "duressPolicyCard",
             "duressStatusBadge",
             "duressPinField",
             "duressPinConfirmField",
             "saveDuressPinButton",
             "clearDuressPinButton",
             "appearanceCard",
             "themeDarkButton",
             "themeLightButton",
             "themeSystemButton",
             "fontScale85Button",
             "fontScale100Button",
             "fontScale120Button",
             "fontScale140Button",
             "highContrastSwitch",
             "networkTlsCard",
             "liveTransportSwitch",
             "gatewayHostField",
             "gatewayPortField",
             "proxyTypeNoneButton",
             "proxyTypeHttpButton",
             "proxyTypeSocks5Button",
             "tlsPinnedSpkiField",
             "tlsStrictPinningSwitch",
             "tlsPinStatusBadge",
             "inspectTlsButton",
             "pinObservedTlsButton",
             "saveNetworkConfigButton",
             "recoveryPhraseCard",
             "recoveryStatusBadge",
             "recoveryLength12Button",
             "recoveryLength24Button",
             "generateRecoveryPhraseButton",
             "verifyExistingRecoveryField",
             "verifyExistingRecoveryButton",
             "recoveryPhraseModal",
             "recoveryWordsGrid",
             "recoveryChallengeInput0",
             "recoveryChallengeInput1",
             "recoveryChallengeInput2",
             "confirmRecoveryChallengeButton",
             "cancelRecoveryModalButton",
         }) {
        EXPECT_NE(root->findChild<QObject*>(QString::fromUtf8(obj_name)), nullptr)
            << "Missing objectName: " << obj_name;
    }

    // Exercise runtime accessibility/palette combinations & recovery modal live.
    EXPECT_TRUE(workspace_vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Light), 1.20, false));
    QCoreApplication::processEvents();
    EXPECT_TRUE(workspace_vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Dark), 1.40, true));
    QCoreApplication::processEvents();
    EXPECT_TRUE(workspace_vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Light), 0.85, true));
    QCoreApplication::processEvents();

    auto* modal = root->findChild<QObject*>(QStringLiteral("recoveryPhraseModal"));
    ASSERT_NE(modal, nullptr);
    const QVariantMap payload = workspace_vm.generateRecoveryPhraseWords(false);
    ASSERT_TRUE(QMetaObject::invokeMethod(modal, "openWithPayload", Q_ARG(QVariant, QVariant::fromValue(payload))));
    QCoreApplication::processEvents();
    EXPECT_TRUE(modal->property("isOpen").toBool());
    ASSERT_TRUE(QMetaObject::invokeMethod(modal, "closeModal"));
    QCoreApplication::processEvents();
    EXPECT_FALSE(modal->property("isOpen").toBool());

    delete root;
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();

    EXPECT_TRUE(QmlWarningCapture::warnings.empty())
        << (QmlWarningCapture::warnings.empty() ? "" : QmlWarningCapture::warnings.front());

    (void)app->shutdown();
}

} // namespace
} // namespace securecloud::client::ui::test
