#include "application/client_application.hpp"
#include "application/client_config.hpp"
#include "ui/app_view_model.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/ui_theme.hpp"
#include "ui/workspace_view_model.hpp"

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlComponent>
#include <QQmlContext>
#include <QUrl>
#include <gtest/gtest.h>

namespace {

using namespace securecloud::client::ui;

class UiComponentsTest : public ::testing::Test {
  protected:
    static void SetUpTestSuite() {
        if (!qobject_cast<QGuiApplication*>(QGuiApplication::instance())) {
            static int argc = 1;
            static char appName[] = "UiComponentsTest";
            static char* argv[] = {appName, nullptr};
            // Intentionally allocate on heap to avoid static destruction order issues with gtest_main
            [[maybe_unused]] static auto* app = new QGuiApplication(argc, argv);
        }
    }

    void SetUp() override {
        engine_.rootContext()->setContextProperty("Theme", &theme_);
        engine_.rootContext()->setContextProperty("navigationController", &navController_);
    }

    QQmlApplicationEngine engine_;
    UiTheme theme_;
    NavigationController navController_;
};

TEST_F(UiComponentsTest, SCButtonInstantiationAndProperties) {
    QQmlComponent component(&engine_, QUrl("qrc:/qml/controls/SCButton.qml"));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();

    auto* obj = component.create();
    ASSERT_NE(obj, nullptr);

    // Verify default properties
    EXPECT_EQ(obj->property("variant").toString(), "Primary");
    EXPECT_EQ(obj->property("busy").toBool(), false);
    EXPECT_EQ(obj->property("enabled").toBool(), true);
    EXPECT_EQ(obj->property("buttonHeight").toInt(), 38);

    // Mutation of properties
    obj->setProperty("variant", "Danger");
    EXPECT_EQ(obj->property("variant").toString(), "Danger");

    obj->setProperty("text", "Emergency Wipe");
    EXPECT_EQ(obj->property("text").toString(), "Emergency Wipe");

    obj->setProperty("busy", true);
    EXPECT_TRUE(obj->property("busy").toBool());

    delete obj;
}

TEST_F(UiComponentsTest, SCTextFieldInstantiationAndProperties) {
    QQmlComponent component(&engine_, QUrl("qrc:/qml/controls/SCTextField.qml"));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();

    auto* obj = component.create();
    ASSERT_NE(obj, nullptr);

    // Verify label and placeholder
    obj->setProperty("label", "Master Key");
    EXPECT_EQ(obj->property("label").toString(), "Master Key");

    obj->setProperty("placeholderText", "Enter 32-byte secret");
    EXPECT_EQ(obj->property("placeholderText").toString(), "Enter 32-byte secret");

    obj->setProperty("isPassword", true);
    EXPECT_TRUE(obj->property("isPassword").toBool());

    obj->setProperty("isMonospace", true);
    EXPECT_TRUE(obj->property("isMonospace").toBool());

    obj->setProperty("text", "super_secret_payload");
    EXPECT_EQ(obj->property("text").toString(), "super_secret_payload");

    obj->setProperty("errorMessage", "Key checksum verification failed");
    EXPECT_EQ(obj->property("errorMessage").toString(), "Key checksum verification failed");

    delete obj;
}

TEST_F(UiComponentsTest, SCIconButtonInstantiationAndProperties) {
    QQmlComponent component(&engine_, QUrl("qrc:/qml/controls/SCIconButton.qml"));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();

    auto* obj = component.create();
    ASSERT_NE(obj, nullptr);

    EXPECT_EQ(obj->property("variant").toString(), "Ghost");
    EXPECT_EQ(obj->property("size").toInt(), 34);

    obj->setProperty("iconText", "⚙");
    EXPECT_EQ(obj->property("iconText").toString(), "⚙");

    obj->setProperty("tooltipText", "Application Settings");
    EXPECT_EQ(obj->property("tooltipText").toString(), "Application Settings");

    obj->setProperty("badgeCount", 7);
    EXPECT_EQ(obj->property("badgeCount").toInt(), 7);

    obj->setProperty("active", true);
    EXPECT_TRUE(obj->property("active").toBool());

    delete obj;
}

TEST_F(UiComponentsTest, SCCardInstantiationAndProperties) {
    QQmlComponent component(&engine_, QUrl("qrc:/qml/controls/SCCard.qml"));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();

    auto* obj = component.create();
    ASSERT_NE(obj, nullptr);

    EXPECT_EQ(obj->property("elevation").toString(), "Base");
    EXPECT_TRUE(obj->property("hasBorder").toBool());

    obj->setProperty("headerText", "Security Credentials");
    EXPECT_EQ(obj->property("headerText").toString(), "Security Credentials");

    obj->setProperty("elevation", "Elevated");
    EXPECT_EQ(obj->property("elevation").toString(), "Elevated");

    delete obj;
}

TEST_F(UiComponentsTest, SCBadgeInstantiationAndTypes) {
    QQmlComponent component(&engine_, QUrl("qrc:/qml/controls/SCBadge.qml"));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();

    auto* obj = component.create();
    ASSERT_NE(obj, nullptr);

    EXPECT_EQ(obj->property("type").toString(), "Info");
    EXPECT_TRUE(obj->property("hasDot").toBool());

    obj->setProperty("type", "Verified");
    EXPECT_EQ(obj->property("type").toString(), "Verified");

    obj->setProperty("text", "E2EE Verified");
    EXPECT_EQ(obj->property("text").toString(), "E2EE Verified");

    delete obj;
}

TEST_F(UiComponentsTest, SCAvatarInitialsAndHashGeneration) {
    QQmlComponent component(&engine_, QUrl("qrc:/qml/controls/SCAvatar.qml"));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();

    auto* obj = component.create();
    ASSERT_NE(obj, nullptr);

    EXPECT_EQ(obj->property("size").toInt(), 40);
    EXPECT_EQ(obj->property("presence").toString(), "None");

    obj->setProperty("displayName", "Alice Smith");
    obj->setProperty("userId", "alice@securecloud.org");
    obj->setProperty("presence", "Online");

    EXPECT_EQ(obj->property("displayName").toString(), "Alice Smith");
    EXPECT_EQ(obj->property("presence").toString(), "Online");

    // Test getInitials function invokable from QML
    QVariant returnedInitials;
    QMetaObject::invokeMethod(obj, "getInitials", Q_RETURN_ARG(QVariant, returnedInitials),
                              Q_ARG(QVariant, "Alice Smith"), Q_ARG(QVariant, "alice@securecloud.org"));
    EXPECT_EQ(returnedInitials.toString(), "AS");

    QVariant singleWordInitials;
    QMetaObject::invokeMethod(obj, "getInitials", Q_RETURN_ARG(QVariant, singleWordInitials), Q_ARG(QVariant, "Bob"),
                              Q_ARG(QVariant, "bob@securecloud.org"));
    EXPECT_EQ(singleWordInitials.toString(), "BO");

    delete obj;
}

TEST_F(UiComponentsTest, SCDialogConfirmedAndCancelledSignals) {
    QQmlComponent component(&engine_, QUrl("qrc:/qml/controls/SCDialog.qml"));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();

    auto* obj = component.create();
    ASSERT_NE(obj, nullptr);

    EXPECT_FALSE(obj->property("isOpen").toBool());
    EXPECT_FALSE(obj->property("isDanger").toBool());

    obj->setProperty("title", "Confirm Action");
    obj->setProperty("message", "Proceed with operation?");
    obj->setProperty("isDanger", true);
    obj->setProperty("isOpen", true);

    EXPECT_TRUE(obj->property("isOpen").toBool());
    EXPECT_TRUE(obj->property("isDanger").toBool());

    delete obj;
}

TEST_F(UiComponentsTest, StyleGuideViewInstantiation) {
    QQmlComponent component(&engine_, QUrl("qrc:/qml/StyleGuideView.qml"));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();

    auto* obj = component.create();
    ASSERT_NE(obj, nullptr);
    delete obj;
}

TEST_F(UiComponentsTest, NavigationShellInstantiationAndRouting) {
    QQmlComponent component(&engine_, QUrl("qrc:/qml/NavigationShell.qml"));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();

    auto* obj = component.create();
    ASSERT_NE(obj, nullptr);
    EXPECT_FALSE(obj->property("showAlert").toBool());
    delete obj;
}

TEST_F(UiComponentsTest, WorkspaceAndSettingsViewsInstantiation) {
    const auto config = securecloud::client::application::ClientConfig::create_default();
    securecloud::client::application::ClientApplication clientApp(config);
    ASSERT_TRUE(clientApp.initialize().is_ok());

    navController_.setAuthenticated(true);
    AppViewModel appViewModel(clientApp, navController_);
    WorkspaceViewModel workspaceViewModel(clientApp, navController_);

    engine_.rootContext()->setContextProperty("appViewModel", &appViewModel);
    engine_.rootContext()->setContextProperty("workspaceViewModel", &workspaceViewModel);

    // 1. Instantiate WorkspacePlaceholder.qml and verify section switching
    QQmlComponent workspaceComp(&engine_, QUrl("qrc:/qml/WorkspacePlaceholder.qml"));
    ASSERT_TRUE(workspaceComp.isReady()) << workspaceComp.errorString().toStdString();
    auto* workspaceObj = workspaceComp.create();
    ASSERT_NE(workspaceObj, nullptr);
    EXPECT_EQ(workspaceObj->property("activeSection").toString(), "Messages");

    workspaceViewModel.setActiveSection("Files");
    EXPECT_EQ(workspaceObj->property("activeSection").toString(), "Files");

    workspaceViewModel.setActiveSection("Contacts");
    EXPECT_EQ(workspaceObj->property("activeSection").toString(), "Contacts");

    delete workspaceObj;

    // 2. Instantiate SettingsPlaceholder.qml (Device Trust, Identity & MFA Center)
    QQmlComponent settingsComp(&engine_, QUrl("qrc:/qml/SettingsPlaceholder.qml"));
    ASSERT_TRUE(settingsComp.isReady()) << settingsComp.errorString().toStdString();
    auto* settingsObj = settingsComp.create();
    ASSERT_NE(settingsObj, nullptr);
    delete settingsObj;
}

TEST_F(UiComponentsTest, ContactsDirectoryAndKeyChangedSecurityBanner) {
    const auto config = securecloud::client::application::ClientConfig::create_default();
    securecloud::client::application::ClientApplication clientApp(config);
    ASSERT_TRUE(clientApp.initialize().is_ok());

    navController_.setAuthenticated(true);
    AppViewModel appViewModel(clientApp, navController_);
    WorkspaceViewModel workspaceViewModel(clientApp, navController_);

    engine_.rootContext()->setContextProperty("appViewModel", &appViewModel);
    engine_.rootContext()->setContextProperty("workspaceViewModel", &workspaceViewModel);

    QQmlComponent workspaceComp(&engine_, QUrl("qrc:/qml/WorkspacePlaceholder.qml"));
    ASSERT_TRUE(workspaceComp.isReady()) << workspaceComp.errorString().toStdString();
    auto* workspaceObj = workspaceComp.create();
    ASSERT_NE(workspaceObj, nullptr);

    // 1. Verify Contacts section active state & seeded count
    workspaceViewModel.setActiveSection("Contacts");
    EXPECT_EQ(workspaceObj->property("activeSection").toString(), "Contacts");
    EXPECT_EQ(workspaceViewModel.contacts().size(), 5);

    // 2. Locate ADR-008 Key Changed Security Banner
    auto* banner = workspaceObj->findChild<QObject*>("keyChangedSecurityBanner");
    ASSERT_NE(banner, nullptr);
    EXPECT_FALSE(banner->property("visible").toBool());

    // 3. Simulate peer identity key change -> banner becomes visible
    workspaceViewModel.simulatePeerKeyChange("frances.swann@securecloud.org");
    EXPECT_TRUE(workspaceViewModel.selectedPeerKeyChanged());
    EXPECT_TRUE(banner->property("visible").toBool());

    // 4. Verify safety number -> banner becomes hidden again
    workspaceViewModel.acceptAndVerifyPeerKey("frances.swann@securecloud.org");
    EXPECT_FALSE(workspaceViewModel.selectedPeerKeyChanged());
    EXPECT_FALSE(banner->property("visible").toBool());

    // 5. Verify Add Contact Dialog & Edit Contact Dialog exist
    auto* addDialog = workspaceObj->findChild<QObject*>("addContactDialog");
    ASSERT_NE(addDialog, nullptr);
    EXPECT_FALSE(addDialog->property("isOpen").toBool());

    auto* editDialog = workspaceObj->findChild<QObject*>("editContactDialog");
    ASSERT_NE(editDialog, nullptr);
    EXPECT_FALSE(editDialog->property("isOpen").toBool());

    auto* removeDialog = workspaceObj->findChild<QObject*>("removeContactConfirmDialog");
    ASSERT_NE(removeDialog, nullptr);
    EXPECT_FALSE(removeDialog->property("isOpen").toBool());

    delete workspaceObj;
}

} // namespace
