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
    void SetUp() override {
        engine_.rootContext()->setContextProperty("Theme", &theme_);
        engine_.rootContext()->setContextProperty("navigationController", &navController_);
    }

    void TearDown() override {
        engine_.clearComponentCache();
        engine_.rootContext()->setContextProperty("Theme", QVariant());
        engine_.rootContext()->setContextProperty("navigationController", QVariant());
        engine_.rootContext()->setContextProperty("appViewModel", QVariant());
        engine_.rootContext()->setContextProperty("workspaceViewModel", QVariant());
        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();
    }

    UiTheme theme_;
    NavigationController navController_;
    QQmlApplicationEngine engine_;
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

    engine_.rootContext()->setContextProperty("workspaceViewModel", QVariant());
    engine_.rootContext()->setContextProperty("appViewModel", QVariant());
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
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
    engine_.rootContext()->setContextProperty("workspaceViewModel", QVariant());
    engine_.rootContext()->setContextProperty("appViewModel", QVariant());
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
}

TEST_F(UiComponentsTest, GroupConversationCreationAndRosterInspection) {
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

    // 1. Verify existence of group management dialogs
    auto* newConvDialog = workspaceObj->findChild<QObject*>("newConversationDialog");
    ASSERT_NE(newConvDialog, nullptr);
    EXPECT_FALSE(newConvDialog->property("isOpen").toBool());

    auto* addPartDialog = workspaceObj->findChild<QObject*>("addParticipantDialog");
    ASSERT_NE(addPartDialog, nullptr);
    EXPECT_FALSE(addPartDialog->property("isOpen").toBool());

    auto* leaveGroupDialog = workspaceObj->findChild<QObject*>("leaveGroupConfirmDialog");
    ASSERT_NE(leaveGroupDialog, nullptr);
    EXPECT_FALSE(leaveGroupDialog->property("isOpen").toBool());

    // 2. Select seeded group conversation (SecOps Incident Bridge)
    workspaceViewModel.selectConversation("conv-secops");
    EXPECT_TRUE(workspaceViewModel.selectedConversationIsGroup());
    EXPECT_GE(workspaceViewModel.selectedConversationParticipantCount(), 3);
    EXPECT_FALSE(workspaceViewModel.selectedConversationParticipants().isEmpty());

    // 3. Test aggregate verification getters
    EXPECT_GE(workspaceViewModel.selectedGroupUnverifiedCount(), 0);

    // 4. Test adding and removing a participant
    const int initialCount = workspaceViewModel.selectedConversationParticipantCount();
    EXPECT_TRUE(workspaceViewModel.addParticipantToActiveGroup("corina.mccoy@securecloud.org"));
    EXPECT_EQ(workspaceViewModel.selectedConversationParticipantCount(), initialCount + 1);

    EXPECT_TRUE(workspaceViewModel.removeParticipantFromActiveGroup("corina.mccoy@securecloud.org"));
    EXPECT_EQ(workspaceViewModel.selectedConversationParticipantCount(), initialCount);

    // 5. Test creating a new group conversation via ViewModel
    const QVariantList members = {"angelina.froster@securecloud.org", "ricky.smith@securecloud.org"};
    const QString newGroupId = workspaceViewModel.createGroupConversation("Zero-Trust Response Unit", members);
    EXPECT_FALSE(newGroupId.isEmpty());
    EXPECT_TRUE(workspaceViewModel.selectedConversationIsGroup());
    EXPECT_EQ(workspaceViewModel.selectedPeerName(), "Zero-Trust Response Unit");
    EXPECT_EQ(workspaceViewModel.selectedConversationParticipantCount(), 3); // 2 members + operator

    delete workspaceObj;
    engine_.rootContext()->setContextProperty("workspaceViewModel", QVariant());
    engine_.rootContext()->setContextProperty("appViewModel", QVariant());
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
}

TEST_F(UiComponentsTest, DeliveryStateRetryAndEmergencyAcknowledgement) {
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

    // 1. Verify existence of emergency alert banner
    auto* emergencyBanner = workspaceObj->findChild<QObject*>("emergencyAlertBanner");
    ASSERT_NE(emergencyBanner, nullptr);

    // 2. Select conversation with emergency message (conv-angelina)
    workspaceViewModel.selectConversation("conv-angelina");
    EXPECT_EQ(workspaceViewModel.unacknowledgedEmergencyCount(), 2);
    EXPECT_TRUE(emergencyBanner->property("visible").toBool());

    // 3. Acknowledge emergency messages
    EXPECT_TRUE(workspaceViewModel.acknowledgeEmergencyMessage("msg-5"));
    EXPECT_EQ(workspaceViewModel.unacknowledgedEmergencyCount(), 1);
    EXPECT_TRUE(emergencyBanner->property("visible").toBool());

    EXPECT_TRUE(workspaceViewModel.acknowledgeEmergencyMessage("msg-6"));
    EXPECT_EQ(workspaceViewModel.unacknowledgedEmergencyCount(), 0);
    EXPECT_FALSE(emergencyBanner->property("visible").toBool());

    // 4. Test delivery failure simulation toggle
    EXPECT_FALSE(workspaceViewModel.deliveryFailureSimulated());
    workspaceViewModel.setSimulateDeliveryFailure(true);
    EXPECT_TRUE(workspaceViewModel.deliveryFailureSimulated());

    // 5. Send message with failure simulation active
    EXPECT_TRUE(workspaceViewModel.sendMessage("Simulated packet drop payload", 1));
    const auto activeMsgs = workspaceViewModel.activeMessages();
    ASSERT_FALSE(activeMsgs.isEmpty());
    const auto lastMsg = activeMsgs.last().toMap();
    EXPECT_EQ(lastMsg.value("deliveryState").toString(), "Failed");
    const QString failedMsgId = lastMsg.value("messageId").toString();
    const QString idemKey = lastMsg.value("idempotencyKey").toString();
    EXPECT_FALSE(failedMsgId.isEmpty());
    EXPECT_FALSE(idemKey.isEmpty());

    // 6. Test idempotent retry
    EXPECT_TRUE(workspaceViewModel.retryFailedMessage(failedMsgId));
    const auto activeMsgsAfterRetry = workspaceViewModel.activeMessages();
    const auto retriedMsg = activeMsgsAfterRetry.last().toMap();
    EXPECT_EQ(retriedMsg.value("deliveryState").toString(), "Delivered");
    EXPECT_EQ(retriedMsg.value("idempotencyKey").toString(), idemKey); // Preserved

    // 7. Test discard failed message
    EXPECT_TRUE(workspaceViewModel.sendMessage("Transient drop to be discarded", 1));
    const auto msgsBeforeDiscard = workspaceViewModel.activeMessages();
    const auto discardMsg = msgsBeforeDiscard.last().toMap();
    EXPECT_EQ(discardMsg.value("deliveryState").toString(), "Failed");
    const QString discardMsgId = discardMsg.value("messageId").toString();

    EXPECT_TRUE(workspaceViewModel.discardFailedMessage(discardMsgId));
    const auto msgsAfterDiscard = workspaceViewModel.activeMessages();
    EXPECT_EQ(msgsAfterDiscard.size(), msgsBeforeDiscard.size() - 1);

    // Turn failure simulation back off
    workspaceViewModel.setSimulateDeliveryFailure(false);
    EXPECT_FALSE(workspaceViewModel.deliveryFailureSimulated());

    // 8. Test Search Query and clearSearchQuery
    workspaceViewModel.setSearchQuery("nonexistent_filter_query");
    EXPECT_EQ(workspaceViewModel.searchQuery(), "nonexistent_filter_query");
    workspaceViewModel.clearSearchQuery();
    EXPECT_TRUE(workspaceViewModel.searchQuery().isEmpty());

    delete workspaceObj;
    engine_.rootContext()->setContextProperty("workspaceViewModel", QVariant());
    engine_.rootContext()->setContextProperty("appViewModel", QVariant());
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
}

} // namespace
