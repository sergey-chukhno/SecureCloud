#include "application/client_application.hpp"
#include "application/client_config.hpp"
#include "ui/app_view_model.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/workspace_view_model.hpp"

#include <QSignalSpy>
#include <gtest/gtest.h>

namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::ui;

TEST(NavigationControllerTest, DefaultStateIsUnauthenticated) {
    NavigationController controller;

    EXPECT_EQ(controller.currentState(), NavigationController::NavigationState::Unauthenticated);
    EXPECT_EQ(controller.currentViewName(), QStringLiteral("Login"));
    EXPECT_FALSE(controller.canNavigateBack());
    EXPECT_FALSE(controller.isAuthenticated());
}

TEST(NavigationControllerTest, RestrictedRoutesDeniedWhenUnauthenticated) {
    NavigationController controller;
    QSignalSpy deniedSpy(&controller, &NavigationController::navigationDenied);
    QSignalSpy stateSpy(&controller, &NavigationController::stateChanged);

    // Attempting to navigate to MainWorkspace while unauthenticated must fail
    const bool workspaceNav = controller.navigateTo(NavigationController::NavigationState::MainWorkspace);
    EXPECT_FALSE(workspaceNav);
    EXPECT_EQ(deniedSpy.count(), 1);
    EXPECT_EQ(stateSpy.count(), 0);
    EXPECT_EQ(controller.currentState(), NavigationController::NavigationState::Unauthenticated);

    // Attempting to navigate to Settings while unauthenticated must fail
    const bool settingsNav = controller.navigateTo(NavigationController::NavigationState::Settings);
    EXPECT_FALSE(settingsNav);
    EXPECT_EQ(deniedSpy.count(), 2);
    EXPECT_EQ(stateSpy.count(), 0);
}

TEST(NavigationControllerTest, AllowedUnauthenticatedRoutes) {
    NavigationController controller;
    QSignalSpy stateSpy(&controller, &NavigationController::stateChanged);

    EXPECT_TRUE(controller.navigateTo(NavigationController::NavigationState::MfaVerification));
    EXPECT_EQ(controller.currentViewName(), QStringLiteral("MfaVerification"));
    EXPECT_EQ(stateSpy.count(), 1);

    EXPECT_TRUE(controller.navigateTo(NavigationController::NavigationState::EmergencyMode));
    EXPECT_EQ(controller.currentViewName(), QStringLiteral("Emergency"));
    EXPECT_EQ(stateSpy.count(), 2);

    EXPECT_TRUE(controller.navigateTo(NavigationController::NavigationState::StyleGuide));
    EXPECT_EQ(controller.currentViewName(), QStringLiteral("StyleGuide"));
    EXPECT_EQ(stateSpy.count(), 3);
}

TEST(NavigationControllerTest, StyleGuideRouteAccessibleAndUnrestricted) {
    NavigationController controller;
    QSignalSpy stateSpy(&controller, &NavigationController::stateChanged);

    EXPECT_FALSE(controller.isAuthenticated());
    // StyleGuide must be accessible even when unauthenticated
    EXPECT_TRUE(controller.navigateTo(NavigationController::NavigationState::StyleGuide));
    EXPECT_EQ(controller.currentState(), NavigationController::NavigationState::StyleGuide);
    EXPECT_EQ(controller.currentViewName(), QStringLiteral("StyleGuide"));
    EXPECT_EQ(stateSpy.count(), 1);
    EXPECT_TRUE(controller.canNavigateBack());

    EXPECT_TRUE(controller.navigateBack());
    EXPECT_EQ(controller.currentState(), NavigationController::NavigationState::Unauthenticated);
}

TEST(NavigationControllerTest, AuthenticatedNavigationAndHistory) {
    NavigationController controller;
    QSignalSpy authSpy(&controller, &NavigationController::authenticationChanged);
    QSignalSpy stateSpy(&controller, &NavigationController::stateChanged);

    controller.setAuthenticated(true);
    EXPECT_TRUE(controller.isAuthenticated());
    EXPECT_EQ(authSpy.count(), 1);

    // Navigate to MainWorkspace
    EXPECT_TRUE(controller.navigateTo(NavigationController::NavigationState::MainWorkspace));
    EXPECT_EQ(controller.currentViewName(), QStringLiteral("Workspace"));
    EXPECT_TRUE(controller.canNavigateBack());

    // Navigate to Settings
    EXPECT_TRUE(controller.navigateTo(NavigationController::NavigationState::Settings));
    EXPECT_EQ(controller.currentViewName(), QStringLiteral("Settings"));

    // Navigate back to MainWorkspace
    EXPECT_TRUE(controller.navigateBack());
    EXPECT_EQ(controller.currentState(), NavigationController::NavigationState::MainWorkspace);
    EXPECT_TRUE(controller.canNavigateBack());

    // Navigate back to initial Unauthenticated
    EXPECT_TRUE(controller.navigateBack());
    EXPECT_EQ(controller.currentState(), NavigationController::NavigationState::Unauthenticated);
    EXPECT_FALSE(controller.canNavigateBack());
}

TEST(NavigationControllerTest, SetUnauthenticatedResetsRestrictedView) {
    NavigationController controller;
    controller.setAuthenticated(true);
    EXPECT_TRUE(controller.navigateTo(NavigationController::NavigationState::MainWorkspace));
    EXPECT_EQ(controller.currentState(), NavigationController::NavigationState::MainWorkspace);

    // Setting unauthenticated must immediately reset restricted view to Unauthenticated
    controller.setAuthenticated(false);
    EXPECT_EQ(controller.currentState(), NavigationController::NavigationState::Unauthenticated);
    EXPECT_FALSE(controller.canNavigateBack());
}

TEST(AppViewModelTest, LoginLogoutAndEmergencyFlow) {
    const auto config = ClientConfig::create_default();
    ClientApplication app(config);
    ASSERT_TRUE(app.initialize().is_ok());

    NavigationController navController;
    AppViewModel viewModel(app, navController);

    QSignalSpy userSpy(&viewModel, &AppViewModel::currentUserChanged);
    QSignalSpy wipeSpy(&viewModel, &AppViewModel::emergencyWipedChanged);

    EXPECT_EQ(viewModel.currentUser(), QStringLiteral(""));
    EXPECT_FALSE(viewModel.isEmergencyWiped());
    EXPECT_EQ(viewModel.connectionStatus(), QStringLiteral("Connected"));

    // 1. Request Login
    viewModel.requestLogin(QStringLiteral("alice"), QStringLiteral("password123"));
    EXPECT_EQ(viewModel.currentUser(), QStringLiteral("alice"));
    EXPECT_TRUE(navController.isAuthenticated());
    EXPECT_EQ(navController.currentState(), NavigationController::NavigationState::MainWorkspace);
    EXPECT_EQ(userSpy.count(), 1);

    // 2. Request Logout
    viewModel.requestLogout();
    EXPECT_EQ(viewModel.currentUser(), QStringLiteral(""));
    EXPECT_FALSE(navController.isAuthenticated());
    EXPECT_EQ(navController.currentState(), NavigationController::NavigationState::Unauthenticated);
    EXPECT_EQ(userSpy.count(), 2);

    // 3. Emergency Wipe
    viewModel.triggerEmergencyWipe();
    EXPECT_TRUE(viewModel.isEmergencyWiped());
    EXPECT_FALSE(viewModel.isAuthenticated());
    EXPECT_FALSE(navController.isAuthenticated());
    EXPECT_EQ(navController.currentState(), NavigationController::NavigationState::EmergencyMode);
    EXPECT_EQ(wipeSpy.count(), 1);
}

TEST(AppViewModelTest, SecurityStateConsistencyAndMfaAndWipeRevocation) {
    const auto config = ClientConfig::create_default();
    ClientApplication app(config);
    ASSERT_TRUE(app.initialize().is_ok());

    NavigationController navController;
    AppViewModel viewModel(app, navController);

    // 1. Pre-auth state must never claim Verified Identity or E2EE session
    EXPECT_FALSE(viewModel.isAuthenticated());
    EXPECT_EQ(viewModel.securityBadgeType(), QStringLiteral("Offline"));
    EXPECT_EQ(viewModel.sessionStatusText(), QStringLiteral("Unauthenticated — Awaiting Credentials"));
    EXPECT_EQ(viewModel.securityStatusText(), QStringLiteral("TLS 1.3 Gateway Ready · No Active Session"));

    // 2. Empty login produces Validation error and keeps user unauthenticated
    viewModel.requestLogin(QStringLiteral(""), QStringLiteral(""));
    EXPECT_FALSE(viewModel.isAuthenticated());
    EXPECT_EQ(viewModel.lastErrorCategory(), QStringLiteral("Validation"));
    EXPECT_FALSE(viewModel.lastErrorMessage().isEmpty());

    // 3. Valid login transitions to MainWorkspace and clears pre-auth back history
    viewModel.requestLogin(QStringLiteral("alice"), QStringLiteral("password123"));
    EXPECT_TRUE(viewModel.isAuthenticated());
    EXPECT_EQ(viewModel.lastErrorMessage(), QStringLiteral(""));
    EXPECT_EQ(navController.currentState(), NavigationController::NavigationState::MainWorkspace);
    EXPECT_FALSE(navController.canNavigateBack());
    EXPECT_EQ(viewModel.securityBadgeType(), QStringLiteral("Info"));

    // 4. Emergency Wipe while authenticated must revoke authentication and clear user
    viewModel.triggerEmergencyWipe();
    EXPECT_TRUE(viewModel.isEmergencyWiped());
    EXPECT_FALSE(viewModel.isAuthenticated());
    EXPECT_FALSE(navController.isAuthenticated());
    EXPECT_EQ(viewModel.currentUser(), QStringLiteral(""));
    EXPECT_EQ(viewModel.securityBadgeType(), QStringLiteral("Danger"));
}

TEST(AppViewModelTest, MfaChallengeFlow) {
    const auto config = ClientConfig::create_default();
    ClientApplication app(config);
    ASSERT_TRUE(app.initialize().is_ok());

    NavigationController navController;
    AppViewModel viewModel(app, navController);

    viewModel.beginMfaChallenge(QStringLiteral("bob"), QStringLiteral("secret456"));
    EXPECT_EQ(navController.currentState(), NavigationController::NavigationState::MfaVerification);
    EXPECT_FALSE(viewModel.isAuthenticated());

    // Invalid MFA code
    viewModel.submitMfaCode(QStringLiteral("123"));
    EXPECT_FALSE(viewModel.isAuthenticated());
    EXPECT_EQ(viewModel.lastErrorCategory(), QStringLiteral("Authentication"));

    // Valid 6-digit MFA code
    viewModel.submitMfaCode(QStringLiteral("482910"));
    EXPECT_TRUE(viewModel.isAuthenticated());
    EXPECT_EQ(viewModel.currentUser(), QStringLiteral("bob"));
    EXPECT_EQ(navController.currentState(), NavigationController::NavigationState::MainWorkspace);
}

TEST(NavigationControllerTest, WorkspaceSectionsRequireAuthAndSwitchCleanly) {
    NavigationController controller;
    QSignalSpy deniedSpy(&controller, &NavigationController::navigationDenied);
    QSignalSpy sectionSpy(&controller, &NavigationController::workspaceSectionChanged);

    // Unauthenticated section switch must fail
    EXPECT_FALSE(controller.navigateToSection(QStringLiteral("Files")));
    EXPECT_EQ(deniedSpy.count(), 1);
    EXPECT_EQ(controller.activeWorkspaceSection(), QStringLiteral("Messages"));

    // Authenticated section switch transitions to MainWorkspace and updates section
    controller.setAuthenticated(true);
    EXPECT_TRUE(controller.navigateToSection(QStringLiteral("Files")));
    EXPECT_EQ(controller.currentState(), NavigationController::NavigationState::MainWorkspace);
    EXPECT_EQ(controller.activeWorkspaceSection(), QStringLiteral("Files"));
    EXPECT_EQ(sectionSpy.count(), 1);

    EXPECT_TRUE(controller.navigateToSection(QStringLiteral("Contacts")));
    EXPECT_EQ(controller.activeWorkspaceSection(), QStringLiteral("Contacts"));
    EXPECT_EQ(sectionSpy.count(), 2);

    // Reset restores Messages section
    controller.reset(NavigationController::NavigationState::Unauthenticated);
    EXPECT_EQ(controller.activeWorkspaceSection(), QStringLiteral("Messages"));
}

TEST(WorkspaceViewModelTest, SearchSelectionMessagingFileTransferAndWipe) {
    const auto config = ClientConfig::create_default();
    ClientApplication app(config);
    ASSERT_TRUE(app.initialize().is_ok());

    NavigationController navController;
    navController.setAuthenticated(true);
    WorkspaceViewModel workspace(app, navController);

    // 1. Default seeded state
    EXPECT_EQ(workspace.activeSection(), QStringLiteral("Messages"));
    EXPECT_EQ(workspace.conversations().size(), 5);
    EXPECT_EQ(workspace.contacts().size(), 5);
    EXPECT_EQ(workspace.fileTransfers().size(), 3);
    EXPECT_EQ(workspace.selectedPeerName(), QStringLiteral("Frances Swann"));
    EXPECT_TRUE(workspace.isInspectorOpen());

    // 2. Real-time search filter across conversations and files
    workspace.setSearchQuery(QStringLiteral("Angelina"));
    EXPECT_EQ(workspace.conversations().size(), 1);
    EXPECT_EQ(workspace.fileTransfers().size(), 1);
    workspace.setSearchQuery(QStringLiteral(""));
    EXPECT_EQ(workspace.conversations().size(), 5);

    // 3. Select conversation & clear unread count
    workspace.selectConversation(QStringLiteral("conv-angelina"));
    EXPECT_EQ(workspace.selectedPeerName(), QStringLiteral("Angelina Froster"));

    // 4. Send message via MessagingManager
    const qsizetype initialMsgCount = workspace.activeMessages().size();
    EXPECT_TRUE(workspace.sendMessage(QStringLiteral("Verified threat model hash.")));
    EXPECT_EQ(workspace.activeMessages().size(), initialMsgCount + 1);

    // 5. Stage encrypted file transfer via FileManager
    const qsizetype initialFileCount = workspace.fileTransfers().size();
    const QString txId = workspace.stageEncryptedFileTransfer(QStringLiteral("incident-keys.enc"), 2097152);
    EXPECT_FALSE(txId.isEmpty());
    EXPECT_EQ(workspace.fileTransfers().size(), initialFileCount + 1);
    EXPECT_TRUE(workspace.cancelFileTransfer(txId));

    // 6. Toggle inspector & block peer
    workspace.toggleInspector();
    EXPECT_FALSE(workspace.isInspectorOpen());
    workspace.togglePeerBlocked(QStringLiteral(""));
    EXPECT_TRUE(workspace.selectedPeerBlocked());
    EXPECT_FALSE(workspace.sendMessage(QStringLiteral("Should be blocked")));

    // 7. Emergency wipe resets workspace state
    workspace.resetForEmergencyWipe();
    EXPECT_TRUE(workspace.conversations().isEmpty());
    EXPECT_TRUE(workspace.fileTransfers().isEmpty());
}

} // namespace
