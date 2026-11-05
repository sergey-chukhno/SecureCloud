#include "application/client_app_service.hpp"
#include "domain/session_state.hpp"
#include "infrastructure/gateway_adapter_stub.hpp"
#include "ui/ui_controller.hpp"

#include <QSignalSpy>
#include <gtest/gtest.h>

namespace {

using namespace securecloud::client;

TEST(ClientDomainTest, SessionStateDefaultInitialization) {
    domain::SessionState state;
    EXPECT_TRUE(state.userId().empty());
    EXPECT_TRUE(state.deviceId().empty());
    EXPECT_EQ(state.status(), domain::SessionStatus::LoggedOut);
    EXPECT_FALSE(state.isAuthenticated());
}

TEST(ClientDomainTest, SessionStateLifecycleAndReset) {
    domain::SessionState state("user-123", "device-456", domain::SessionStatus::Active);
    EXPECT_EQ(state.userId(), "user-123");
    EXPECT_EQ(state.deviceId(), "device-456");
    EXPECT_EQ(state.status(), domain::SessionStatus::Active);
    EXPECT_TRUE(state.isAuthenticated());

    state.setStatus(domain::SessionStatus::Locked);
    EXPECT_EQ(state.status(), domain::SessionStatus::Locked);
    EXPECT_FALSE(state.isAuthenticated());

    state.reset();
    EXPECT_TRUE(state.userId().empty());
    EXPECT_TRUE(state.deviceId().empty());
    EXPECT_EQ(state.status(), domain::SessionStatus::LoggedOut);
    EXPECT_FALSE(state.isAuthenticated());
}

TEST(ClientDomainTest, SessionStatusToString) {
    EXPECT_EQ(domain::to_string(domain::SessionStatus::LoggedOut), "LoggedOut");
    EXPECT_EQ(domain::to_string(domain::SessionStatus::Authenticating), "Authenticating");
    EXPECT_EQ(domain::to_string(domain::SessionStatus::Active), "Active");
    EXPECT_EQ(domain::to_string(domain::SessionStatus::Locked), "Locked");
    EXPECT_EQ(domain::to_string(domain::SessionStatus::Expired), "Expired");
}

TEST(ClientInfrastructureTest, GatewayAdapterStubProbing) {
    infrastructure::GatewayAdapterStub defaultStub;
    EXPECT_EQ(defaultStub.endpoint(), "https://127.0.0.1:8443");
    EXPECT_FALSE(defaultStub.isConnected());

    EXPECT_TRUE(defaultStub.probeGateway("/health"));
    EXPECT_TRUE(defaultStub.isConnected());

    infrastructure::GatewayAdapterStub customStub("https://gateway.internal:9443");
    EXPECT_EQ(customStub.endpoint(), "https://gateway.internal:9443");
    EXPECT_FALSE(customStub.isConnected());
}

TEST(ClientApplicationTest, ClientAppServiceInitializationAndSessionFlow) {
    application::ClientAppService service;
    EXPECT_FALSE(service.sessionState().isAuthenticated());
    EXPECT_FALSE(service.gateway().isConnected());

    EXPECT_TRUE(service.initialize());
    EXPECT_TRUE(service.gateway().isConnected());

    service.updateSession("alice@example.com", "laptop-001");
    EXPECT_TRUE(service.sessionState().isAuthenticated());
    EXPECT_EQ(service.sessionState().userId(), "alice@example.com");
    EXPECT_EQ(service.sessionState().deviceId(), "laptop-001");

    service.logout();
    EXPECT_FALSE(service.sessionState().isAuthenticated());
    EXPECT_TRUE(service.sessionState().userId().empty());
}

TEST(ClientUiTest, UiControllerSignalAndPropertyBindings) {
    application::ClientAppService appService;
    ASSERT_TRUE(appService.initialize());

    ui::UiController controller(appService);
    EXPECT_EQ(controller.statusText(), QStringLiteral("Ready"));
    EXPECT_FALSE(controller.isAuthenticated());

    QSignalSpy statusSpy(&controller, &ui::UiController::statusTextChanged);
    QSignalSpy sessionSpy(&controller, &ui::UiController::sessionChanged);

    controller.requestLogin(QStringLiteral("bob@securecloud.org"));
    EXPECT_EQ(statusSpy.count(), 1);
    EXPECT_EQ(sessionSpy.count(), 1);
    EXPECT_TRUE(controller.isAuthenticated());
    EXPECT_EQ(controller.statusText(), QStringLiteral("User authenticated"));

    controller.requestLogout();
    EXPECT_EQ(statusSpy.count(), 2);
    EXPECT_EQ(sessionSpy.count(), 2);
    EXPECT_FALSE(controller.isAuthenticated());
    EXPECT_EQ(controller.statusText(), QStringLiteral("User logged out"));
}

} // namespace
