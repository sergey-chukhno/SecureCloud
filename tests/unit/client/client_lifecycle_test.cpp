#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"

#include <gtest/gtest.h>
#include <memory>

namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::infrastructure::adapters;

TEST(ClientBootstrapTest, DefaultWiringAndManagerRetrieval) {
    const auto config = ClientConfig::create_default();
    ClientBootstrap bootstrap(config);

    EXPECT_EQ(bootstrap.config().gateway_port, 8443);

    // Verify all managers are instantiated and accessible
    EXPECT_NO_THROW({
        (void)bootstrap.auth_manager();
        (void)bootstrap.messaging_manager();
        (void)bootstrap.contact_manager();
        (void)bootstrap.device_manager();
        (void)bootstrap.file_manager();
        (void)bootstrap.emergency_manager();
        (void)bootstrap.sync_manager();
    });

    EXPECT_FALSE(bootstrap.auth_manager().is_authenticated());
    EXPECT_FALSE(bootstrap.emergency_manager().is_wiped());
    EXPECT_FALSE(bootstrap.sync_manager().is_syncing());
}

TEST(ClientBootstrapTest, CustomAdapterInjection) {
    const auto config = ClientConfig::create_default();
    auto gateway = std::make_unique<DefaultGatewayClient>(config);
    auto store = std::make_unique<MemoryLocalStore>();
    auto secure_storage = std::make_unique<MemorySecureStorage>();
    auto crypto = std::make_unique<StubCryptoProvider>();

    auto bootstrap = ClientBootstrap::create_with_adapters(config, std::move(gateway), std::move(store),
                                                           std::move(secure_storage), std::move(crypto));

    ASSERT_NE(bootstrap, nullptr);

    // Test authentication through the wired managers
    const auto auth_res = bootstrap->auth_manager().authenticate("alice", "password123");
    EXPECT_TRUE(auth_res.is_ok());
    EXPECT_TRUE(bootstrap->auth_manager().is_authenticated());

    const auto token_res = bootstrap->auth_manager().session_token();
    ASSERT_TRUE(token_res.is_ok());
    EXPECT_FALSE(token_res.value().empty());

    // Test logout
    const auto logout_res = bootstrap->auth_manager().logout();
    EXPECT_TRUE(logout_res.is_ok());
    EXPECT_FALSE(bootstrap->auth_manager().is_authenticated());
}

TEST(ClientApplicationLifecycleTest, FullLifecycleTransitions) {
    const auto config = ClientConfig::create_default();
    ClientApplication app(config);

    EXPECT_EQ(app.state(), ApplicationLifecycleState::Uninitialized);
    EXPECT_FALSE(app.is_running());
    EXPECT_EQ(to_string(ApplicationLifecycleState::Uninitialized), "Uninitialized");

    // 1. Initialize
    const auto init_res = app.initialize();
    ASSERT_TRUE(init_res.is_ok());
    EXPECT_EQ(app.state(), ApplicationLifecycleState::Initializing);
    EXPECT_EQ(to_string(ApplicationLifecycleState::Initializing), "Initializing");

    // Initializing twice should fail
    const auto second_init = app.initialize();
    EXPECT_TRUE(second_init.is_error());

    // 2. Start
    const auto start_res = app.start();
    ASSERT_TRUE(start_res.is_ok());
    EXPECT_EQ(app.state(), ApplicationLifecycleState::Running);
    EXPECT_TRUE(app.is_running());
    EXPECT_TRUE(app.bootstrap().sync_manager().is_syncing());
    EXPECT_EQ(to_string(ApplicationLifecycleState::Running), "Running");

    // 3. Shutdown
    const auto shutdown_res = app.shutdown(std::chrono::milliseconds(500));
    EXPECT_TRUE(shutdown_res.is_ok());
    EXPECT_EQ(app.state(), ApplicationLifecycleState::Terminated);
    EXPECT_FALSE(app.is_running());
    EXPECT_FALSE(app.bootstrap().sync_manager().is_syncing());
    EXPECT_EQ(to_string(ApplicationLifecycleState::Terminated), "Terminated");
    EXPECT_EQ(to_string(ApplicationLifecycleState::ShuttingDown), "ShuttingDown");

    // Shutdown should be idempotent
    const auto second_shutdown = app.shutdown();
    EXPECT_TRUE(second_shutdown.is_ok());
    EXPECT_EQ(app.state(), ApplicationLifecycleState::Terminated);
}

TEST(ClientApplicationLifecycleTest, InvalidConfigurationFailsInitialize) {
    auto config = ClientConfig::create_default();
    config.gateway_port = 0; // Invalid port

    ClientApplication app(config);
    const auto init_res = app.initialize();
    EXPECT_TRUE(init_res.is_error());
    EXPECT_EQ(app.state(), ApplicationLifecycleState::Terminated);
}

TEST(ClientApplicationLifecycleTest, StartFromUninitializedAutoInitializes) {
    const auto config = ClientConfig::create_default();
    ClientApplication app(config);

    // Calling start directly from uninitialized should trigger initialize first
    const auto start_res = app.start();
    ASSERT_TRUE(start_res.is_ok());
    EXPECT_TRUE(app.is_running());
    EXPECT_EQ(app.state(), ApplicationLifecycleState::Running);

    (void)app.shutdown();
}

TEST(ClientEmergencyManagerTest, EmergencyWipeExecution) {
    const auto config = ClientConfig::create_default();
    ClientBootstrap bootstrap(config);

    const auto auth_res = bootstrap.auth_manager().authenticate("bob", "secret");
    ASSERT_TRUE(auth_res.is_ok());
    EXPECT_TRUE(bootstrap.auth_manager().is_authenticated());

    const auto token_before = bootstrap.secure_storage().has_secret("session_auth_token");
    ASSERT_TRUE(token_before.is_ok());
    EXPECT_TRUE(token_before.value());

    // Trigger emergency wipe
    const auto wipe_res = bootstrap.emergency_manager().trigger_emergency_wipe();
    EXPECT_TRUE(wipe_res.is_ok());
    EXPECT_TRUE(bootstrap.emergency_manager().is_wiped());

    const auto token_after = bootstrap.secure_storage().has_secret("session_auth_token");
    ASSERT_TRUE(token_after.is_ok());
    EXPECT_FALSE(token_after.value());
}

TEST(ClientSyncManagerTest, SyncLifecycleAndPolling) {
    const auto config = ClientConfig::create_default();
    ClientBootstrap bootstrap(config);

    EXPECT_FALSE(bootstrap.sync_manager().is_syncing());
    EXPECT_EQ(bootstrap.sync_manager().config().gateway_port, 8443);

    const auto start_sync = bootstrap.sync_manager().start_sync();
    EXPECT_TRUE(start_sync.is_ok());
    EXPECT_TRUE(bootstrap.sync_manager().is_syncing());

    const auto poll_res = bootstrap.sync_manager().poll_sync();
    ASSERT_TRUE(poll_res.is_ok());
    EXPECT_EQ(poll_res.value(), 0u);

    const auto stop_sync = bootstrap.sync_manager().stop_sync();
    EXPECT_TRUE(stop_sync.is_ok());
    EXPECT_FALSE(bootstrap.sync_manager().is_syncing());
}

} // namespace
