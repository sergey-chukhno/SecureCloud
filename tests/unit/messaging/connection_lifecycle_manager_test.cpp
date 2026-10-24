#include "delivery/connection_lifecycle_manager.hpp"
#include "delivery/device_connection_registry.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "service/presence_coordinator.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <vector>

namespace securecloud::messaging::delivery {
namespace {

using namespace std::chrono_literals;

class ConnectionLifecycleManagerTest : public ::testing::Test {
  protected:
    domain::DeviceId dev1_{"dev-001"};
    domain::DeviceId dev2_{"dev-002"};
    domain::DeviceId dev3_{"dev-003"};
    domain::UserId user1_{"usr-001"};
    domain::UserId user2_{"usr-002"};

    std::shared_ptr<DeviceConnectionRegistry> registry_;
    std::shared_ptr<service::PresenceCoordinator> presence_;
    std::unique_ptr<ConnectionLifecycleManager> lifecycle_;

    void SetUp() override {
        registry_ = std::make_shared<DeviceConnectionRegistry>(std::chrono::milliseconds(200));
        presence_ = std::make_shared<service::PresenceCoordinator>(std::chrono::milliseconds(200));
        lifecycle_ = std::make_unique<ConnectionLifecycleManager>(registry_, presence_, std::chrono::milliseconds(50),
                                                                  std::chrono::milliseconds(200));
    }

    void TearDown() override {
        if (lifecycle_ && lifecycle_->is_running()) {
            lifecycle_->stop();
        }
    }
};

TEST_F(ConnectionLifecycleManagerTest, EstablishConnectionPopulatesSessionAndPresence) {
    auto ch1 = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    auto session = lifecycle_->establish_connection(ch1, "192.168.1.100", "SecureCloud-iOS/1.0", 2);

    EXPECT_FALSE(session.connection_id.empty());
    EXPECT_EQ(session.device_id, dev1_);
    EXPECT_EQ(session.user_id, user1_);
    EXPECT_EQ(session.client_ip, "192.168.1.100");
    EXPECT_EQ(session.user_agent, "SecureCloud-iOS/1.0");
    EXPECT_EQ(session.protocol_version, 2u);
    EXPECT_EQ(session.state, domain::ConnectionState::Active);

    EXPECT_EQ(lifecycle_->active_session_count(), 1u);
    EXPECT_TRUE(registry_->is_online(dev1_));

    // Verify PresenceCoordinator reflected the connection
    auto pres = presence_->get_user_presence(user1_);
    EXPECT_EQ(pres.status, domain::PresenceStatus::Online);
    EXPECT_EQ(pres.active_device_count, 1u);
}

TEST_F(ConnectionLifecycleManagerTest, RejectEstablishWithNullChannel) {
    EXPECT_THROW(lifecycle_->establish_connection(nullptr), std::invalid_argument);
}

TEST_F(ConnectionLifecycleManagerTest, TerminateConnectionEvictsSessionAndUpdatesPresence) {
    auto ch1 = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    lifecycle_->establish_connection(ch1);

    EXPECT_EQ(lifecycle_->active_session_count(), 1u);
    EXPECT_TRUE(registry_->is_online(dev1_));

    lifecycle_->terminate_connection(dev1_);

    EXPECT_EQ(lifecycle_->active_session_count(), 0u);
    EXPECT_FALSE(registry_->is_online(dev1_));

    auto pres = presence_->get_user_presence(user1_);
    EXPECT_EQ(pres.status, domain::PresenceStatus::Offline);
    EXPECT_EQ(pres.active_device_count, 0u);
}

TEST_F(ConnectionLifecycleManagerTest, AtomicSupersedingMaintainsPresenceAndUpdatesSession) {
    auto ch1_old = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    auto session_old = lifecycle_->establish_connection(ch1_old, "10.0.0.1", "App/1.0", 1);

    // Second connection for dev1_ arrives
    auto ch1_new = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    auto session_new = lifecycle_->establish_connection(ch1_new, "10.0.0.2", "App/1.1", 2);

    EXPECT_NE(session_old.connection_id, session_new.connection_id);
    EXPECT_EQ(session_new.client_ip, "10.0.0.2");
    EXPECT_EQ(session_new.protocol_version, 2u);

    // Still only 1 active session and 1 active device for user1_
    EXPECT_EQ(lifecycle_->active_session_count(), 1u);
    EXPECT_EQ(registry_->connected_device_count(), 1u);
    EXPECT_EQ(registry_->user_device_count(user1_), 1u);

    auto pres = presence_->get_user_presence(user1_);
    EXPECT_EQ(pres.status, domain::PresenceStatus::Online);
    EXPECT_EQ(pres.active_device_count, 1u);
}

TEST_F(ConnectionLifecycleManagerTest, HeartbeatTouchesRegistryAndRefreshesSessionTimestamp) {
    auto ch1 = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    lifecycle_->establish_connection(ch1);

    auto session_before = lifecycle_->get_session(dev1_);
    ASSERT_TRUE(session_before.has_value());

    std::this_thread::sleep_for(10ms);

    EXPECT_TRUE(lifecycle_->record_heartbeat(dev1_));

    auto session_after = lifecycle_->get_session(dev1_);
    ASSERT_TRUE(session_after.has_value());
    EXPECT_GT(session_after->last_heartbeat_at, session_before->last_heartbeat_at);

    // Heartbeat on unregistered device returns false
    EXPECT_FALSE(lifecycle_->record_heartbeat(dev2_));
}

TEST_F(ConnectionLifecycleManagerTest, BackgroundReaperEvictsStaleConnection) {
    auto ch1 = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    lifecycle_->establish_connection(ch1);
    EXPECT_EQ(lifecycle_->active_session_count(), 1u);

    // Start background reaper (runs every 50ms, lease is 200ms)
    lifecycle_->start();
    EXPECT_TRUE(lifecycle_->is_running());

    // Wait past lease timeout
    std::this_thread::sleep_for(300ms);

    // Reaper should have swept the connection
    EXPECT_EQ(lifecycle_->active_session_count(), 0u);
    EXPECT_FALSE(registry_->is_online(dev1_));

    auto pres = presence_->get_user_presence(user1_);
    EXPECT_EQ(pres.status, domain::PresenceStatus::Offline);
}

TEST_F(ConnectionLifecycleManagerTest, HeartbeatKeepsConnectionAliveDuringReaperCycles) {
    auto ch1 = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    lifecycle_->establish_connection(ch1);

    lifecycle_->start();

    // Send heartbeats every 80ms over 350ms (lease is 200ms)
    for (int i = 0; i < 4; ++i) {
        std::this_thread::sleep_for(80ms);
        EXPECT_TRUE(lifecycle_->record_heartbeat(dev1_));
    }

    // Connection must still be alive
    EXPECT_EQ(lifecycle_->active_session_count(), 1u);
    EXPECT_TRUE(registry_->is_online(dev1_));
    EXPECT_EQ(presence_->get_user_presence(user1_).status, domain::PresenceStatus::Online);
}

TEST_F(ConnectionLifecycleManagerTest, ManualSweepStaleConnections) {
    auto ch1 = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    lifecycle_->establish_connection(ch1);

    // Lease is 200ms, not expired yet
    EXPECT_EQ(lifecycle_->sweep_stale_connections(), 0u);
    EXPECT_EQ(lifecycle_->active_session_count(), 1u);

    std::this_thread::sleep_for(220ms);

    // Now expired
    EXPECT_EQ(lifecycle_->sweep_stale_connections(), 1u);
    EXPECT_EQ(lifecycle_->active_session_count(), 0u);
    EXPECT_FALSE(registry_->is_online(dev1_));
}

TEST_F(ConnectionLifecycleManagerTest, CleanStartAndStop) {
    lifecycle_->start();
    EXPECT_TRUE(lifecycle_->is_running());
    lifecycle_->stop();
    EXPECT_FALSE(lifecycle_->is_running());
}

} // namespace
} // namespace securecloud::messaging::delivery
