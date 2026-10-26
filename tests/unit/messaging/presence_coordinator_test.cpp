#include "service/presence_coordinator.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

namespace securecloud::messaging::service::test {

using namespace domain;

class PresenceCoordinatorTest : public ::testing::Test {
  protected:
    const UserId user_alice = *UserId::from_string("018f4a7c-6e21-789a-bcde-0123456789a1");
    const UserId user_bob = *UserId::from_string("018f4a7c-6e21-789a-bcde-0123456789b2");
    const UserId user_carol = *UserId::from_string("018f4a7c-6e21-789a-bcde-0123456789c3");

    const DeviceId dev_alice_phone{"dev-alice-phone-001"};
    const DeviceId dev_alice_laptop{"dev-alice-laptop-002"};
    const DeviceId dev_alice_tablet{"dev-alice-tablet-003"};
    const DeviceId dev_bob_phone{"dev-bob-phone-001"};
};

// ============================================================================
// 1. Single-Device Connection Lifecycle Tests
// ============================================================================

TEST_F(PresenceCoordinatorTest, UnobservedUserReturnsUnspecified) {
    PresenceCoordinator coordinator(std::chrono::seconds(60));

    auto presence = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(presence.user_id, user_alice);
    EXPECT_EQ(presence.status, PresenceStatus::Unspecified);
    EXPECT_FALSE(presence.is_online());
    EXPECT_EQ(presence.active_device_count, 0u);
}

TEST_F(PresenceCoordinatorTest, SingleDeviceConnectAndDisconnect) {
    PresenceCoordinator coordinator(std::chrono::seconds(60));

    coordinator.on_device_connected(user_alice, dev_alice_phone);

    auto online_presence = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(online_presence.status, PresenceStatus::Online);
    EXPECT_TRUE(online_presence.is_online());
    EXPECT_EQ(online_presence.active_device_count, 1u);

    coordinator.on_device_disconnected(user_alice, dev_alice_phone);

    auto offline_presence = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(offline_presence.status, PresenceStatus::Offline);
    EXPECT_FALSE(offline_presence.is_online());
    EXPECT_EQ(offline_presence.active_device_count, 0u);
    EXPECT_GT(offline_presence.last_active_at.time_since_epoch().count(), 0);
}

// ============================================================================
// 2. Multi-Device Aggregation Tests
// ============================================================================

TEST_F(PresenceCoordinatorTest, MultiDeviceAggregationIndependentTransitions) {
    PresenceCoordinator coordinator(std::chrono::seconds(60));

    // Connect 3 devices for Alice
    coordinator.on_device_connected(user_alice, dev_alice_phone);
    coordinator.on_device_connected(user_alice, dev_alice_laptop);
    coordinator.on_device_connected(user_alice, dev_alice_tablet);

    auto p3 = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(p3.status, PresenceStatus::Online);
    EXPECT_EQ(p3.active_device_count, 3u);

    // Disconnect phone -> remaining 2 devices keep user Online
    coordinator.on_device_disconnected(user_alice, dev_alice_phone);
    auto p2 = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(p2.status, PresenceStatus::Online);
    EXPECT_EQ(p2.active_device_count, 2u);

    // Disconnect laptop -> remaining 1 device keeps user Online
    coordinator.on_device_disconnected(user_alice, dev_alice_laptop);
    auto p1 = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(p1.status, PresenceStatus::Online);
    EXPECT_EQ(p1.active_device_count, 1u);

    // Disconnect tablet -> last device disconnected -> transitions to Offline
    coordinator.on_device_disconnected(user_alice, dev_alice_tablet);
    auto p0 = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(p0.status, PresenceStatus::Offline);
    EXPECT_EQ(p0.active_device_count, 0u);
}

// ============================================================================
// 3. User Explicit Status Override Tests
// ============================================================================

TEST_F(PresenceCoordinatorTest, UserStatusOverrideWhileConnected) {
    PresenceCoordinator coordinator(std::chrono::seconds(60));

    coordinator.on_device_connected(user_alice, dev_alice_phone);

    // Override to Busy with note
    coordinator.set_user_override(user_alice, PresenceStatus::Busy, "Operating room triage");
    auto p_busy = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(p_busy.status, PresenceStatus::Busy);
    EXPECT_TRUE(p_busy.is_online());
    EXPECT_EQ(p_busy.custom_status_message, "Operating room triage");
    EXPECT_EQ(p_busy.active_device_count, 1u);

    // Override to Away with note
    coordinator.set_user_override(user_alice, PresenceStatus::Away, "In field transit");
    auto p_away = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(p_away.status, PresenceStatus::Away);
    EXPECT_TRUE(p_away.is_online());
    EXPECT_EQ(p_away.custom_status_message, "In field transit");

    // Clear override -> reverts to natural Online status
    coordinator.clear_user_override(user_alice);
    auto p_reverted = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(p_reverted.status, PresenceStatus::Online);
    EXPECT_TRUE(p_reverted.is_online());
    EXPECT_TRUE(p_reverted.custom_status_message.empty());
}

TEST_F(PresenceCoordinatorTest, StatusOverrideDecaysWhenAllDevicesDisconnect) {
    PresenceCoordinator coordinator(std::chrono::seconds(60));

    coordinator.on_device_connected(user_alice, dev_alice_phone);
    coordinator.set_user_override(user_alice, PresenceStatus::Busy, "Do not disturb");

    coordinator.on_device_disconnected(user_alice, dev_alice_phone);

    // With zero active devices, user must be Offline regardless of previous override
    auto p_offline = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(p_offline.status, PresenceStatus::Offline);
    EXPECT_FALSE(p_offline.is_online());
}

// ============================================================================
// 4. Lease Timeout & Heartbeat Tests
// ============================================================================

TEST_F(PresenceCoordinatorTest, LeaseTimeoutDecaysInactiveDeviceToOffline) {
    // 50ms lease timeout
    PresenceCoordinator coordinator(std::chrono::milliseconds(50));

    coordinator.on_device_connected(user_alice, dev_alice_phone);
    EXPECT_EQ(coordinator.get_user_presence(user_alice).status, PresenceStatus::Online);

    // Sleep past the lease timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(70));

    auto decayed = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(decayed.status, PresenceStatus::Offline);
    EXPECT_EQ(decayed.active_device_count, 0u);
}

TEST_F(PresenceCoordinatorTest, HeartbeatRefreshesLeaseWindow) {
    // 300ms lease timeout
    PresenceCoordinator coordinator(std::chrono::milliseconds(300));

    coordinator.on_device_connected(user_alice, dev_alice_phone);

    // Sleep 150ms (within lease window)
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Send heartbeat (refreshes lease for another 300ms)
    coordinator.on_device_heartbeat(user_alice, dev_alice_phone);

    // Sleep another 200ms (total 350ms since connect > 300ms initial lease, but only 200ms since heartbeat < 300ms)
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Still online because heartbeat refreshed the lease
    auto presence = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(presence.status, PresenceStatus::Online);
    EXPECT_EQ(presence.active_device_count, 1u);
}

// ============================================================================
// 5. Batch Query & Inspection Helper Tests
// ============================================================================

TEST_F(PresenceCoordinatorTest, BatchGetPresenceEvaluation) {
    PresenceCoordinator coordinator(std::chrono::seconds(60));

    coordinator.on_device_connected(user_alice, dev_alice_phone);
    coordinator.on_device_connected(user_bob, dev_bob_phone);
    coordinator.set_user_override(user_bob, PresenceStatus::Busy, "In meeting");

    const std::vector<UserId> query_users = {user_alice, user_bob, user_carol};
    const auto batch = coordinator.batch_get_presence(query_users);

    ASSERT_EQ(batch.size(), 3u);

    EXPECT_EQ(batch[0].user_id, user_alice);
    EXPECT_EQ(batch[0].status, PresenceStatus::Online);

    EXPECT_EQ(batch[1].user_id, user_bob);
    EXPECT_EQ(batch[1].status, PresenceStatus::Busy);
    EXPECT_EQ(batch[1].custom_status_message, "In meeting");

    EXPECT_EQ(batch[2].user_id, user_carol);
    EXPECT_EQ(batch[2].status, PresenceStatus::Unspecified);
}

TEST_F(PresenceCoordinatorTest, OperationalInspectionCounts) {
    PresenceCoordinator coordinator(std::chrono::seconds(60));

    EXPECT_EQ(coordinator.tracked_devices_count(), 0u);
    EXPECT_EQ(coordinator.online_users_count(), 0u);

    coordinator.on_device_connected(user_alice, dev_alice_phone);
    coordinator.on_device_connected(user_alice, dev_alice_laptop);
    coordinator.on_device_connected(user_bob, dev_bob_phone);

    EXPECT_EQ(coordinator.tracked_devices_count(), 3u);
    EXPECT_EQ(coordinator.online_users_count(), 2u);

    coordinator.on_device_disconnected(user_alice, dev_alice_phone);
    coordinator.on_device_disconnected(user_alice, dev_alice_laptop);

    EXPECT_EQ(coordinator.tracked_devices_count(), 1u);
    EXPECT_EQ(coordinator.online_users_count(), 1u);
}

// ============================================================================
// 6. Concurrency & High-Throughput Thread-Safety Stress Test
// ============================================================================

TEST_F(PresenceCoordinatorTest, ConcurrentReadWriteStressTest) {
    PresenceCoordinator coordinator(std::chrono::seconds(60));
    std::atomic<bool> stop_flag{false};

    // Pre-populate some users
    coordinator.on_device_connected(user_alice, dev_alice_phone);
    coordinator.on_device_connected(user_bob, dev_bob_phone);

    // 8 reader threads
    std::vector<std::thread> readers;
    readers.reserve(8);
    for (size_t i = 0; i < 8; ++i) {
        readers.emplace_back([&]() {
            while (!stop_flag.load(std::memory_order_relaxed)) {
                auto p_a = coordinator.get_user_presence(user_alice);
                auto p_b = coordinator.get_user_presence(user_bob);
                auto p_c = coordinator.get_user_presence(user_carol);
                (void)p_a;
                (void)p_b;
                (void)p_c;
                auto batch = coordinator.batch_get_presence({user_alice, user_bob, user_carol});
                (void)batch;
            }
        });
    }

    // 4 writer threads performing mutations
    std::vector<std::thread> writers;
    writers.reserve(4);
    for (size_t i = 0; i < 4; ++i) {
        writers.emplace_back([&, i]() {
            DeviceId dev{"dev-stress-" + std::to_string(i)};
            while (!stop_flag.load(std::memory_order_relaxed)) {
                coordinator.on_device_connected(user_carol, dev);
                coordinator.on_device_heartbeat(user_carol, dev);
                coordinator.set_user_override(user_carol, PresenceStatus::Busy, "Stress testing");
                coordinator.clear_user_override(user_carol);
                coordinator.on_device_disconnected(user_carol, dev);
            }
        });
    }

    // Let the threads hammer the coordinator for 150ms
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    stop_flag.store(true, std::memory_order_relaxed);

    for (auto& r : readers) {
        r.join();
    }
    for (auto& w : writers) {
        w.join();
    }

    // After stress test completes, coordinator remains fully operational
    auto final_p = coordinator.get_user_presence(user_alice);
    EXPECT_EQ(final_p.status, PresenceStatus::Online);
}

} // namespace securecloud::messaging::service::test
