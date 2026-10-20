#include "delivery/device_connection_registry.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "domain/delivery_types.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::messaging::delivery {
namespace {

using namespace std::chrono_literals;

class DeviceConnectionRegistryTest : public ::testing::Test {
  protected:
    domain::DeviceId dev1_{"dev-001"};
    domain::DeviceId dev2_{"dev-002"};
    domain::DeviceId dev3_{"dev-003"};
    domain::UserId user1_{"usr-001"};
    domain::UserId user2_{"usr-002"};

    domain::DeliveryTask make_dummy_task(domain::DeviceId dev, domain::UserId usr) {
        domain::DeliveryTask task;
        task.message_id = domain::MessageId::generate_v7();
        task.conversation_id = domain::ConversationId::generate_v7();
        task.recipient_device_id = std::move(dev);
        task.recipient_user_id = std::move(usr);
        task.accepted_at = std::chrono::system_clock::now();
        task.scheduled_at = task.accepted_at;
        return task;
    }
};

TEST_F(DeviceConnectionRegistryTest, RegisterAndLookupLifecycle) {
    DeviceConnectionRegistry registry(60s);

    EXPECT_EQ(registry.connected_device_count(), 0u);
    EXPECT_FALSE(registry.is_online(dev1_));
    EXPECT_EQ(registry.get_channel(dev1_), nullptr);

    auto channel = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    registry.register_channel(channel);

    EXPECT_EQ(registry.connected_device_count(), 1u);
    EXPECT_TRUE(registry.is_online(dev1_));
    ASSERT_NE(registry.get_channel(dev1_), nullptr);
    EXPECT_EQ(registry.get_channel(dev1_)->device_id(), dev1_);
    EXPECT_EQ(registry.get_channel(dev1_)->user_id(), user1_);

    // Unknown device remains offline
    EXPECT_FALSE(registry.is_online(dev2_));
    EXPECT_EQ(registry.get_channel(dev2_), nullptr);
}

TEST_F(DeviceConnectionRegistryTest, IgnoresNullChannelRegistration) {
    DeviceConnectionRegistry registry(60s);
    registry.register_channel(nullptr);
    EXPECT_EQ(registry.connected_device_count(), 0u);
}

TEST_F(DeviceConnectionRegistryTest, UnregisterLifecycle) {
    DeviceConnectionRegistry registry(60s);
    auto channel = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    registry.register_channel(channel);

    EXPECT_TRUE(registry.is_online(dev1_));
    registry.unregister_channel(dev1_);

    EXPECT_FALSE(registry.is_online(dev1_));
    EXPECT_EQ(registry.get_channel(dev1_), nullptr);
    EXPECT_EQ(registry.connected_device_count(), 0u);

    // Idempotent unregister
    EXPECT_NO_THROW(registry.unregister_channel(dev1_));
}

TEST_F(DeviceConnectionRegistryTest, BatchOnlineFilter) {
    DeviceConnectionRegistry registry(60s);

    auto ch1 = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    auto ch3 = std::make_shared<MockDeviceDeliveryChannel>(dev3_, user1_);

    registry.register_channel(ch1);
    registry.register_channel(ch3);

    std::vector<domain::DeviceId> query{dev1_, dev2_, dev3_, domain::DeviceId{"dev-999"}};
    auto online = registry.filter_online_devices(query);

    ASSERT_EQ(online.size(), 2u);
    EXPECT_EQ(online[0], dev1_);
    EXPECT_EQ(online[1], dev3_);

    // Empty input returns empty
    EXPECT_TRUE(registry.filter_online_devices({}).empty());
}

TEST_F(DeviceConnectionRegistryTest, DeviceReconnectReplacesPreviousChannel) {
    DeviceConnectionRegistry registry(60s);

    auto ch1 = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    auto ch2 = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);

    registry.register_channel(ch1);
    EXPECT_EQ(registry.get_channel(dev1_), ch1);

    // Reconnect replaces previous channel atomically
    registry.register_channel(ch2);
    EXPECT_EQ(registry.connected_device_count(), 1u);
    EXPECT_EQ(registry.get_channel(dev1_), ch2);
}

TEST_F(DeviceConnectionRegistryTest, InactiveChannelTreatedAsOffline) {
    DeviceConnectionRegistry registry(60s);
    auto ch = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    registry.register_channel(ch);

    EXPECT_TRUE(registry.is_online(dev1_));

    // Underlying channel drops connection
    ch->set_active(false);

    EXPECT_FALSE(registry.is_online(dev1_));
    EXPECT_EQ(registry.get_channel(dev1_), nullptr);

    // Filter also excludes inactive channels
    auto online = registry.filter_online_devices({dev1_});
    EXPECT_TRUE(online.empty());
}

TEST_F(DeviceConnectionRegistryTest, HeartbeatAndStaleEviction) {
    // Registry with 60ms lease timeout
    DeviceConnectionRegistry registry(60ms);

    auto ch1 = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    auto ch2 = std::make_shared<MockDeviceDeliveryChannel>(dev2_, user2_);

    registry.register_channel(ch1);
    registry.register_channel(ch2);
    EXPECT_EQ(registry.connected_device_count(), 2u);

    // Sleep 30ms, then touch dev1_
    std::this_thread::sleep_for(30ms);
    EXPECT_TRUE(registry.touch_channel(dev1_));
    EXPECT_FALSE(registry.touch_channel(domain::DeviceId{"non-existent"}));

    // Sleep another 40ms: dev2_ has been idle for 70ms (> 60ms), dev1_ was touched 40ms ago (< 60ms)
    std::this_thread::sleep_for(40ms);

    size_t evicted = registry.evict_stale_channels(60ms);
    EXPECT_EQ(evicted, 1u);
    EXPECT_EQ(registry.connected_device_count(), 1u);
    EXPECT_TRUE(registry.is_online(dev1_));
    EXPECT_FALSE(registry.is_online(dev2_));
}

TEST_F(DeviceConnectionRegistryTest, DisconnectCallbackNotification) {
    DeviceConnectionRegistry registry(50ms);

    std::vector<domain::DeviceId> disconnected;
    std::mutex notify_mutex;

    registry.register_disconnect_callback([&](const domain::DeviceId& dev) {
        std::lock_guard<std::mutex> lock(notify_mutex);
        disconnected.push_back(dev);
    });

    auto ch1 = std::make_shared<MockDeviceDeliveryChannel>(dev1_, user1_);
    auto ch2 = std::make_shared<MockDeviceDeliveryChannel>(dev2_, user2_);
    registry.register_channel(ch1);
    registry.register_channel(ch2);

    // Explicit unregister triggers callback
    registry.unregister_channel(dev1_);

    {
        std::lock_guard<std::mutex> lock(notify_mutex);
        ASSERT_EQ(disconnected.size(), 1u);
        EXPECT_EQ(disconnected[0], dev1_);
    }

    // Eviction triggers callback
    std::this_thread::sleep_for(60ms);
    registry.evict_stale_channels(50ms);

    {
        std::lock_guard<std::mutex> lock(notify_mutex);
        ASSERT_EQ(disconnected.size(), 2u);
        EXPECT_EQ(disconnected[1], dev2_);
    }
}

TEST_F(DeviceConnectionRegistryTest, ConcurrentReadWriteStress) {
    DeviceConnectionRegistry registry(10s);
    constexpr int kDevices = 50;
    std::vector<domain::DeviceId> device_pool;
    for (int i = 0; i < kDevices; ++i) {
        device_pool.emplace_back("dev-" + std::to_string(i));
    }

    std::atomic<bool> running{true};
    std::vector<std::thread> workers;

    // 4 Writer threads
    for (int w = 0; w < 4; ++w) {
        workers.emplace_back([&, w]() {
            int counter = 0;
            while (running.load(std::memory_order_relaxed)) {
                const auto& dev = device_pool[static_cast<size_t>((w * 10 + counter) % kDevices)];
                auto ch = std::make_shared<MockDeviceDeliveryChannel>(dev, user1_);
                registry.register_channel(ch);
                registry.touch_channel(dev);
                if (counter % 3 == 0) {
                    registry.unregister_channel(dev);
                }
                ++counter;
            }
        });
    }

    // 8 Reader threads
    for (int r = 0; r < 8; ++r) {
        workers.emplace_back([&, r]() {
            while (running.load(std::memory_order_relaxed)) {
                const auto& dev = device_pool[static_cast<size_t>(r % kDevices)];
                (void)registry.is_online(dev);
                (void)registry.get_channel(dev);
                const auto next_idx = static_cast<size_t>((r + 1) % kDevices);
                (void)registry.filter_online_devices({dev, device_pool[next_idx]});
                (void)registry.connected_device_count();
            }
        });
    }

    // Run for 150 milliseconds under high concurrent load
    std::this_thread::sleep_for(150ms);
    running.store(false, std::memory_order_relaxed);

    for (auto& th : workers) {
        th.join();
    }

    // Must be completely stable with zero deadlock/crash
    EXPECT_GE(registry.connected_device_count(), 0u);
}

TEST_F(DeviceConnectionRegistryTest, MockChannelDispatchAndInspection) {
    MockDeviceDeliveryChannel channel(dev1_, user1_);

    EXPECT_EQ(channel.device_id(), dev1_);
    EXPECT_EQ(channel.user_id(), user1_);
    EXPECT_TRUE(channel.is_active());
    EXPECT_EQ(channel.sent_task_count(), 0u);

    auto task = make_dummy_task(dev1_, user1_);
    const auto expected_msg_id = task.message_id;

    // 1. Successful send
    channel.set_next_result(domain::DeliveryAttemptResult::Success);
    auto res1 = channel.send_envelope(task, 1000ms);
    EXPECT_EQ(res1, domain::DeliveryAttemptResult::Success);
    EXPECT_EQ(channel.sent_task_count(), 1u);
    EXPECT_EQ(channel.sent_tasks()[0].message_id, expected_msg_id);

    // 2. Simulated inactive channel
    channel.set_active(false);
    auto res2 = channel.send_envelope(task, 1000ms);
    EXPECT_EQ(res2, domain::DeliveryAttemptResult::RecipientOffline);

    // 3. Simulated latency timeout
    channel.set_active(true);
    channel.set_simulated_latency(100ms);
    auto res3 = channel.send_envelope(task, 10ms); // timeout < simulated latency
    EXPECT_EQ(res3, domain::DeliveryAttemptResult::TransientFailure);

    // 4. Custom handler override
    channel.set_simulated_latency(0ms);
    channel.set_custom_handler([](const domain::DeliveryTask& t) {
        if (t.priority == domain::MessagePriority::Emergency) {
            return domain::DeliveryAttemptResult::Success;
        }
        return domain::DeliveryAttemptResult::TerminalFailure;
    });

    task.priority = domain::MessagePriority::Normal;
    EXPECT_EQ(channel.send_envelope(task, 500ms), domain::DeliveryAttemptResult::TerminalFailure);

    task.priority = domain::MessagePriority::Emergency;
    EXPECT_EQ(channel.send_envelope(task, 500ms), domain::DeliveryAttemptResult::Success);
}

} // namespace
} // namespace securecloud::messaging::delivery
