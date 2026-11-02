#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/connection_lifecycle_manager.hpp"
#include "delivery/device_connection_registry.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "domain/conversation_entity.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/message_entity.hpp"
#include "domain/sync_types.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/repository/sync_cursor_repository_interface.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/in_memory_sequence_allocator.hpp"
#include "service/message_sync_service.hpp"
#include "service/presence_coordinator.hpp"
#include "service/sync_commands.hpp"
#include "service/sync_cursor_manager.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::service {
namespace {

using delivery::BoundedDeliveryScheduler;
using delivery::ConnectionCapacityConfig;
using delivery::ConnectionLifecycleManager;
using delivery::DeliverySchedulerConfig;
using delivery::DeviceConnectionRegistry;
using delivery::MockDeviceDeliveryChannel;
using delivery::SchedulerStatus;
using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryTask;
using domain::DeviceId;
using domain::DeviceSyncCursor;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::MessagePriority;
using domain::ParticipantRole;
using domain::PresenceStatus;
using domain::UserId;

// ============================================================================
// Thread-Safe In-Memory Repositories for Sync & Reconnect Storm Testing
// ============================================================================

class StormMessageRepo final : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& vec = messages_[msg.conversation_id.to_string()][msg.message_bucket.value()];
        vec.push_back(msg);
        std::sort(vec.begin(), vec.end(), [](const MessageEntity& a, const MessageEntity& b) {
            return a.message_sequence < b.message_sequence;
        });
    }

    std::optional<MessageEntity> find_by_id(const ConversationId& conv, const MessageBucket& bucket,
                                            const MessageId& id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto c_it = messages_.find(conv.to_string());
        if (c_it == messages_.end()) {
            return std::nullopt;
        }
        auto b_it = c_it->second.find(bucket.value());
        if (b_it == c_it->second.end()) {
            return std::nullopt;
        }
        for (const auto& m : b_it->second) {
            if (m.message_id == id) {
                return m;
            }
        }
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId& conv, const MessageBucket& bucket,
                                                               uint64_t from, uint64_t to, size_t limit) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<MessageEntity> result;
        auto c_it = messages_.find(conv.to_string());
        if (c_it == messages_.end()) {
            return result;
        }
        auto b_it = c_it->second.find(bucket.value());
        if (b_it == c_it->second.end()) {
            return result;
        }
        for (const auto& m : b_it->second) {
            if (m.message_sequence >= from && m.message_sequence <= to) {
                result.push_back(m);
                if (result.size() >= limit) {
                    break;
                }
            }
        }
        return result;
    }

    uint64_t get_last_sequence(const ConversationId& conv, const MessageBucket& bucket) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto c_it = messages_.find(conv.to_string());
        if (c_it == messages_.end()) {
            return 0;
        }
        auto b_it = c_it->second.find(bucket.value());
        if (b_it == c_it->second.end() || b_it->second.empty()) {
            return 0;
        }
        return b_it->second.back().message_sequence;
    }

  private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::vector<MessageEntity>>> messages_;
};

class StormSyncCursorRepo final : public repository::ISyncCursorRepository {
  public:
    std::optional<DeviceSyncCursor> get_sync_cursor(const DeviceId& device_id,
                                                    const ConversationId& conversation_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto key = device_id.str() + ":" + conversation_id.to_string();
        auto it = cursors_.find(key);
        if (it != cursors_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::vector<DeviceSyncCursor> list_sync_cursors_by_device(const DeviceId& device_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DeviceSyncCursor> result;
        for (const auto& [_, cursor] : cursors_) {
            if (cursor.device_id == device_id) {
                result.push_back(cursor);
            }
        }
        return result;
    }

    void upsert_sync_cursor(const DeviceSyncCursor& cursor) override {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto key = cursor.device_id.str() + ":" + cursor.conversation_id.to_string();
        cursors_[key] = cursor;
    }

  private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, DeviceSyncCursor> cursors_;
};

// ============================================================================
// Test Fixture for MSG-012-T02
// ============================================================================

class MessagingSyncReconnectStormTest : public ::testing::Test {
  protected:
    void SetUp() override {
        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        membership_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *membership_repo_);
        sequence_allocator_ = std::make_shared<InMemorySequenceAllocator>();
        message_repo_ = std::make_shared<StormMessageRepo>();
        cursor_repo_ = std::make_shared<StormSyncCursorRepo>();
        cursor_manager_ = std::make_shared<SyncCursorManager>(cursor_repo_, message_repo_, sequence_allocator_);
        sync_service_ = std::make_shared<MessageSyncService>(message_repo_, cursor_manager_, auth_service_);

        conv_id_ = ConversationId::generate_v7();
        sender_user_ = make_user_uuid(999);
        sender_dev_ = DeviceId("dev-sender-999");

        const auto now = std::chrono::system_clock::now();
        ConversationEntity conv;
        conv.conversation_id = conv_id_;
        conv.type = ConversationType::Group;
        conv.created_by_user_id = sender_user_;
        conv.created_at = now;
        conv_repo_->save_conversation(conv);

        ConversationParticipantEntity p_sender;
        p_sender.conversation_id = conv_id_;
        p_sender.user_id = sender_user_;
        p_sender.role = ParticipantRole::Admin;
        p_sender.status = MembershipStatus::Active;
        p_sender.joined_at = now;
        membership_repo_->add_participant(p_sender);
    }

    static UserId make_user_uuid(uint32_t index) {
        std::ostringstream ss;
        ss << "018f1234-5678-7000-8000-" << std::setw(12) << std::setfill('0') << index;
        return UserId(ss.str());
    }

    static DeviceId make_device_id(uint32_t user_idx, uint32_t dev_idx) {
        return DeviceId("storm-user-" + std::to_string(user_idx) + "-dev-" + std::to_string(dev_idx));
    }

    void add_active_participant(const UserId& uid) {
        ConversationParticipantEntity p;
        p.conversation_id = conv_id_;
        p.user_id = uid;
        p.role = ParticipantRole::Member;
        p.status = MembershipStatus::Active;
        p.joined_at = std::chrono::system_clock::now();
        membership_repo_->add_participant(p);
    }

    void append_message_with_next_sequence(const std::string& ciphertext) {
        const auto now = std::chrono::system_clock::now();
        const auto bucket = MessageBucket::from_time_point(now);
        const uint64_t seq = sequence_allocator_->allocate_sequence(conv_id_, bucket);

        MessageEntity msg;
        msg.conversation_id = conv_id_;
        msg.message_bucket = bucket;
        msg.message_sequence = seq;
        msg.message_id = MessageId::generate_v7();
        msg.sender_user_id = sender_user_;
        msg.sender_device_id = sender_dev_;
        msg.priority = MessagePriority::Normal;
        msg.accepted_at = now;
        msg.envelope.ciphertext = ciphertext;
        msg.envelope.envelope_version = 1;
        message_repo_->save_message(msg);
    }

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> membership_repo_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<InMemorySequenceAllocator> sequence_allocator_;
    std::shared_ptr<StormMessageRepo> message_repo_;
    std::shared_ptr<StormSyncCursorRepo> cursor_repo_;
    std::shared_ptr<SyncCursorManager> cursor_manager_;
    std::shared_ptr<MessageSyncService> sync_service_;

    ConversationId conv_id_;
    UserId sender_user_;
    DeviceId sender_dev_;
};

// ============================================================================
// 1. 500-Device Reconnect Storm, Atomic Superseding & Stale Channel Reaper
// ============================================================================

TEST_F(MessagingSyncReconnectStormTest, FiveHundredDevicesReconnectStormSupersedingAndStaleReaper) {
    constexpr uint32_t kNumUsers = 100;
    constexpr uint32_t kDevicesPerUser = 5;
    constexpr size_t kTotalDevices = kNumUsers * kDevicesPerUser; // 500 devices
    constexpr size_t kWorkerThreads = 16;

    ConnectionCapacityConfig cap_cfg;
    cap_cfg.max_devices_per_user = 10;
    cap_cfg.max_global_connections = 10000;
    cap_cfg.default_lease_timeout = std::chrono::seconds(60);

    auto registry = std::make_shared<DeviceConnectionRegistry>(cap_cfg);
    auto presence_coord = std::make_shared<PresenceCoordinator>(std::chrono::seconds(60));
    auto lifecycle_mgr = std::make_shared<ConnectionLifecycleManager>(
        registry, presence_coord, std::chrono::milliseconds(500), std::chrono::seconds(60));

    // Seed 10 messages in the conversation so reconnecting devices can immediately sync
    for (int i = 1; i <= 10; ++i) {
        append_message_with_next_sequence("STORM_CIPHERTEXT_" + std::to_string(i));
    }

    struct DeviceDescriptor {
        UserId user_id;
        DeviceId device_id;
        std::shared_ptr<MockDeviceDeliveryChannel> initial_channel;
        std::shared_ptr<MockDeviceDeliveryChannel> reconnected_channel;
    };

    std::vector<DeviceDescriptor> devices;
    devices.reserve(kTotalDevices);

    for (uint32_t u = 1; u <= kNumUsers; ++u) {
        const UserId uid = make_user_uuid(u);
        add_active_participant(uid);
        for (uint32_t d = 1; d <= kDevicesPerUser; ++d) {
            const DeviceId dev_id = make_device_id(u, d);
            devices.push_back(DeviceDescriptor{
                .user_id = uid,
                .device_id = dev_id,
                .initial_channel = std::make_shared<MockDeviceDeliveryChannel>(dev_id, uid),
                .reconnected_channel = std::make_shared<MockDeviceDeliveryChannel>(dev_id, uid),
            });
        }
    }

    // Wave 1: Initial connection of all 500 devices
    for (const auto& desc : devices) {
        lifecycle_mgr->establish_connection(desc.initial_channel, "10.0.0.1", "SecureCloud-Client/1.0", 1);
    }
    ASSERT_EQ(registry->connected_device_count(), kTotalDevices);
    ASSERT_EQ(lifecycle_mgr->active_session_count(), kTotalDevices);
    ASSERT_EQ(presence_coord->online_users_count(), kNumUsers);

    // Wave 2: Simulated network drop & 500-device simultaneous reconnect storm + sync burst
    std::atomic<size_t> ready_count{0};
    std::atomic<bool> start_gun{false};
    std::atomic<size_t> successful_syncs{0};

    std::vector<std::thread> workers;
    workers.reserve(kWorkerThreads);

    for (size_t w = 0; w < kWorkerThreads; ++w) {
        workers.emplace_back([&, w]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (!start_gun.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            for (size_t idx = w; idx < kTotalDevices; idx += kWorkerThreads) {
                const auto& desc = devices[idx];

                // Half of the devices drop cleanly before reconnecting; the other half supersede directly
                if (idx % 2 == 0) {
                    lifecycle_mgr->terminate_connection(desc.device_id);
                }

                // Re-establish connection with new socket channel
                auto session = lifecycle_mgr->establish_connection(desc.reconnected_channel, "10.0.0.2",
                                                                   "SecureCloud-Client/1.1", 1);
                EXPECT_EQ(session.device_id, desc.device_id);

                // Immediately issue heartbeat and message synchronization pull
                EXPECT_TRUE(lifecycle_mgr->record_heartbeat(desc.device_id));

                SyncDeviceMessagesCommand sync_cmd;
                sync_cmd.device_id = desc.device_id;
                sync_cmd.conversation_id = conv_id_;
                sync_cmd.since_sequence = 0;
                sync_cmd.max_messages = 50;

                auto sync_res = sync_service_->sync_messages(desc.user_id, sync_cmd);
                if (sync_res.is_success() && sync_res.messages.size() == 10u) {
                    auto cur_out = cursor_manager_->update_cursor(desc.device_id, conv_id_, 10);
                    if (cur_out.is_success()) {
                        successful_syncs.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }
        });
    }

    while (ready_count.load(std::memory_order_acquire) < kWorkerThreads) {
        std::this_thread::yield();
    }
    start_gun.store(true, std::memory_order_release);

    for (auto& t : workers) {
        t.join();
    }

    // All 500 devices must be online, superseded cleanly onto reconnected_channel, and synced to seq 10
    EXPECT_EQ(successful_syncs.load(), kTotalDevices);
    EXPECT_EQ(registry->connected_device_count(), kTotalDevices);
    EXPECT_EQ(lifecycle_mgr->active_session_count(), kTotalDevices);
    EXPECT_EQ(presence_coord->online_users_count(), kNumUsers);

    for (const auto& desc : devices) {
        EXPECT_EQ(registry->get_channel(desc.device_id), desc.reconnected_channel);
        const auto cur = cursor_manager_->get_cursor(desc.device_id, conv_id_);
        EXPECT_EQ(cur.last_synced_sequence, 10u);
    }

    // Simulate 200 sockets dying abruptly and run the stale connection reaper
    constexpr size_t kDeadSockets = 200;
    for (size_t i = 0; i < kDeadSockets; ++i) {
        devices[i].reconnected_channel->set_active(false);
    }

    const size_t evicted = lifecycle_mgr->sweep_stale_connections();
    EXPECT_EQ(evicted, kDeadSockets);
    EXPECT_EQ(registry->connected_device_count(), kTotalDevices - kDeadSockets);
    EXPECT_EQ(lifecycle_mgr->active_session_count(), kTotalDevices - kDeadSockets);
}

// ============================================================================
// 2. Concurrent Message Submissions Interleaved with Multi-Device Sync Queries
// ============================================================================

TEST_F(MessagingSyncReconnectStormTest, ConcurrentSubmissionsAndInterleavedDeviceSyncZeroMissedSequences) {
    constexpr size_t kTotalMessages = 500;
    constexpr size_t kNumSyncingDevices = 8;

    const UserId recipient_user = make_user_uuid(1);
    add_active_participant(recipient_user);

    std::vector<DeviceId> sync_devices;
    sync_devices.reserve(kNumSyncingDevices);
    for (uint32_t d = 1; d <= kNumSyncingDevices; ++d) {
        sync_devices.push_back(make_device_id(1, d));
    }

    std::atomic<bool> producer_done{false};
    std::vector<std::vector<uint64_t>> received_sequences(kNumSyncingDevices);

    // Producer thread continuously appending 500 messages in sequence
    std::thread producer([&]() {
        for (size_t i = 1; i <= kTotalMessages; ++i) {
            append_message_with_next_sequence("STREAM_MSG_" + std::to_string(i));
            if (i % 25 == 0) {
                std::this_thread::yield();
            }
        }
        producer_done.store(true, std::memory_order_release);
    });

    // 8 consumer threads concurrently syncing batches of 20 messages and updating cursors
    std::vector<std::thread> consumers;
    consumers.reserve(kNumSyncingDevices);

    for (size_t d = 0; d < kNumSyncingDevices; ++d) {
        consumers.emplace_back([&, d]() {
            const DeviceId& dev_id = sync_devices[d];
            auto& seq_log = received_sequences[d];
            seq_log.reserve(kTotalMessages);

            auto drain_available = [&]() {
                while (true) {
                    SyncDeviceMessagesCommand cmd;
                    cmd.device_id = dev_id;
                    cmd.conversation_id = conv_id_;
                    cmd.since_sequence = 0; // Use stored cursor watermark in SyncCursorManager
                    cmd.max_messages = 20;

                    auto res = sync_service_->sync_messages(recipient_user, cmd);
                    ASSERT_TRUE(res.is_success()) << res.error_message;

                    if (res.messages.empty()) {
                        break;
                    }

                    for (const auto& m : res.messages) {
                        seq_log.push_back(m.message_sequence);
                    }

                    const uint64_t highest = res.messages.back().message_sequence;
                    auto upd = cursor_manager_->update_cursor(dev_id, conv_id_, highest);
                    ASSERT_TRUE(upd.is_success()) << upd.error_message;

                    if (!res.has_more) {
                        break;
                    }
                }
            };

            while (!producer_done.load(std::memory_order_acquire)) {
                drain_available();
                std::this_thread::yield();
            }
            // Final catch-up pass after producer finishes
            drain_available();
        });
    }

    producer.join();
    for (auto& c : consumers) {
        c.join();
    }

    // Assert every device received [1..500] strictly in order with zero gaps and zero duplicates
    for (size_t d = 0; d < kNumSyncingDevices; ++d) {
        const auto& seq_log = received_sequences[d];
        ASSERT_EQ(seq_log.size(), kTotalMessages) << "Device " << d << " missed or duplicated messages";
        for (size_t i = 0; i < kTotalMessages; ++i) {
            ASSERT_EQ(seq_log[i], static_cast<uint64_t>(i + 1))
                << "Out-of-order or skipped sequence on device " << d << " at index " << i;
        }

        const auto final_cursor = cursor_manager_->get_cursor(sync_devices[d], conv_id_);
        EXPECT_EQ(final_cursor.last_synced_sequence, kTotalMessages);
    }
}

// ============================================================================
// 3. Out-Of-Order Concurrent Sync Cursor Updates Never Regress
// ============================================================================

TEST_F(MessagingSyncReconnectStormTest, ConcurrentOutOfOrderCursorUpdatesStrictlyMonotonicNeverRegress) {
    constexpr uint64_t kCeiling = 1000;
    constexpr size_t kUpdaterThreads = 32;
    constexpr size_t kObserverThreads = 4;

    const auto now = std::chrono::system_clock::now();
    const auto bucket = MessageBucket::from_time_point(now);
    sequence_allocator_->set_sequence(conv_id_, bucket, kCeiling);

    const DeviceId target_dev("cursor-race-device-001");

    std::atomic<size_t> ready_count{0};
    std::atomic<bool> start_gun{false};
    std::atomic<bool> updaters_done{false};
    std::atomic<size_t> out_of_bounds_rejections{0};

    std::vector<std::thread> updaters;
    updaters.reserve(kUpdaterThreads);

    for (size_t t = 0; t < kUpdaterThreads; ++t) {
        updaters.emplace_back([&, t]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (!start_gun.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            // Issue interleaved forward, backward, and out-of-bounds sequence updates
            for (uint64_t step = 1; step <= 100; ++step) {
                const uint64_t candidate_seq = ((step * 37 + t * 13) % kCeiling) + 1;
                auto outcome = cursor_manager_->update_cursor(target_dev, conv_id_, candidate_seq);
                EXPECT_TRUE(outcome.status == SyncCursorUpdateStatus::Success ||
                            outcome.status == SyncCursorUpdateStatus::RegressionRejected);
            }

            // Attempt out-of-bounds update (> ceiling)
            auto oob = cursor_manager_->update_cursor(target_dev, conv_id_, kCeiling + 1 + t);
            if (oob.status == SyncCursorUpdateStatus::OutOfBoundsRejected) {
                out_of_bounds_rejections.fetch_add(1, std::memory_order_relaxed);
            }

            // Ensure ceiling is reached by the end
            auto final_step = cursor_manager_->update_cursor(target_dev, conv_id_, kCeiling);
            EXPECT_TRUE(final_step.is_success());
        });
    }

    // Observer threads continuously polling the active cursor to verify zero backward regressions
    std::vector<std::thread> observers;
    observers.reserve(kObserverThreads);

    for (size_t o = 0; o < kObserverThreads; ++o) {
        observers.emplace_back([&]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (!start_gun.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            uint64_t highest_seen_seq = 0;
            int32_t highest_seen_version = 1;

            while (!updaters_done.load(std::memory_order_acquire)) {
                const auto cur = cursor_manager_->get_cursor(target_dev, conv_id_);
                EXPECT_GE(cur.last_synced_sequence, highest_seen_seq) << "Observed sync cursor sequence regression!";
                EXPECT_GE(cur.sync_version, highest_seen_version) << "Observed sync cursor version regression!";
                highest_seen_seq = cur.last_synced_sequence;
                highest_seen_version = cur.sync_version;
                std::this_thread::yield();
            }
        });
    }

    while (ready_count.load(std::memory_order_acquire) < kUpdaterThreads + kObserverThreads) {
        std::this_thread::yield();
    }
    start_gun.store(true, std::memory_order_release);

    for (auto& u : updaters) {
        u.join();
    }
    updaters_done.store(true, std::memory_order_release);
    for (auto& o : observers) {
        o.join();
    }

    EXPECT_EQ(out_of_bounds_rejections.load(), kUpdaterThreads);
    const auto final_cursor = cursor_manager_->get_cursor(target_dev, conv_id_);
    EXPECT_EQ(final_cursor.last_synced_sequence, kCeiling);
}

// ============================================================================
// 4. BoundedDeliveryScheduler Per-Device Flood Backpressure & Fair Round-Robin
// ============================================================================

TEST_F(MessagingSyncReconnectStormTest, BoundedDeliverySchedulerDeviceFloodBackpressureAndFairRoundRobin) {
    DeliverySchedulerConfig cfg;
    cfg.max_tasks_per_device = 50;
    cfg.max_global_queued_tasks = 5000;
    cfg.emergency_queue_reserved_slots = 100;
    cfg.fairness_quanta_per_device = 5;

    BoundedDeliveryScheduler scheduler(cfg);

    const DeviceId flooded_dev("flooded-device-001");
    const std::vector<DeviceId> healthy_devs = {
        DeviceId("healthy-device-001"),
        DeviceId("healthy-device-002"),
        DeviceId("healthy-device-003"),
        DeviceId("healthy-device-004"),
    };

    // Flood flooded_dev from 10 concurrent threads (25 tasks each = 250 total attempts, limit = 50)
    constexpr size_t kFloodThreads = 10;
    constexpr size_t kAttemptsPerThread = 25;
    std::atomic<size_t> flood_enqueued{0};
    std::atomic<size_t> flood_backpressured{0};

    std::vector<std::thread> flooders;
    flooders.reserve(kFloodThreads);

    for (size_t t = 0; t < kFloodThreads; ++t) {
        flooders.emplace_back([&]() {
            for (size_t i = 0; i < kAttemptsPerThread; ++i) {
                DeliveryTask task;
                task.message_id = MessageId::generate_v7();
                task.conversation_id = conv_id_;
                task.recipient_device_id = flooded_dev;
                task.priority = MessagePriority::Normal;

                const auto st = scheduler.schedule(std::move(task));
                if (st == SchedulerStatus::Enqueued) {
                    flood_enqueued.fetch_add(1, std::memory_order_relaxed);
                } else if (st == SchedulerStatus::DeviceQueueFull) {
                    flood_backpressured.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& f : flooders) {
        f.join();
    }

    // Assert exact per-device backpressure bound (50 enqueued, 200 rejected with DeviceQueueFull)
    EXPECT_EQ(flood_enqueued.load(), 50u);
    EXPECT_EQ(flood_backpressured.load(), 200u);
    EXPECT_EQ(scheduler.device_queue_depth(flooded_dev), 50u);

    // Enqueue 15 tasks for each of the 4 healthy devices
    for (const auto& h_dev : healthy_devs) {
        for (size_t i = 0; i < 15; ++i) {
            DeliveryTask task;
            task.message_id = MessageId::generate_v7();
            task.conversation_id = conv_id_;
            task.recipient_device_id = h_dev;
            task.priority = MessagePriority::Normal;
            EXPECT_EQ(scheduler.schedule(std::move(task)), SchedulerStatus::Enqueued);
        }
        EXPECT_EQ(scheduler.device_queue_depth(h_dev), 15u);
    }

    EXPECT_EQ(scheduler.global_queue_depth(), 50u + 4u * 15u);

    // Dequeue the first full round-robin cycle (5 devices * 5 fairness quanta = 25 tasks)
    // Verify that flooded_dev only consumes 5 quanta before rotating to healthy devices (zero starvation)
    std::map<DeviceId, size_t> first_cycle_counts;
    for (size_t i = 0; i < 25; ++i) {
        auto task_opt = scheduler.try_dequeue();
        ASSERT_TRUE(task_opt.has_value());
        first_cycle_counts[task_opt->recipient_device_id]++;
    }

    EXPECT_EQ(first_cycle_counts[flooded_dev], 5u);
    for (const auto& h_dev : healthy_devs) {
        EXPECT_EQ(first_cycle_counts[h_dev], 5u);
    }
}

// ============================================================================
// 5. Global Capacity Saturation & Emergency Priority Preemption Under Load
// ============================================================================

TEST_F(MessagingSyncReconnectStormTest, BoundedDeliverySchedulerGlobalSaturationAndEmergencyPreemptionUnderLoad) {
    DeliverySchedulerConfig cfg;
    cfg.max_tasks_per_device = 100;
    cfg.max_global_queued_tasks = 200;
    cfg.emergency_queue_reserved_slots = 25;
    cfg.fairness_quanta_per_device = 5;

    BoundedDeliveryScheduler scheduler(cfg);

    // Saturate the 200 global normal slots across 4 devices (50 tasks each)
    for (int d = 1; d <= 4; ++d) {
        const DeviceId dev_id("global-sat-dev-" + std::to_string(d));
        for (int i = 0; i < 50; ++i) {
            DeliveryTask task;
            task.message_id = MessageId::generate_v7();
            task.conversation_id = conv_id_;
            task.recipient_device_id = dev_id;
            task.priority = MessagePriority::Normal;
            ASSERT_EQ(scheduler.schedule(std::move(task)), SchedulerStatus::Enqueued);
        }
    }

    ASSERT_EQ(scheduler.global_queue_depth(), 200u);

    // Additional Normal/Urgent tasks must now be rejected with GlobalCapacityExhausted
    for (int i = 0; i < 30; ++i) {
        DeliveryTask excess_normal;
        excess_normal.message_id = MessageId::generate_v7();
        excess_normal.conversation_id = conv_id_;
        excess_normal.recipient_device_id = DeviceId("global-sat-dev-5");
        excess_normal.priority = MessagePriority::Normal;
        EXPECT_EQ(scheduler.schedule(std::move(excess_normal)), SchedulerStatus::GlobalCapacityExhausted);
    }

    // Emergency tasks must still be accepted up to emergency_queue_reserved_slots (25)
    for (int i = 0; i < 25; ++i) {
        DeliveryTask emergency_task;
        emergency_task.message_id = MessageId::generate_v7();
        emergency_task.conversation_id = conv_id_;
        emergency_task.recipient_device_id = DeviceId("global-sat-dev-5");
        emergency_task.priority = MessagePriority::Emergency;
        EXPECT_EQ(scheduler.schedule(std::move(emergency_task)), SchedulerStatus::Enqueued);
    }

    EXPECT_EQ(scheduler.emergency_queue_depth(), 25u);
    EXPECT_EQ(scheduler.global_queue_depth(), 225u);

    // 26th Emergency task exceeds (max_global_queued_tasks + emergency_queue_reserved_slots)
    DeliveryTask overflow_emergency;
    overflow_emergency.message_id = MessageId::generate_v7();
    overflow_emergency.conversation_id = conv_id_;
    overflow_emergency.recipient_device_id = DeviceId("global-sat-dev-5");
    overflow_emergency.priority = MessagePriority::Emergency;
    EXPECT_EQ(scheduler.schedule(std::move(overflow_emergency)), SchedulerStatus::GlobalCapacityExhausted);

    // Verify strict priority preemption: the first 25 dequeued tasks are all Emergency tasks
    for (int i = 0; i < 25; ++i) {
        auto task_opt = scheduler.try_dequeue();
        ASSERT_TRUE(task_opt.has_value());
        EXPECT_EQ(task_opt->priority, MessagePriority::Emergency);
    }
    EXPECT_EQ(scheduler.emergency_queue_depth(), 0u);
    EXPECT_EQ(scheduler.global_queue_depth(), 200u);
}

} // namespace
} // namespace securecloud::messaging::service
