#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/connection_lifecycle_manager.hpp"
#include "delivery/device_connection_registry.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "delivery/realtime_delivery_accelerator.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_bucket.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "service/presence_coordinator.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <vector>

namespace securecloud::messaging::delivery {
namespace {

using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::MessageId;
using domain::RecipientDeliveryState;
using domain::UserId;

class MockDeliveryStateRepository final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.insert(pending_.end(), records.begin(), records.end());
    }

    std::vector<DeviceDeliveryRecord>
    fetch_pending_for_device(const DeviceId& device_id, const std::string& delivery_bucket, size_t limit) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DeviceDeliveryRecord> result;
        for (const auto& rec : pending_) {
            if (rec.device_id == device_id && rec.delivery_bucket == delivery_bucket) {
                result.push_back(rec);
                if (result.size() >= limit) {
                    break;
                }
            }
        }
        return result;
    }

    void update_device_delivery_status(const DeviceId& device_id, const std::string& delivery_bucket,
                                       const std::chrono::system_clock::time_point& accepted_at,
                                       const MessageId& message_id, domain::DeliveryState state, int32_t attempt_count,
                                       std::optional<std::chrono::system_clock::time_point> next_retry) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& rec : pending_) {
            if (rec.device_id == device_id && rec.delivery_bucket == delivery_bucket &&
                rec.accepted_at == accepted_at && rec.message_id == message_id) {
                rec.delivery_state = state;
                rec.attempt_count = attempt_count;
                rec.next_retry_at = next_retry;
                break;
            }
        }
    }

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mutex_);
        recipient_states_.insert(recipient_states_.end(), states.begin(), states.end());
    }

    void record_delivery_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point&) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& rec : pending_) {
            if (rec.message_id == message_id && rec.device_id == recipient_device_id) {
                rec.delivery_state = domain::DeliveryState::Delivered;
            }
        }
        for (auto& s : recipient_states_) {
            if (s.message_id == message_id && s.recipient_device_id == recipient_device_id) {
                s.delivery_state = domain::DeliveryState::Delivered;
            }
        }
    }

    void record_read_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {}

    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<RecipientDeliveryState> result;
        for (const auto& s : recipient_states_) {
            if (s.message_id == message_id) {
                result.push_back(s);
            }
        }
        return result;
    }

    std::mutex mutex_;
    std::vector<DeviceDeliveryRecord> pending_;
    std::vector<RecipientDeliveryState> recipient_states_;
};

class RealtimeDeliveryAcceleratorTest : public ::testing::Test {
  protected:
    void SetUp() override {
        delivery_repo_ = std::make_shared<MockDeliveryStateRepository>();
        scheduler_ = std::make_shared<BoundedDeliveryScheduler>(DeliverySchedulerConfig{
            .max_global_queued_tasks = 200,
            .max_tasks_per_device = 100,
            .emergency_queue_reserved_slots = 10,
        });
        registry_ = std::make_shared<DeviceConnectionRegistry>();
        presence_ = std::make_shared<service::PresenceCoordinator>();

        device_id_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
        user_id_ = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        channel_ = std::make_shared<MockDeviceDeliveryChannel>(device_id_, user_id_);

        current_bucket_ = domain::MessageBucket::from_time_point(std::chrono::system_clock::now()).value();
    }

    DeviceDeliveryRecord
    make_record(const MessageId& mid, domain::DeliveryState state = domain::DeliveryState::Queued,
                std::chrono::system_clock::time_point accepted_at = std::chrono::system_clock::now()) {
        DeviceDeliveryRecord rec;
        rec.device_id = device_id_;
        rec.delivery_bucket = current_bucket_;
        rec.accepted_at = accepted_at;
        rec.message_id = mid;
        rec.conversation_id = domain::ConversationId::generate_v7();
        rec.delivery_state = state;
        rec.ciphertext_blob = "encrypted_payload_" + mid.to_string();
        rec.iv = {0x01, 0x02, 0x03, 0x04};
        rec.auth_tag = {0xAA, 0xBB, 0xCC, 0xDD};
        return rec;
    }

    std::shared_ptr<MockDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<BoundedDeliveryScheduler> scheduler_;
    std::shared_ptr<DeviceConnectionRegistry> registry_;
    std::shared_ptr<service::PresenceCoordinator> presence_;
    DeviceId device_id_;
    UserId user_id_;
    std::shared_ptr<MockDeviceDeliveryChannel> channel_;
    std::string current_bucket_;
};

TEST_F(RealtimeDeliveryAcceleratorTest, HydratesPendingDeliveriesOnReconnect) {
    registry_->register_channel(channel_);

    auto m1 = MessageId::generate_v7();
    auto m2 = MessageId::generate_v7();
    auto m3 = MessageId::generate_v7();

    std::vector<DeviceDeliveryRecord> records = {
        make_record(m1),
        make_record(m2),
        make_record(m3),
    };
    delivery_repo_->save_pending_deliveries(records);

    RealtimeDeliveryAccelerator accelerator(delivery_repo_, scheduler_, registry_);

    const size_t enqueued = accelerator.on_device_connected(device_id_, user_id_, current_bucket_);
    EXPECT_EQ(enqueued, 3);
    EXPECT_EQ(accelerator.total_accelerated_count(), 3);
    EXPECT_EQ(scheduler_->device_queue_depth(device_id_), 3);

    auto task1 = scheduler_->try_dequeue();
    ASSERT_TRUE(task1.has_value());
    EXPECT_EQ(task1->message_id, m1);
    EXPECT_EQ(task1->recipient_device_id, device_id_);
    EXPECT_EQ(task1->recipient_user_id, user_id_);
    EXPECT_EQ(task1->envelope.ciphertext_blob, "encrypted_payload_" + m1.to_string());

    auto task2 = scheduler_->try_dequeue();
    ASSERT_TRUE(task2.has_value());
    EXPECT_EQ(task2->message_id, m2);

    auto task3 = scheduler_->try_dequeue();
    ASSERT_TRUE(task3.has_value());
    EXPECT_EQ(task3->message_id, m3);

    EXPECT_FALSE(scheduler_->try_dequeue().has_value());
}

TEST_F(RealtimeDeliveryAcceleratorTest, EnforcesMaxFastTrackBatchBurstLimit) {
    registry_->register_channel(channel_);

    std::vector<DeviceDeliveryRecord> records;
    records.reserve(70);
    for (int i = 0; i < 70; ++i) {
        records.push_back(make_record(MessageId::generate_v7()));
    }
    delivery_repo_->save_pending_deliveries(records);

    RealtimeDeliveryAccelerator::Config cfg{
        .max_fast_track_batch = 50,
        .max_delivery_ttl = std::chrono::hours(24 * 7),
    };
    RealtimeDeliveryAccelerator accelerator(delivery_repo_, scheduler_, registry_, cfg);

    const size_t enqueued = accelerator.on_device_connected(device_id_, user_id_, current_bucket_);
    EXPECT_EQ(enqueued, 50);
    EXPECT_EQ(accelerator.total_accelerated_count(), 50);
    EXPECT_EQ(scheduler_->device_queue_depth(device_id_), 50);
}

TEST_F(RealtimeDeliveryAcceleratorTest, NoPendingMessagesReturnsZero) {
    registry_->register_channel(channel_);

    RealtimeDeliveryAccelerator accelerator(delivery_repo_, scheduler_, registry_);

    const size_t enqueued = accelerator.on_device_connected(device_id_, user_id_, current_bucket_);
    EXPECT_EQ(enqueued, 0);
    EXPECT_EQ(accelerator.total_accelerated_count(), 0);
    EXPECT_EQ(scheduler_->device_queue_depth(device_id_), 0);
}

TEST_F(RealtimeDeliveryAcceleratorTest, IgnoresOfflineDeviceWhenRegistryConfigured) {
    // Channel is NOT registered in registry_ -> device is offline
    delivery_repo_->save_pending_deliveries({make_record(MessageId::generate_v7())});

    RealtimeDeliveryAccelerator accelerator(delivery_repo_, scheduler_, registry_);

    const size_t enqueued = accelerator.on_device_connected(device_id_, user_id_, current_bucket_);
    EXPECT_EQ(enqueued, 0);
    EXPECT_EQ(accelerator.total_accelerated_count(), 0);
    EXPECT_EQ(scheduler_->device_queue_depth(device_id_), 0);
}

TEST_F(RealtimeDeliveryAcceleratorTest, SkipsAlreadyDeliveredOrNonQueuedMessages) {
    registry_->register_channel(channel_);

    auto m_queued = MessageId::generate_v7();
    auto m_delivered = MessageId::generate_v7();
    auto m_read = MessageId::generate_v7();
    auto m_expired = MessageId::generate_v7();
    auto m_delivering = MessageId::generate_v7();

    std::vector<DeviceDeliveryRecord> records = {
        make_record(m_queued, domain::DeliveryState::Queued),
        make_record(m_delivered, domain::DeliveryState::Delivered),
        make_record(m_read, domain::DeliveryState::Read),
        make_record(m_expired, domain::DeliveryState::Expired),
        make_record(m_delivering, domain::DeliveryState::Delivering),
    };
    delivery_repo_->save_pending_deliveries(records);

    RealtimeDeliveryAccelerator accelerator(delivery_repo_, scheduler_, registry_);

    const size_t enqueued = accelerator.on_device_connected(device_id_, user_id_, current_bucket_);
    EXPECT_EQ(enqueued, 2); // Only queued and delivering
    EXPECT_EQ(accelerator.total_accelerated_count(), 2);

    auto t1 = scheduler_->try_dequeue();
    ASSERT_TRUE(t1.has_value());
    EXPECT_EQ(t1->message_id, m_queued);

    auto t2 = scheduler_->try_dequeue();
    ASSERT_TRUE(t2.has_value());
    EXPECT_EQ(t2->message_id, m_delivering);
}

TEST_F(RealtimeDeliveryAcceleratorTest, EnforcesMaxDeliveryTtlAndMarksExpired) {
    registry_->register_channel(channel_);

    const auto now = std::chrono::system_clock::now();
    const auto expired_time = now - std::chrono::hours(24 * 10); // 10 days ago (TTL is 7 days)
    const auto valid_time = now - std::chrono::hours(1);

    auto m_expired = MessageId::generate_v7();
    auto m_valid = MessageId::generate_v7();

    std::vector<DeviceDeliveryRecord> records = {
        make_record(m_expired, domain::DeliveryState::Queued, expired_time),
        make_record(m_valid, domain::DeliveryState::Queued, valid_time),
    };
    delivery_repo_->save_pending_deliveries(records);

    RealtimeDeliveryAccelerator accelerator(delivery_repo_, scheduler_, registry_);

    const size_t enqueued = accelerator.on_device_connected(device_id_, user_id_, current_bucket_);
    EXPECT_EQ(enqueued, 1);
    EXPECT_EQ(accelerator.total_accelerated_count(), 1);

    auto t = scheduler_->try_dequeue();
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->message_id, m_valid);

    // Verify expired record was updated in repo
    const auto pending = delivery_repo_->fetch_pending_for_device(device_id_, current_bucket_, 10);
    for (const auto& r : pending) {
        if (r.message_id == m_expired) {
            EXPECT_EQ(r.delivery_state, domain::DeliveryState::Expired);
        }
    }
}

TEST_F(RealtimeDeliveryAcceleratorTest, DropToDurableBackpressureOnSchedulerSaturation) {
    registry_->register_channel(channel_);

    // Create a scheduler with very tight capacity (max 2 tasks per device)
    auto tight_scheduler = std::make_shared<BoundedDeliveryScheduler>(DeliverySchedulerConfig{
        .max_global_queued_tasks = 10,
        .max_tasks_per_device = 2,
        .emergency_queue_reserved_slots = 0,
    });

    std::vector<DeviceDeliveryRecord> records = {
        make_record(MessageId::generate_v7()),
        make_record(MessageId::generate_v7()),
        make_record(MessageId::generate_v7()),
        make_record(MessageId::generate_v7()),
    };
    delivery_repo_->save_pending_deliveries(records);

    RealtimeDeliveryAccelerator accelerator(delivery_repo_, tight_scheduler, registry_);

    const size_t enqueued = accelerator.on_device_connected(device_id_, user_id_, current_bucket_);
    // Halts gracefully on 3rd task due to DeviceQueueFull backpressure
    EXPECT_EQ(enqueued, 2);
    EXPECT_EQ(accelerator.total_accelerated_count(), 2);
    EXPECT_EQ(tight_scheduler->device_queue_depth(device_id_), 2);
}

TEST_F(RealtimeDeliveryAcceleratorTest, EndToEndIntegrationViaConnectionLifecycleManager) {
    ConnectionLifecycleManager lifecycle_mgr(registry_, presence_);
    RealtimeDeliveryAccelerator accelerator(delivery_repo_, scheduler_, registry_);

    // Attach accelerator to lifecycle manager reconnection callback
    accelerator.attach_to_lifecycle_manager(lifecycle_mgr);

    auto m1 = MessageId::generate_v7();
    auto m2 = MessageId::generate_v7();

    // Save pending records while device is offline
    delivery_repo_->save_pending_deliveries({
        make_record(m1),
        make_record(m2),
    });

    EXPECT_EQ(scheduler_->global_queue_depth(), 0);
    EXPECT_EQ(accelerator.total_accelerated_count(), 0);

    // Client establishes connection channel
    auto session = lifecycle_mgr.establish_connection(channel_, "192.168.1.50", "SecureCloud-iOS/1.0");

    // Fast-track hook should have triggered synchronously during establish_connection
    EXPECT_EQ(accelerator.total_accelerated_count(), 2);
    EXPECT_EQ(scheduler_->device_queue_depth(device_id_), 2);

    auto t1 = scheduler_->try_dequeue();
    ASSERT_TRUE(t1.has_value());
    EXPECT_EQ(t1->message_id, m1);

    auto t2 = scheduler_->try_dequeue();
    ASSERT_TRUE(t2.has_value());
    EXPECT_EQ(t2->message_id, m2);
}

TEST_F(RealtimeDeliveryAcceleratorTest, NonConflationGuaranteeEnforced) {
    registry_->register_channel(channel_);

    auto m = MessageId::generate_v7();
    delivery_repo_->save_pending_deliveries({make_record(m)});

    RealtimeDeliveryAccelerator accelerator(delivery_repo_, scheduler_, registry_);
    accelerator.on_device_connected(device_id_, user_id_, current_bucket_);

    // 1. Task is scheduled and dequeued for push
    auto task = scheduler_->try_dequeue();
    ASSERT_TRUE(task.has_value());

    // 2. Non-Conflation Axiom: Message in durable repository must REMAIN Queued!
    // Simply connecting and scheduling NEVER marks a message DELIVERED!
    auto records = delivery_repo_->fetch_pending_for_device(device_id_, current_bucket_, 10);
    ASSERT_EQ(records.size(), 1);
    EXPECT_EQ(records[0].delivery_state, domain::DeliveryState::Queued);

    // 3. Only explicit client ACK marks DELIVERED
    delivery_repo_->record_delivery_ack(m, device_id_, std::chrono::system_clock::now());
    records = delivery_repo_->fetch_pending_for_device(device_id_, current_bucket_, 10);
    ASSERT_EQ(records.size(), 1);
    EXPECT_EQ(records[0].delivery_state, domain::DeliveryState::Delivered);
}

} // namespace
} // namespace securecloud::messaging::delivery
