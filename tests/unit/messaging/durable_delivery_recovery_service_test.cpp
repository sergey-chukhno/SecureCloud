#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/device_connection_registry.hpp"
#include "delivery/durable_delivery_recovery_service.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_bucket.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"

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

    void record_delivery_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {
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

class DurableDeliveryRecoveryServiceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        delivery_repo_ = std::make_shared<MockDeliveryStateRepository>();
        scheduler_ = std::make_shared<BoundedDeliveryScheduler>(DeliverySchedulerConfig{
            .max_global_queued_tasks = 100,
            .max_tasks_per_device = 10,
            .emergency_queue_reserved_slots = 10,
        });
        registry_ = std::make_shared<DeviceConnectionRegistry>();

        device_id_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
        user_id_ = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        channel_ = std::make_shared<MockDeviceDeliveryChannel>(device_id_, user_id_);
        registry_->register_channel(channel_);

        now_ = std::chrono::system_clock::now();
        bucket_ = domain::MessageBucket::from_time_point(now_).value();

        config_.batch_size = 50;
        config_.sweep_interval = std::chrono::milliseconds(50);
        config_.max_retry_attempts = 3;
        config_.max_delivery_ttl = std::chrono::hours(24);

        recovery_service_ =
            std::make_unique<DurableDeliveryRecoveryService>(delivery_repo_, scheduler_, registry_, config_);
    }

    DeviceDeliveryRecord create_record(const MessageId& mid,
                                       domain::DeliveryState state = domain::DeliveryState::Queued,
                                       int32_t attempt_count = 0) {
        DeviceDeliveryRecord r;
        r.device_id = device_id_;
        r.delivery_bucket = bucket_;
        r.accepted_at = now_;
        r.message_id = mid;
        r.conversation_id = domain::ConversationId::generate_v7();
        r.delivery_state = state;
        r.attempt_count = attempt_count;
        r.ciphertext_blob = "ciphertext-data";
        r.iv = {0x01, 0x02};
        r.auth_tag = {0x03, 0x04};
        return r;
    }

    std::shared_ptr<MockDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<BoundedDeliveryScheduler> scheduler_;
    std::shared_ptr<DeviceConnectionRegistry> registry_;
    std::shared_ptr<MockDeviceDeliveryChannel> channel_;
    DeviceId device_id_;
    UserId user_id_;
    std::chrono::system_clock::time_point now_;
    std::string bucket_;
    DeliveryRecoveryConfig config_;
    std::unique_ptr<DurableDeliveryRecoveryService> recovery_service_;
};

TEST_F(DurableDeliveryRecoveryServiceTest, StartupRecoveryHydratesPendingTasks) {
    auto m1 = MessageId::generate_v7();
    auto m2 = MessageId::generate_v7();
    delivery_repo_->save_pending_deliveries({create_record(m1), create_record(m2)});

    size_t recovered = recovery_service_->recover_pending_for_device(device_id_, bucket_);

    EXPECT_EQ(recovered, 2u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 2u);

    auto t1 = scheduler_->try_dequeue();
    ASSERT_TRUE(t1.has_value());
    EXPECT_EQ(t1->message_id, m1);
    EXPECT_EQ(t1->recipient_device_id, device_id_);

    auto t2 = scheduler_->try_dequeue();
    ASSERT_TRUE(t2.has_value());
    EXPECT_EQ(t2->message_id, m2);
}

TEST_F(DurableDeliveryRecoveryServiceTest, RetrySweeperReEnqueuesReadyTasks) {
    auto mid = MessageId::generate_v7();
    auto rec = create_record(mid, domain::DeliveryState::RetryWait, 1);
    rec.next_retry_at = now_ - std::chrono::seconds(5); // in the past: ready for retry
    delivery_repo_->save_pending_deliveries({rec});

    size_t swept = recovery_service_->sweep_retries_for_device(device_id_, bucket_, now_);

    EXPECT_EQ(swept, 1u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 1u);

    // Verify repo updated to QUEUED
    auto pending = delivery_repo_->fetch_pending_for_device(device_id_, bucket_, 10);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].delivery_state, domain::DeliveryState::Queued);
}

TEST_F(DurableDeliveryRecoveryServiceTest, RetrySweeperIgnoresFutureRetries) {
    auto mid = MessageId::generate_v7();
    auto rec = create_record(mid, domain::DeliveryState::RetryWait, 1);
    rec.next_retry_at = now_ + std::chrono::seconds(60); // future: not ready
    delivery_repo_->save_pending_deliveries({rec});

    size_t swept = recovery_service_->sweep_retries_for_device(device_id_, bucket_, now_);

    EXPECT_EQ(swept, 0u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 0u);

    auto pending = delivery_repo_->fetch_pending_for_device(device_id_, bucket_, 10);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].delivery_state, domain::DeliveryState::RetryWait);
}

TEST_F(DurableDeliveryRecoveryServiceTest, RetrySweeperExpiresExhaustedRetries) {
    auto mid = MessageId::generate_v7();
    auto rec = create_record(mid, domain::DeliveryState::RetryWait, 3); // 3 attempts >= max_retries (3)
    rec.next_retry_at = now_ - std::chrono::seconds(5);
    delivery_repo_->save_pending_deliveries({rec});

    size_t swept = recovery_service_->sweep_retries_for_device(device_id_, bucket_, now_);

    EXPECT_EQ(swept, 0u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 0u);

    // Verify status transitioned to EXPIRED
    auto pending = delivery_repo_->fetch_pending_for_device(device_id_, bucket_, 10);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].delivery_state, domain::DeliveryState::Expired);
}

TEST_F(DurableDeliveryRecoveryServiceTest, ExpiredDeliveryPurgerMarksExpired) {
    auto mid = MessageId::generate_v7();
    auto rec = create_record(mid, domain::DeliveryState::Queued, 0);
    rec.accepted_at = now_ - std::chrono::hours(25); // > 24 hours TTL
    delivery_repo_->save_pending_deliveries({rec});

    size_t purged = recovery_service_->purge_expired_for_device(device_id_, bucket_, now_);

    EXPECT_EQ(purged, 1u);
    auto pending = delivery_repo_->fetch_pending_for_device(device_id_, bucket_, 10);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].delivery_state, domain::DeliveryState::Expired);
}

TEST_F(DurableDeliveryRecoveryServiceTest, OfflineDeviceSkippedUntilOnline) {
    registry_->unregister_channel(device_id_);
    EXPECT_FALSE(registry_->is_online(device_id_));

    auto mid = MessageId::generate_v7();
    delivery_repo_->save_pending_deliveries({create_record(mid)});

    // Recovery skips offline device
    size_t recovered = recovery_service_->recover_pending_for_device(device_id_, bucket_);
    EXPECT_EQ(recovered, 0u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 0u);

    // Device reconnects
    registry_->register_channel(channel_);
    EXPECT_TRUE(registry_->is_online(device_id_));

    recovered = recovery_service_->recover_pending_for_device(device_id_, bucket_);
    EXPECT_EQ(recovered, 1u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 1u);
}

TEST_F(DurableDeliveryRecoveryServiceTest, DropToDurableBackpressureTolerance) {
    // Reconfigure scheduler with small per-device capacity
    scheduler_ = std::make_shared<BoundedDeliveryScheduler>(DeliverySchedulerConfig{
        .max_global_queued_tasks = 100,
        .max_tasks_per_device = 2,
        .emergency_queue_reserved_slots = 10,
    });
    recovery_service_ =
        std::make_unique<DurableDeliveryRecoveryService>(delivery_repo_, scheduler_, registry_, config_);

    // Save 4 records for device in ScyllaDB
    for (int i = 0; i < 4; ++i) {
        delivery_repo_->save_pending_deliveries({create_record(MessageId::generate_v7())});
    }

    // First recovery sweep: fills queue to capacity 2, drops remaining 2 to durable storage
    size_t recovered = recovery_service_->recover_pending_for_device(device_id_, bucket_);
    EXPECT_EQ(recovered, 2u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 2u);

    // Dequeue both tasks
    EXPECT_TRUE(scheduler_->try_dequeue().has_value());
    EXPECT_TRUE(scheduler_->try_dequeue().has_value());
    EXPECT_EQ(scheduler_->global_queue_depth(), 0u);

    // Next recovery sweep recovers remaining tasks without data loss
    recovered = recovery_service_->recover_pending_for_device(device_id_, bucket_);
    EXPECT_EQ(recovered, 2u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 2u);
}

TEST_F(DurableDeliveryRecoveryServiceTest, BackgroundSweeperThreadLifecycle) {
    EXPECT_FALSE(recovery_service_->is_running());
    recovery_service_->start({device_id_});
    EXPECT_TRUE(recovery_service_->is_running());
    recovery_service_->stop();
    EXPECT_FALSE(recovery_service_->is_running());
}

} // namespace
} // namespace securecloud::messaging::delivery
