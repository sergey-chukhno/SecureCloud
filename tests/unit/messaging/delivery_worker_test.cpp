#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/delivery_worker.hpp"
#include "delivery/device_connection_registry.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "domain/message_bucket.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::delivery::test {
namespace {

using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationOutboxEventType;
using domain::DeliveryAttemptResult;
using domain::DeliveryState;
using domain::DeliveryTask;
using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::MessageId;
using domain::MessagePriority;
using domain::PerDeviceEnvelope;
using domain::RecipientDeliveryState;
using domain::UserId;

// ============================================================================
// Test Mock Repositories
// ============================================================================

struct StatusUpdateRecord {
    DeviceId device_id;
    std::string delivery_bucket;
    std::chrono::system_clock::time_point accepted_at;
    MessageId message_id;
    DeliveryState state;
    int32_t attempt_count;
    std::optional<std::chrono::system_clock::time_point> next_retry;
};

struct DeliveryAckRecord {
    MessageId message_id;
    DeviceId recipient_device_id;
    std::chrono::system_clock::time_point delivered_at;
};

class MockDeliveryStateRepository final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.insert(pending_.end(), records.begin(), records.end());
    }

    std::vector<DeviceDeliveryRecord> fetch_pending_for_device(const DeviceId&, const std::string&, size_t) override {
        return {};
    }

    void update_device_delivery_status(const DeviceId& device_id, const std::string& delivery_bucket,
                                       const std::chrono::system_clock::time_point& accepted_at,
                                       const MessageId& message_id, DeliveryState state, int32_t attempt_count,
                                       std::optional<std::chrono::system_clock::time_point> next_retry) override {
        std::lock_guard<std::mutex> lock(mutex_);
        status_updates_.push_back(
            {device_id, delivery_bucket, accepted_at, message_id, state, attempt_count, next_retry});
    }

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>&) override {}

    void record_delivery_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point& delivered_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        recorded_acks_.push_back({message_id, recipient_device_id, delivered_at});
    }

    void record_read_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {}

    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId&) override { return {}; }

    std::mutex mutex_;
    std::vector<DeviceDeliveryRecord> pending_;
    std::vector<StatusUpdateRecord> status_updates_;
    std::vector<DeliveryAckRecord> recorded_acks_;
};

class MockOutboxRepository final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string&) override {
        std::lock_guard<std::mutex> lock(mutex_);
        enqueued_events_.push_back(event);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }

    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

    std::mutex mutex_;
    std::vector<ConversationOutboxEvent> enqueued_events_;
};

DeliveryTask create_test_task(const DeviceId& device_id, const MessageId& message_id,
                              MessagePriority priority = MessagePriority::Normal) {
    DeliveryTask task;
    task.message_id = message_id;
    task.conversation_id = ConversationId::generate_v7();
    task.recipient_device_id = device_id;
    task.recipient_user_id = UserId("user-1");
    task.priority = priority;
    task.attempt_count = 0;
    task.accepted_at = std::chrono::system_clock::now();
    task.scheduled_at = task.accepted_at;

    task.envelope.recipient_device_id = device_id;
    task.envelope.recipient_user_id = task.recipient_user_id;
    task.envelope.ciphertext_blob = "encrypted-data";
    task.envelope.iv = {0x01, 0x02, 0x03};
    task.envelope.auth_tag = {0x04, 0x05, 0x06};
    return task;
}

// ============================================================================
// DeliveryWorker Test Suite
// ============================================================================

class DeliveryWorkerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        scheduler_ = std::make_shared<BoundedDeliveryScheduler>();
        connection_registry_ = std::make_shared<DeviceConnectionRegistry>();
        delivery_repo_ = std::make_shared<MockDeliveryStateRepository>();
        outbox_repo_ = std::make_shared<MockOutboxRepository>();
        retry_policy_ = std::make_shared<service::DeliveryRetryPolicy>();

        DeliveryWorkerConfig config;
        config.send_timeout = std::chrono::milliseconds(500);
        config.poll_timeout = std::chrono::milliseconds(50);
        config.worker_threads = 2;

        worker_ = std::make_unique<DeliveryWorker>(scheduler_, connection_registry_, delivery_repo_, outbox_repo_,
                                                   retry_policy_, config);
    }

    std::shared_ptr<BoundedDeliveryScheduler> scheduler_;
    std::shared_ptr<DeviceConnectionRegistry> connection_registry_;
    std::shared_ptr<MockDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<MockOutboxRepository> outbox_repo_;
    std::shared_ptr<service::DeliveryRetryPolicy> retry_policy_;
    std::unique_ptr<DeliveryWorker> worker_;
};

TEST_F(DeliveryWorkerTest, SuccessfulDeliveryUpdatesDurableStateAndEmitsOutboxAck) {
    const auto dev_id = DeviceId("dev-1");
    const auto msg_id = MessageId::generate_v7();

    auto channel = std::make_shared<MockDeviceDeliveryChannel>(dev_id, UserId("user-1"));
    channel->set_next_result(DeliveryAttemptResult::Success);
    connection_registry_->register_channel(channel);

    auto task = create_test_task(dev_id, msg_id);
    EXPECT_EQ(scheduler_->schedule(task), SchedulerStatus::Enqueued);

    const bool processed = worker_->process_single_task(std::chrono::milliseconds(100));
    EXPECT_TRUE(processed);

    // Verify channel received envelope
    EXPECT_EQ(channel->sent_tasks().size(), 1u);
    EXPECT_EQ(channel->sent_tasks()[0].message_id, msg_id);

    // Verify durable ACK recorded
    ASSERT_EQ(delivery_repo_->recorded_acks_.size(), 1u);
    EXPECT_EQ(delivery_repo_->recorded_acks_[0].message_id, msg_id);
    EXPECT_EQ(delivery_repo_->recorded_acks_[0].recipient_device_id, dev_id);

    // Verify status transitions: DELIVERING -> DELIVERED
    ASSERT_GE(delivery_repo_->status_updates_.size(), 2u);
    EXPECT_EQ(delivery_repo_->status_updates_[0].state, DeliveryState::Delivering);
    EXPECT_EQ(delivery_repo_->status_updates_[1].state, DeliveryState::Delivered);

    // Verify outbox ack event
    ASSERT_EQ(outbox_repo_->enqueued_events_.size(), 1u);
    EXPECT_EQ(outbox_repo_->enqueued_events_[0].event_type, ConversationOutboxEventType::MessageDelivered);
    EXPECT_NE(outbox_repo_->enqueued_events_[0].payload_json.find(msg_id.to_string()), std::string::npos);
}

TEST_F(DeliveryWorkerTest, RecipientOfflineRevertsToQueuedWithoutRetryPenalty) {
    const auto dev_id = DeviceId("dev-1");
    const auto msg_id = MessageId::generate_v7();

    // Device is NOT registered in connection_registry_
    auto task = create_test_task(dev_id, msg_id);
    EXPECT_EQ(scheduler_->schedule(task), SchedulerStatus::Enqueued);

    const bool processed = worker_->process_single_task(std::chrono::milliseconds(100));
    EXPECT_TRUE(processed);

    // Verify state transitioned to QUEUED with 0 retry penalty
    ASSERT_EQ(delivery_repo_->status_updates_.size(), 1u);
    EXPECT_EQ(delivery_repo_->status_updates_[0].state, DeliveryState::Queued);
    EXPECT_EQ(delivery_repo_->status_updates_[0].attempt_count, 0);

    // No outbox ack and no delivered ack
    EXPECT_TRUE(delivery_repo_->recorded_acks_.empty());
    EXPECT_TRUE(outbox_repo_->enqueued_events_.empty());
}

TEST_F(DeliveryWorkerTest, DisconnectedDuringTransmissionRevertsToQueued) {
    const auto dev_id = DeviceId("dev-1");
    const auto msg_id = MessageId::generate_v7();

    auto channel = std::make_shared<MockDeviceDeliveryChannel>(dev_id, UserId("user-1"));
    channel->set_next_result(DeliveryAttemptResult::RecipientOffline);
    connection_registry_->register_channel(channel);

    auto task = create_test_task(dev_id, msg_id);
    EXPECT_EQ(scheduler_->schedule(task), SchedulerStatus::Enqueued);

    const bool processed = worker_->process_single_task(std::chrono::milliseconds(100));
    EXPECT_TRUE(processed);

    // Status transitions: DELIVERING -> QUEUED
    ASSERT_GE(delivery_repo_->status_updates_.size(), 2u);
    EXPECT_EQ(delivery_repo_->status_updates_[0].state, DeliveryState::Delivering);
    EXPECT_EQ(delivery_repo_->status_updates_[1].state, DeliveryState::Queued);
    EXPECT_TRUE(delivery_repo_->recorded_acks_.empty());
}

TEST_F(DeliveryWorkerTest, TransientFailureComputesBackoffAndTransitionsToRetryWait) {
    const auto dev_id = DeviceId("dev-1");
    const auto msg_id = MessageId::generate_v7();

    auto channel = std::make_shared<MockDeviceDeliveryChannel>(dev_id, UserId("user-1"));
    channel->set_next_result(DeliveryAttemptResult::TransientFailure);
    connection_registry_->register_channel(channel);

    auto task = create_test_task(dev_id, msg_id);
    EXPECT_EQ(scheduler_->schedule(task), SchedulerStatus::Enqueued);

    const bool processed = worker_->process_single_task(std::chrono::milliseconds(100));
    EXPECT_TRUE(processed);

    // Status transitions: DELIVERING -> RETRY_WAIT
    ASSERT_GE(delivery_repo_->status_updates_.size(), 2u);
    EXPECT_EQ(delivery_repo_->status_updates_[0].state, DeliveryState::Delivering);
    EXPECT_EQ(delivery_repo_->status_updates_[1].state, DeliveryState::RetryWait);
    EXPECT_EQ(delivery_repo_->status_updates_[1].attempt_count, 1);
    EXPECT_TRUE(delivery_repo_->status_updates_[1].next_retry.has_value());

    // Task must be re-enqueued into scheduler for retry
    EXPECT_EQ(scheduler_->global_queue_depth(), 1u);
}

TEST_F(DeliveryWorkerTest, ExhaustedRetriesTransitionToExpired) {
    const auto dev_id = DeviceId("dev-1");
    const auto msg_id = MessageId::generate_v7();

    auto channel = std::make_shared<MockDeviceDeliveryChannel>(dev_id, UserId("user-1"));
    channel->set_next_result(DeliveryAttemptResult::TransientFailure);
    connection_registry_->register_channel(channel);

    auto task = create_test_task(dev_id, msg_id);
    task.attempt_count = 10; // Max allowed attempts
    EXPECT_EQ(scheduler_->schedule(task), SchedulerStatus::Enqueued);

    const bool processed = worker_->process_single_task(std::chrono::milliseconds(100));
    EXPECT_TRUE(processed);

    // Status transitions: DELIVERING -> EXPIRED
    ASSERT_GE(delivery_repo_->status_updates_.size(), 2u);
    EXPECT_EQ(delivery_repo_->status_updates_[0].state, DeliveryState::Delivering);
    EXPECT_EQ(delivery_repo_->status_updates_[1].state, DeliveryState::Expired);

    // Scheduler should not have re-enqueued
    EXPECT_EQ(scheduler_->global_queue_depth(), 0u);
}

TEST_F(DeliveryWorkerTest, TerminalFailureTransitionsToExpired) {
    const auto dev_id = DeviceId("dev-1");
    const auto msg_id = MessageId::generate_v7();

    auto channel = std::make_shared<MockDeviceDeliveryChannel>(dev_id, UserId("user-1"));
    channel->set_next_result(DeliveryAttemptResult::TerminalFailure);
    connection_registry_->register_channel(channel);

    auto task = create_test_task(dev_id, msg_id);
    EXPECT_EQ(scheduler_->schedule(task), SchedulerStatus::Enqueued);

    const bool processed = worker_->process_single_task(std::chrono::milliseconds(100));
    EXPECT_TRUE(processed);

    // Status transitions: DELIVERING -> EXPIRED
    ASSERT_GE(delivery_repo_->status_updates_.size(), 2u);
    EXPECT_EQ(delivery_repo_->status_updates_[0].state, DeliveryState::Delivering);
    EXPECT_EQ(delivery_repo_->status_updates_[1].state, DeliveryState::Expired);
}

TEST_F(DeliveryWorkerTest, WorkerThreadPoolProcessesTasksConcurrentlyAndStopsGracefully) {
    const auto dev_id = DeviceId("dev-1");
    auto channel = std::make_shared<MockDeviceDeliveryChannel>(dev_id, UserId("user-1"));
    channel->set_next_result(DeliveryAttemptResult::Success);
    connection_registry_->register_channel(channel);

    // Enqueue 10 tasks
    for (int i = 0; i < 10; ++i) {
        scheduler_->schedule(create_test_task(dev_id, MessageId::generate_v7()));
    }
    EXPECT_EQ(scheduler_->global_queue_depth(), 10u);

    worker_->start();
    EXPECT_TRUE(worker_->is_running());

    // Wait until queue is drained
    for (int wait = 0; wait < 50 && scheduler_->global_queue_depth() > 0; ++wait) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    worker_->stop();
    EXPECT_FALSE(worker_->is_running());

    EXPECT_EQ(scheduler_->global_queue_depth(), 0u);
    EXPECT_EQ(channel->sent_tasks().size(), 10u);
    EXPECT_EQ(delivery_repo_->recorded_acks_.size(), 10u);
}

} // namespace
} // namespace securecloud::messaging::delivery::test
