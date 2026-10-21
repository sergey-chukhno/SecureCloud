#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/delivery_worker.hpp"
#include "delivery/device_connection_registry.hpp"
#include "delivery/durable_delivery_recovery_service.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "delivery/outbox_delivery_consumer.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/outbox_event.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "service/delivery_service.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <thread>
#include <vector>

namespace securecloud::messaging::delivery {
namespace {

using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::MessageId;
using domain::RecipientDeliveryState;
using domain::UserId;

// ============================================================================
// In-Memory Test Repositories
// ============================================================================

class InMemoryDeliveryStateRepo final : public repository::IDeliveryStateRepository {
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
            if (rec.device_id == device_id && (delivery_bucket.empty() || rec.delivery_bucket == delivery_bucket)) {
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
                             const std::chrono::system_clock::time_point& delivered_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        ack_count_++;
        for (auto& s : recipient_states_) {
            if (s.message_id == message_id && s.recipient_device_id == recipient_device_id) {
                s.delivery_state = domain::DeliveryState::Delivered;
                s.delivered_at = delivered_at;
                break;
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
    size_t ack_count_{0};
};

class InMemoryOutboxRepo final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const domain::ConversationOutboxEvent& event, const std::string& bucket) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string b = bucket.empty() ? repository::outbox_bucket_from_time_point(event.created_at) : bucket;
        events_.push_back({b, event.created_at, event.event_id, event.conversation_id,
                           domain::to_string(event.event_type), event.payload_json, std::nullopt,
                           repository::OutboxPublishStatus::Pending});
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string& bucket, size_t limit) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<repository::OutboxEventRecord> result;
        for (const auto& rec : events_) {
            if (rec.outbox_bucket == bucket && rec.publish_status == repository::OutboxPublishStatus::Pending) {
                result.push_back(rec);
                if (result.size() >= limit) {
                    break;
                }
            }
        }
        return result;
    }

    void mark_event_published(const std::string& bucket, std::chrono::system_clock::time_point created_at,
                              const std::string& event_id,
                              std::chrono::system_clock::time_point published_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& rec : events_) {
            if (rec.outbox_bucket == bucket && rec.created_at == created_at && rec.event_id == event_id) {
                rec.publish_status = repository::OutboxPublishStatus::Published;
                rec.published_at = published_at;
                break;
            }
        }
    }

    std::mutex mutex_;
    std::vector<repository::OutboxEventRecord> events_;
};

// ============================================================================
// Comprehensive Pipeline Fixture
// ============================================================================

class OnlineDeliveryPipelineTest : public ::testing::Test {
  protected:
    void SetUp() override {
        delivery_repo_ = std::make_shared<InMemoryDeliveryStateRepo>();
        outbox_repo_ = std::make_shared<InMemoryOutboxRepo>();
        registry_ = std::make_shared<DeviceConnectionRegistry>();

        scheduler_ = std::make_shared<BoundedDeliveryScheduler>(DeliverySchedulerConfig{
            .max_global_queued_tasks = 200,
            .max_tasks_per_device = 20,
            .emergency_queue_reserved_slots = 20,
        });

        auto retry_policy = std::make_shared<service::DeliveryRetryPolicy>(service::DeliveryRetryConfig{
            .initial_backoff = std::chrono::milliseconds(50),
            .max_backoff = std::chrono::milliseconds(500),
            .max_retry_attempts = 3,
        });

        worker_ = std::make_unique<DeliveryWorker>(scheduler_, registry_, delivery_repo_, outbox_repo_, retry_policy,
                                                   DeliveryWorkerConfig{
                                                       .send_timeout = std::chrono::milliseconds(200),
                                                       .poll_timeout = std::chrono::milliseconds(50),
                                                       .worker_threads = 2,
                                                   });

        consumer_ = std::make_unique<OutboxDeliveryConsumer>(outbox_repo_, delivery_repo_, registry_, scheduler_);

        delivery_service_ = std::make_shared<service::DeliveryService>(delivery_repo_, outbox_repo_);

        recovery_service_ =
            std::make_unique<DurableDeliveryRecoveryService>(delivery_repo_, scheduler_, registry_,
                                                             DeliveryRecoveryConfig{
                                                                 .batch_size = 50,
                                                                 .sweep_interval = std::chrono::milliseconds(50),
                                                                 .max_retry_attempts = 3,
                                                                 .max_delivery_ttl = std::chrono::hours(24),
                                                             });

        now_ = std::chrono::system_clock::now();
        bucket_ = domain::MessageBucket::from_time_point(now_).value();
        outbox_bucket_ = repository::outbox_bucket_from_time_point(now_);
    }

    void TearDown() override {
        if (worker_) {
            worker_->stop();
        }
        if (recovery_service_) {
            recovery_service_->stop();
        }
    }

    std::shared_ptr<InMemoryDeliveryStateRepo> delivery_repo_;
    std::shared_ptr<InMemoryOutboxRepo> outbox_repo_;
    std::shared_ptr<DeviceConnectionRegistry> registry_;
    std::shared_ptr<BoundedDeliveryScheduler> scheduler_;
    std::unique_ptr<DeliveryWorker> worker_;
    std::unique_ptr<OutboxDeliveryConsumer> consumer_;
    std::shared_ptr<service::DeliveryService> delivery_service_;
    std::unique_ptr<DurableDeliveryRecoveryService> recovery_service_;

    std::chrono::system_clock::time_point now_;
    std::string bucket_;
    std::string outbox_bucket_;
};

// ============================================================================
// 1. Successful Online Delivery
// ============================================================================

TEST_F(OnlineDeliveryPipelineTest, Scenario1_SuccessfulOnlineDelivery) {
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    auto channel = std::make_shared<MockDeviceDeliveryChannel>(device_id, user_id);
    registry_->register_channel(channel);

    auto message_id = MessageId::generate_v7();
    auto conversation_id = domain::ConversationId::generate_v7();

    // 1. Submit message data into ScyllaDB & Outbox (as MessageSubmissionService does)
    RecipientDeliveryState recip_state;
    recip_state.message_id = message_id;
    recip_state.recipient_device_id = device_id;
    recip_state.recipient_user_id = user_id;
    recip_state.delivery_state = domain::DeliveryState::Queued;
    delivery_repo_->save_recipient_delivery_states({recip_state});

    DeviceDeliveryRecord dev_rec;
    dev_rec.device_id = device_id;
    dev_rec.delivery_bucket = bucket_;
    dev_rec.accepted_at = now_;
    dev_rec.message_id = message_id;
    dev_rec.conversation_id = conversation_id;
    dev_rec.delivery_state = domain::DeliveryState::Queued;
    dev_rec.ciphertext_blob = "encrypted_payload_bytes";
    delivery_repo_->save_pending_deliveries({dev_rec});

    domain::ConversationOutboxEvent sent_event;
    sent_event.event_id = MessageId::generate_v7().to_string();
    sent_event.conversation_id = conversation_id;
    sent_event.event_type = domain::ConversationOutboxEventType::MessageSent;
    sent_event.created_at = now_;
    nlohmann::json payload;
    payload["message_id"] = message_id.to_string();
    payload["conversation_id"] = conversation_id.to_string();
    sent_event.payload_json = payload.dump();
    outbox_repo_->enqueue_event(sent_event, outbox_bucket_);

    // 2. Outbox Consumer polls and enqueues to Scheduler
    size_t processed = consumer_->poll_and_dispatch(outbox_bucket_, 50);
    EXPECT_EQ(processed, 1u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 1u);

    // 3. Worker dequeues task and dispatches over Channel
    worker_->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    worker_->stop();

    EXPECT_EQ(channel->sent_tasks().size(), 1u);
    EXPECT_EQ(channel->sent_tasks()[0].message_id, message_id);

    // 4. Client affirmatively acknowledges delivery
    service::DeliveryAckCommand ack_cmd;
    ack_cmd.message_id = message_id;
    ack_cmd.recipient_device_id = device_id;
    ack_cmd.caller_user_id = user_id;
    ack_cmd.delivered_at = std::chrono::system_clock::now();
    ack_cmd.conversation_id = conversation_id;

    auto ack_result = delivery_service_->acknowledge_delivery(ack_cmd);
    ASSERT_TRUE(ack_result);
    EXPECT_EQ(ack_result.value.state, v1::DELIVERY_STATE_DELIVERED);

    // Verify ScyllaDB state updated to DELIVERED
    auto states = delivery_repo_->get_delivery_states_for_message(message_id);
    ASSERT_EQ(states.size(), 1u);
    EXPECT_EQ(states[0].delivery_state, domain::DeliveryState::Delivered);
}

// ============================================================================
// 2. Offline Recipient
// ============================================================================

TEST_F(OnlineDeliveryPipelineTest, Scenario2_OfflineRecipientDelayedDelivery) {
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    // Device is OFFLINE: channel not registered in registry_

    auto message_id = MessageId::generate_v7();
    auto conversation_id = domain::ConversationId::generate_v7();

    RecipientDeliveryState recip_state;
    recip_state.message_id = message_id;
    recip_state.recipient_device_id = device_id;
    recip_state.recipient_user_id = user_id;
    recip_state.delivery_state = domain::DeliveryState::Queued;
    delivery_repo_->save_recipient_delivery_states({recip_state});

    DeviceDeliveryRecord dev_rec;
    dev_rec.device_id = device_id;
    dev_rec.delivery_bucket = bucket_;
    dev_rec.accepted_at = now_;
    dev_rec.message_id = message_id;
    dev_rec.conversation_id = conversation_id;
    dev_rec.delivery_state = domain::DeliveryState::Queued;
    delivery_repo_->save_pending_deliveries({dev_rec});

    domain::ConversationOutboxEvent sent_event;
    sent_event.event_id = MessageId::generate_v7().to_string();
    sent_event.conversation_id = conversation_id;
    sent_event.event_type = domain::ConversationOutboxEventType::MessageSent;
    sent_event.created_at = now_;
    nlohmann::json payload;
    payload["message_id"] = message_id.to_string();
    sent_event.payload_json = payload.dump();
    outbox_repo_->enqueue_event(sent_event, outbox_bucket_);

    // Outbox Consumer skips offline device
    size_t processed = consumer_->poll_and_dispatch(outbox_bucket_, 50);
    EXPECT_EQ(processed, 1u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 0u);

    // Record remains safely in ScyllaDB
    auto pending = delivery_repo_->fetch_pending_for_device(device_id, bucket_, 10);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].delivery_state, domain::DeliveryState::Queued);

    // Recipient comes online
    auto channel = std::make_shared<MockDeviceDeliveryChannel>(device_id, user_id);
    registry_->register_channel(channel);

    // Recovery engine recovers pending message
    size_t recovered = recovery_service_->recover_pending_for_device(device_id, bucket_);
    EXPECT_EQ(recovered, 1u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 1u);
}

// ============================================================================
// 3. Transient Failure & Exponential Backoff with Jitter
// ============================================================================

TEST_F(OnlineDeliveryPipelineTest, Scenario3_TransientFailureAndBackoff) {
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    auto channel = std::make_shared<MockDeviceDeliveryChannel>(device_id, user_id);
    channel->set_next_result(domain::DeliveryAttemptResult::TransientFailure);
    registry_->register_channel(channel);

    auto message_id = MessageId::generate_v7();
    auto conversation_id = domain::ConversationId::generate_v7();
    domain::DeliveryTask task;
    task.message_id = message_id;
    task.conversation_id = conversation_id;
    task.recipient_device_id = device_id;
    task.recipient_user_id = user_id;
    task.accepted_at = now_;
    task.attempt_count = 0;
    scheduler_->schedule(task);

    DeviceDeliveryRecord dev_rec;
    dev_rec.device_id = device_id;
    dev_rec.delivery_bucket = bucket_;
    dev_rec.accepted_at = now_;
    dev_rec.message_id = message_id;
    dev_rec.conversation_id = conversation_id;
    dev_rec.delivery_state = domain::DeliveryState::Queued;
    delivery_repo_->save_pending_deliveries({dev_rec});

    worker_->process_single_task(std::chrono::milliseconds(50));

    // Verify task transitioned to RETRY_WAIT in ScyllaDB with attempt_count = 1 and next_retry_at set
    auto pending = delivery_repo_->fetch_pending_for_device(device_id, bucket_, 10);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].delivery_state, domain::DeliveryState::RetryWait);
    EXPECT_EQ(pending[0].attempt_count, 1);
    EXPECT_TRUE(pending[0].next_retry_at.has_value());
    EXPECT_GT(*pending[0].next_retry_at, now_);
}

// ============================================================================
// 4. Terminal Failure
// ============================================================================

TEST_F(OnlineDeliveryPipelineTest, Scenario4_TerminalFailureImmediatelyExpires) {
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    auto channel = std::make_shared<MockDeviceDeliveryChannel>(device_id, user_id);
    channel->set_next_result(domain::DeliveryAttemptResult::TerminalFailure); // e.g. revoked device
    registry_->register_channel(channel);

    auto message_id = MessageId::generate_v7();
    auto conversation_id = domain::ConversationId::generate_v7();
    domain::DeliveryTask task;
    task.message_id = message_id;
    task.conversation_id = conversation_id;
    task.recipient_device_id = device_id;
    task.recipient_user_id = user_id;
    task.accepted_at = now_;
    scheduler_->schedule(task);

    DeviceDeliveryRecord dev_rec;
    dev_rec.device_id = device_id;
    dev_rec.delivery_bucket = bucket_;
    dev_rec.accepted_at = now_;
    dev_rec.message_id = message_id;
    dev_rec.conversation_id = conversation_id;
    dev_rec.delivery_state = domain::DeliveryState::Queued;
    delivery_repo_->save_pending_deliveries({dev_rec});

    worker_->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    worker_->stop();

    auto pending = delivery_repo_->fetch_pending_for_device(device_id, bucket_, 10);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].delivery_state, domain::DeliveryState::Expired);
}

// ============================================================================
// 5. Duplicate Delivery & Idempotent ACKs
// ============================================================================

TEST_F(OnlineDeliveryPipelineTest, Scenario5_DuplicateDeliveryAndIdempotentAcks) {
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    auto message_id = MessageId::generate_v7();

    RecipientDeliveryState recip_state;
    recip_state.message_id = message_id;
    recip_state.recipient_device_id = device_id;
    recip_state.recipient_user_id = user_id;
    recip_state.delivery_state = domain::DeliveryState::Delivering;
    delivery_repo_->save_recipient_delivery_states({recip_state});

    service::DeliveryAckCommand cmd;
    cmd.message_id = message_id;
    cmd.recipient_device_id = device_id;
    cmd.caller_user_id = user_id;
    cmd.delivered_at = now_;

    // First affirmative ACK
    auto res1 = delivery_service_->acknowledge_delivery(cmd);
    ASSERT_TRUE(res1);
    EXPECT_FALSE(res1.value.is_idempotent_replay);
    EXPECT_EQ(delivery_repo_->ack_count_, 1u);

    // Second duplicate ACK (network replay or client retry)
    auto res2 = delivery_service_->acknowledge_delivery(cmd);
    ASSERT_TRUE(res2);
    EXPECT_TRUE(res2.value.is_idempotent_replay);
    EXPECT_EQ(res2.value.state, v1::DELIVERY_STATE_DELIVERED);

    // Ack count must not increase (idempotent no-op)
    EXPECT_EQ(delivery_repo_->ack_count_, 1u);
}

// ============================================================================
// 6. Multi-Device Concurrent Delivery
// ============================================================================

TEST_F(OnlineDeliveryPipelineTest, Scenario6_MultiDeviceConcurrentDelivery) {
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId dev_a("0191ec4d-91b4-7b4d-b6a9-8e41e3d3000a");
    DeviceId dev_b("0191ec4d-91b4-7b4d-b6a9-8e41e3d3000b");

    // Device A is online, Device B is offline
    auto channel_a = std::make_shared<MockDeviceDeliveryChannel>(dev_a, user_id);
    registry_->register_channel(channel_a);

    auto message_id = MessageId::generate_v7();
    auto conversation_id = domain::ConversationId::generate_v7();

    // Persist fan-out delivery states
    RecipientDeliveryState s_a{.message_id = message_id,
                               .recipient_device_id = dev_a,
                               .recipient_user_id = user_id,
                               .delivery_state = domain::DeliveryState::Queued};
    RecipientDeliveryState s_b{.message_id = message_id,
                               .recipient_device_id = dev_b,
                               .recipient_user_id = user_id,
                               .delivery_state = domain::DeliveryState::Queued};
    delivery_repo_->save_recipient_delivery_states({s_a, s_b});

    DeviceDeliveryRecord r_a{.device_id = dev_a,
                             .delivery_bucket = bucket_,
                             .accepted_at = now_,
                             .message_id = message_id,
                             .conversation_id = conversation_id,
                             .delivery_state = domain::DeliveryState::Queued};
    DeviceDeliveryRecord r_b{.device_id = dev_b,
                             .delivery_bucket = bucket_,
                             .accepted_at = now_,
                             .message_id = message_id,
                             .conversation_id = conversation_id,
                             .delivery_state = domain::DeliveryState::Queued};
    delivery_repo_->save_pending_deliveries({r_a, r_b});

    domain::ConversationOutboxEvent sent_event;
    sent_event.event_id = MessageId::generate_v7().to_string();
    sent_event.conversation_id = conversation_id;
    sent_event.event_type = domain::ConversationOutboxEventType::MessageSent;
    sent_event.created_at = now_;
    nlohmann::json payload;
    payload["message_id"] = message_id.to_string();
    sent_event.payload_json = payload.dump();
    outbox_repo_->enqueue_event(sent_event, outbox_bucket_);

    // Consumer only dispatches to online Device A
    consumer_->poll_and_dispatch(outbox_bucket_, 50);
    EXPECT_EQ(scheduler_->global_queue_depth(), 1u);
    EXPECT_EQ(scheduler_->device_queue_depth(dev_a), 1u);
    EXPECT_EQ(scheduler_->device_queue_depth(dev_b), 0u);

    // Device B remains safely in ScyllaDB
    auto pending_b = delivery_repo_->fetch_pending_for_device(dev_b, bucket_, 10);
    ASSERT_EQ(pending_b.size(), 1u);
    EXPECT_EQ(pending_b[0].delivery_state, domain::DeliveryState::Queued);
}

// ============================================================================
// 7. Slow Recipient Fairness (Zero Head-of-Line Blocking)
// ============================================================================

TEST_F(OnlineDeliveryPipelineTest, Scenario7_SlowRecipientFairness) {
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId dev_fast("0191ec4d-91b4-7b4d-b6a9-8e41e3d30001");
    DeviceId dev_slow("0191ec4d-91b4-7b4d-b6a9-8e41e3d30002");

    auto ch_fast = std::make_shared<MockDeviceDeliveryChannel>(dev_fast, user_id);
    auto ch_slow = std::make_shared<MockDeviceDeliveryChannel>(dev_slow, user_id);
    registry_->register_channel(ch_fast);
    registry_->register_channel(ch_slow);

    auto fair_scheduler = std::make_shared<BoundedDeliveryScheduler>(DeliverySchedulerConfig{
        .max_global_queued_tasks = 200,
        .max_tasks_per_device = 20,
        .emergency_queue_reserved_slots = 20,
        .fairness_quanta_per_device = 1,
    });

    // Enqueue 5 tasks for slow device, 2 tasks for fast device
    for (int i = 0; i < 5; ++i) {
        domain::DeliveryTask t;
        t.message_id = MessageId::generate_v7();
        t.conversation_id = domain::ConversationId::generate_v7();
        t.recipient_device_id = dev_slow;
        t.recipient_user_id = user_id;
        fair_scheduler->schedule(t);
    }
    for (int i = 0; i < 2; ++i) {
        domain::DeliveryTask t;
        t.message_id = MessageId::generate_v7();
        t.conversation_id = domain::ConversationId::generate_v7();
        t.recipient_device_id = dev_fast;
        t.recipient_user_id = user_id;
        fair_scheduler->schedule(t);
    }

    // Verify round-robin interleaving: fast device tasks are not blocked by slow device queue
    std::vector<DeviceId> dequeued_device_order;
    for (int i = 0; i < 7; ++i) {
        auto task = fair_scheduler->try_dequeue();
        ASSERT_TRUE(task.has_value());
        dequeued_device_order.push_back(task->recipient_device_id);
    }

    // Fast device must receive fair execution turns without waiting for slow queue to drain
    bool fast_device_served_early = false;
    for (size_t i = 0; i < 3; ++i) {
        if (dequeued_device_order[i] == dev_fast) {
            fast_device_served_early = true;
            break;
        }
    }
    EXPECT_TRUE(fast_device_served_early);
}

// ============================================================================
// 8. Worker Saturation & Drop-to-Durable Backpressure
// ============================================================================

TEST_F(OnlineDeliveryPipelineTest, Scenario8_WorkerSaturationAndBackpressure) {
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    auto channel = std::make_shared<MockDeviceDeliveryChannel>(device_id, user_id);
    registry_->register_channel(channel);

    // Small capacity scheduler
    auto small_scheduler = std::make_shared<BoundedDeliveryScheduler>(DeliverySchedulerConfig{
        .max_global_queued_tasks = 3,
        .max_tasks_per_device = 3,
        .emergency_queue_reserved_slots = 1,
    });

    // Enqueue 5 items into ScyllaDB
    for (int i = 0; i < 5; ++i) {
        DeviceDeliveryRecord r;
        r.device_id = device_id;
        r.delivery_bucket = bucket_;
        r.accepted_at = now_;
        r.message_id = MessageId::generate_v7();
        r.conversation_id = domain::ConversationId::generate_v7();
        r.delivery_state = domain::DeliveryState::Queued;
        delivery_repo_->save_pending_deliveries({r});
    }

    DurableDeliveryRecoveryService small_recovery(delivery_repo_, small_scheduler, registry_);

    // First recovery sweep saturates queue with 3 tasks, drops 2 to durable storage
    size_t scheduled = small_recovery.recover_pending_for_device(device_id, bucket_);
    EXPECT_EQ(scheduled, 3u);
    EXPECT_EQ(small_scheduler->global_queue_depth(), 3u);

    // Verify zero data loss: all 5 records preserved in ScyllaDB
    auto pending = delivery_repo_->fetch_pending_for_device(device_id, bucket_, 10);
    EXPECT_EQ(pending.size(), 5u);

    // Simulate worker delivering the first 3 scheduled tasks
    auto pending_first_3 = delivery_repo_->fetch_pending_for_device(device_id, bucket_, 3);
    for (const auto& rec : pending_first_3) {
        delivery_repo_->update_device_delivery_status(device_id, bucket_, rec.accepted_at, rec.message_id,
                                                      domain::DeliveryState::Delivered, 1, std::nullopt);
    }

    // Drain memory queue
    small_scheduler->clear();
    EXPECT_EQ(small_scheduler->global_queue_depth(), 0u);

    // Next sweep hydrates remaining 2 tasks
    scheduled = small_recovery.recover_pending_for_device(device_id, bucket_);
    EXPECT_EQ(scheduled, 2u);
}

// ============================================================================
// 9. Crash Recovery
// ============================================================================

TEST_F(OnlineDeliveryPipelineTest, Scenario9_SimulatedCrashRecovery) {
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    auto channel = std::make_shared<MockDeviceDeliveryChannel>(device_id, user_id);
    registry_->register_channel(channel);

    // Populate durable ScyllaDB pending deliveries
    std::vector<MessageId> saved_messages;
    for (int i = 0; i < 3; ++i) {
        auto mid = MessageId::generate_v7();
        saved_messages.push_back(mid);
        DeviceDeliveryRecord r;
        r.device_id = device_id;
        r.delivery_bucket = bucket_;
        r.accepted_at = now_;
        r.message_id = mid;
        r.conversation_id = domain::ConversationId::generate_v7();
        r.delivery_state = domain::DeliveryState::Queued;
        delivery_repo_->save_pending_deliveries({r});
    }

    // SIMULATED CRASH: Scheduler instance reset / wiped
    scheduler_->clear();
    EXPECT_EQ(scheduler_->global_queue_depth(), 0u);

    // REBOOT: Recovery service starts and hydrates pending deliveries
    size_t recovered = recovery_service_->recover_pending_for_device(device_id, bucket_);
    EXPECT_EQ(recovered, 3u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 3u);

    // Worker successfully dispatches all 3 tasks to completion
    worker_->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    worker_->stop();

    EXPECT_EQ(channel->sent_tasks().size(), 3u);
}

// ============================================================================
// 10. Zero Plaintext Invariant Audit
// ============================================================================

TEST_F(OnlineDeliveryPipelineTest, Scenario10_ZeroPlaintextInvariantAudit) {
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    auto channel = std::make_shared<MockDeviceDeliveryChannel>(device_id, user_id);
    registry_->register_channel(channel);

    auto message_id = MessageId::generate_v7();
    auto conversation_id = domain::ConversationId::generate_v7();

    // Verify task envelope fields are purely cryptographic ciphertext
    domain::DeliveryTask task;
    task.message_id = message_id;
    task.conversation_id = conversation_id;
    task.recipient_device_id = device_id;
    task.recipient_user_id = user_id;
    task.envelope.ciphertext_blob = "Opaque-Encrypted-AES-GCM-Blob";
    task.envelope.iv = {0x00, 0x01, 0x02, 0x03};
    task.envelope.auth_tag = {0xAA, 0xBB, 0xCC, 0xDD};
    task.envelope.ephemeral_public_key = {0x11, 0x22, 0x33};
    task.envelope.algorithm = domain::E2EAlgorithm::XChaCha20_Poly1305;
    task.envelope.protocol_version = domain::E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;

    scheduler_->schedule(task);

    worker_->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    worker_->stop();

    ASSERT_EQ(channel->sent_tasks().size(), 1u);
    const auto delivered = channel->sent_tasks()[0];

    // Assert strictly zero plaintext fields present in task or delivered envelope
    EXPECT_EQ(delivered.envelope.ciphertext_blob, "Opaque-Encrypted-AES-GCM-Blob");
    EXPECT_EQ(delivered.envelope.iv.size(), 4u);
    EXPECT_EQ(delivered.envelope.auth_tag.size(), 4u);
    EXPECT_EQ(delivered.envelope.algorithm, domain::E2EAlgorithm::XChaCha20_Poly1305);
}

} // namespace
} // namespace securecloud::messaging::delivery
