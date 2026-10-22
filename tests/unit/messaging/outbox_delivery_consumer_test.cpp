#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/device_connection_registry.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "delivery/outbox_delivery_consumer.hpp"
#include "domain/message_bucket.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace securecloud::messaging::delivery::test {
namespace {

using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::MessageId;
using domain::MessagePriority;
using domain::RecipientDeliveryState;
using domain::UserId;

class MockDeliveryStateRepository final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.insert(pending_.end(), records.begin(), records.end());
    }

    std::vector<DeviceDeliveryRecord> fetch_pending_for_device(const DeviceId& device_id, const std::string&,
                                                               size_t) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DeviceDeliveryRecord> result;
        for (const auto& r : pending_) {
            if (r.device_id == device_id) {
                result.push_back(r);
            }
        }
        return result;
    }

    void update_device_delivery_status(const DeviceId&, const std::string&,
                                       const std::chrono::system_clock::time_point&, const MessageId&,
                                       domain::DeliveryState, int32_t,
                                       std::optional<std::chrono::system_clock::time_point>) override {}

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

class MockOutboxRepository final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string& bucket) override {
        std::lock_guard<std::mutex> lock(mutex_);
        repository::OutboxEventRecord rec;
        rec.outbox_bucket = bucket.empty() ? repository::outbox_bucket_from_time_point(event.created_at) : bucket;
        rec.created_at = event.created_at;
        rec.event_id = event.event_id;
        rec.conversation_id = event.conversation_id;
        rec.event_type = to_string(event.event_type);
        rec.payload_json = event.payload_json;
        rec.publish_status = repository::OutboxPublishStatus::Pending;
        records_.push_back(rec);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string& outbox_bucket,
                                                                    size_t limit) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<repository::OutboxEventRecord> result;
        for (const auto& r : records_) {
            if (r.outbox_bucket == outbox_bucket && r.publish_status == repository::OutboxPublishStatus::Pending) {
                result.push_back(r);
                if (result.size() >= limit) {
                    break;
                }
            }
        }
        return result;
    }

    void mark_event_published(const std::string& outbox_bucket, std::chrono::system_clock::time_point created_at,
                              const std::string& event_id,
                              std::chrono::system_clock::time_point published_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& r : records_) {
            if (r.outbox_bucket == outbox_bucket && r.created_at == created_at && r.event_id == event_id) {
                r.publish_status = repository::OutboxPublishStatus::Published;
                r.published_at = published_at;
                published_count_++;
                break;
            }
        }
    }

    std::mutex mutex_;
    std::vector<repository::OutboxEventRecord> records_;
    size_t published_count_{0};
};

// ============================================================================
// OutboxDeliveryConsumer Test Suite
// ============================================================================

class OutboxDeliveryConsumerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        scheduler_ = std::make_shared<BoundedDeliveryScheduler>();
        connection_registry_ = std::make_shared<DeviceConnectionRegistry>();
        delivery_repo_ = std::make_shared<MockDeliveryStateRepository>();
        outbox_repo_ = std::make_shared<MockOutboxRepository>();

        consumer_ =
            std::make_unique<OutboxDeliveryConsumer>(outbox_repo_, delivery_repo_, connection_registry_, scheduler_);
    }

    std::shared_ptr<BoundedDeliveryScheduler> scheduler_;
    std::shared_ptr<DeviceConnectionRegistry> connection_registry_;
    std::shared_ptr<MockDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<MockOutboxRepository> outbox_repo_;
    std::unique_ptr<OutboxDeliveryConsumer> consumer_;
};

TEST_F(OutboxDeliveryConsumerTest, DispatchesEnvelopesOnlyToConnectedOnlineDevices) {
    const auto conv_id = ConversationId::generate_v7();
    const auto msg_id = MessageId::generate_v7();
    const auto dev_a = DeviceId("dev-a");
    const auto dev_b = DeviceId("dev-b");
    const auto user_a = UserId("user-a");
    const auto user_b = UserId("user-b");
    const auto now = std::chrono::system_clock::now();
    const auto outbox_bucket = repository::outbox_bucket_from_time_point(now);
    const auto delivery_bucket = domain::MessageBucket::from_time_point(now).value();

    // Device A is registered (online), Device B is NOT (offline)
    auto channel_a = std::make_shared<MockDeviceDeliveryChannel>(dev_a, user_a);
    connection_registry_->register_channel(channel_a);

    // Save recipient states
    RecipientDeliveryState state_a;
    state_a.message_id = msg_id;
    state_a.recipient_device_id = dev_a;
    state_a.recipient_user_id = user_a;
    RecipientDeliveryState state_b;
    state_b.message_id = msg_id;
    state_b.recipient_device_id = dev_b;
    state_b.recipient_user_id = user_b;
    delivery_repo_->save_recipient_delivery_states({state_a, state_b});

    // Save pending device delivery records with encrypted payload
    DeviceDeliveryRecord rec_a;
    rec_a.device_id = dev_a;
    rec_a.delivery_bucket = delivery_bucket;
    rec_a.accepted_at = now;
    rec_a.message_id = msg_id;
    rec_a.conversation_id = conv_id;
    rec_a.ciphertext_blob = "ciphertext-a";

    DeviceDeliveryRecord rec_b;
    rec_b.device_id = dev_b;
    rec_b.delivery_bucket = delivery_bucket;
    rec_b.accepted_at = now;
    rec_b.message_id = msg_id;
    rec_b.conversation_id = conv_id;
    rec_b.ciphertext_blob = "ciphertext-b";
    delivery_repo_->save_pending_deliveries({rec_a, rec_b});

    // Enqueue MessageSent outbox event
    ConversationOutboxEvent event;
    event.event_id = MessageId::generate_v7().to_string();
    event.conversation_id = conv_id;
    event.event_type = domain::ConversationOutboxEventType::MessageSent;
    event.created_at = now;
    std::ostringstream ss;
    ss << "{\"message_id\":\"" << msg_id.to_string() << "\","
       << "\"sequence\":1,"
       << "\"sender_user_id\":\"sender-1\","
       << "\"sender_device_id\":\"dev-0\","
       << "\"recipient_device_count\":2}";
    event.payload_json = ss.str();
    outbox_repo_->enqueue_event(event, outbox_bucket);

    // Process outbox events
    const size_t processed = consumer_->poll_and_dispatch(outbox_bucket, 10);
    EXPECT_EQ(processed, 1u);

    // Only online Device A should be enqueued into scheduler!
    EXPECT_EQ(scheduler_->global_queue_depth(), 1u);
    EXPECT_EQ(scheduler_->device_queue_depth(dev_a), 1u);
    EXPECT_EQ(scheduler_->device_queue_depth(dev_b), 0u);

    // Outbox event was marked published
    EXPECT_EQ(outbox_repo_->published_count_, 1u);
}

TEST_F(OutboxDeliveryConsumerTest, AppliesDropToDurableBackpressureUnderQueueSaturation) {
    DeliverySchedulerConfig sat_cfg;
    sat_cfg.max_global_queued_tasks = 1;
    sat_cfg.max_tasks_per_device = 1;
    auto saturated_scheduler = std::make_shared<BoundedDeliveryScheduler>(sat_cfg);

    auto sat_consumer = std::make_unique<OutboxDeliveryConsumer>(outbox_repo_, delivery_repo_, connection_registry_,
                                                                 saturated_scheduler);

    const auto dev = DeviceId("dev-1");
    const auto user = UserId("user-1");
    auto channel = std::make_shared<MockDeviceDeliveryChannel>(dev, user);
    connection_registry_->register_channel(channel);

    // Fill the scheduler to capacity
    domain::DeliveryTask dummy_task;
    dummy_task.message_id = MessageId::generate_v7();
    dummy_task.conversation_id = ConversationId::generate_v7();
    dummy_task.recipient_device_id = dev;
    dummy_task.priority = MessagePriority::Normal;
    EXPECT_EQ(saturated_scheduler->schedule(dummy_task), SchedulerStatus::Enqueued);
    EXPECT_EQ(saturated_scheduler->global_queue_depth(), 1u);

    // New event comes in for the same device
    const auto conv_id = ConversationId::generate_v7();
    const auto msg_id = MessageId::generate_v7();
    const auto now = std::chrono::system_clock::now();
    const auto outbox_bucket = repository::outbox_bucket_from_time_point(now);
    const auto delivery_bucket = domain::MessageBucket::from_time_point(now).value();

    RecipientDeliveryState state;
    state.message_id = msg_id;
    state.recipient_device_id = dev;
    state.recipient_user_id = user;
    delivery_repo_->save_recipient_delivery_states({state});

    DeviceDeliveryRecord rec;
    rec.device_id = dev;
    rec.delivery_bucket = delivery_bucket;
    rec.accepted_at = now;
    rec.message_id = msg_id;
    rec.conversation_id = conv_id;
    rec.ciphertext_blob = "overflow-ciphertext";
    delivery_repo_->save_pending_deliveries({rec});

    ConversationOutboxEvent event;
    event.event_id = MessageId::generate_v7().to_string();
    event.conversation_id = conv_id;
    event.event_type = domain::ConversationOutboxEventType::MessageSent;
    event.created_at = now;
    std::ostringstream ss;
    ss << "{\"message_id\":\"" << msg_id.to_string() << "\"}";
    event.payload_json = ss.str();
    outbox_repo_->enqueue_event(event, outbox_bucket);

    // Poll and dispatch: must handle queue full cleanly without throwing
    const size_t processed = sat_consumer->poll_and_dispatch(outbox_bucket, 10);
    EXPECT_EQ(processed, 1u);

    // Saturated scheduler did not exceed its bound
    EXPECT_EQ(saturated_scheduler->global_queue_depth(), 1u);
    // Outbox event was marked published (durable recovery will pick up the un-enqueued message)
    EXPECT_EQ(outbox_repo_->published_count_, 1u);
}

TEST_F(OutboxDeliveryConsumerTest, IgnoresNonMessageSentOutboxEvents) {
    const auto now = std::chrono::system_clock::now();
    const auto outbox_bucket = repository::outbox_bucket_from_time_point(now);

    ConversationOutboxEvent event;
    event.event_id = MessageId::generate_v7().to_string();
    event.conversation_id = ConversationId::generate_v7();
    event.event_type = domain::ConversationOutboxEventType::ConversationCreated;
    event.created_at = now;
    event.payload_json = "{}";
    outbox_repo_->enqueue_event(event, outbox_bucket);

    const size_t processed = consumer_->poll_and_dispatch(outbox_bucket, 10);
    EXPECT_EQ(processed, 0u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 0u);
    EXPECT_EQ(outbox_repo_->published_count_, 0u);
}

TEST_F(OutboxDeliveryConsumerTest, MalformedPayloadDoesNotCrashAndIsDiscarded) {
    const auto now = std::chrono::system_clock::now();
    const auto outbox_bucket = repository::outbox_bucket_from_time_point(now);

    ConversationOutboxEvent event;
    event.event_id = MessageId::generate_v7().to_string();
    event.conversation_id = ConversationId::generate_v7();
    event.event_type = domain::ConversationOutboxEventType::MessageSent;
    event.created_at = now;
    event.payload_json = "invalid-non-json{{{";
    outbox_repo_->enqueue_event(event, outbox_bucket);

    const size_t processed = consumer_->poll_and_dispatch(outbox_bucket, 10);
    EXPECT_EQ(processed, 0u);
    EXPECT_EQ(scheduler_->global_queue_depth(), 0u);
    // Malformed event marked published so it does not block the queue
    EXPECT_EQ(outbox_repo_->published_count_, 1u);
}

} // namespace
} // namespace securecloud::messaging::delivery::test
