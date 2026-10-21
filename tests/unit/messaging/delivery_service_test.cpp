#include "concurrency/bounded_worker_pool.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/outbox_event.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "service/delivery_service.hpp"
#include "service/messaging_service_impl.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <vector>

namespace securecloud::messaging::service {
namespace {

using domain::DeviceId;
using domain::MessageId;
using domain::RecipientDeliveryState;
using domain::UserId;

class MockDeliveryStateRepo final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<domain::DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.insert(pending_.end(), records.begin(), records.end());
    }

    std::vector<domain::DeviceDeliveryRecord>
    fetch_pending_for_device(const DeviceId& device_id, const std::string& delivery_bucket, size_t) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<domain::DeviceDeliveryRecord> result;
        for (const auto& rec : pending_) {
            if (rec.device_id == device_id && rec.delivery_bucket == delivery_bucket) {
                result.push_back(rec);
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
        recorded_acks_.push_back({message_id, recipient_device_id, delivered_at});
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

    struct AckEntry {
        MessageId message_id;
        DeviceId device_id;
        std::chrono::system_clock::time_point delivered_at;
    };

    std::mutex mutex_;
    std::vector<domain::DeviceDeliveryRecord> pending_;
    std::vector<RecipientDeliveryState> recipient_states_;
    std::vector<AckEntry> recorded_acks_;
};

class MockOutboxRepo final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const domain::ConversationOutboxEvent& event, const std::string&) override {
        std::lock_guard<std::mutex> lock(mutex_);
        enqueued_events_.push_back(event);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }

    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

    std::mutex mutex_;
    std::vector<domain::ConversationOutboxEvent> enqueued_events_;
};

class DeliveryServiceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        delivery_repo_ = std::make_shared<MockDeliveryStateRepo>();
        outbox_repo_ = std::make_shared<MockOutboxRepo>();
        service_ = std::make_unique<DeliveryService>(delivery_repo_, outbox_repo_);

        user_id_ = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        device_id_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
        message_id_ = MessageId::generate_v7();
        conversation_id_ = domain::ConversationId::generate_v7();
    }

    std::shared_ptr<MockDeliveryStateRepo> delivery_repo_;
    std::shared_ptr<MockOutboxRepo> outbox_repo_;
    std::unique_ptr<DeliveryService> service_;

    UserId user_id_;
    DeviceId device_id_;
    MessageId message_id_;
    domain::ConversationId conversation_id_;
};

TEST_F(DeliveryServiceTest, AcknowledgeDeliverySuccess) {
    // Setup initial recipient delivery state in repo
    RecipientDeliveryState initial_state;
    initial_state.message_id = message_id_;
    initial_state.recipient_device_id = device_id_;
    initial_state.recipient_user_id = user_id_;
    initial_state.delivery_state = domain::DeliveryState::Delivering;
    delivery_repo_->save_recipient_delivery_states({initial_state});

    // Setup active pending record
    const auto accepted_at = std::chrono::system_clock::now();
    const auto bucket = domain::MessageBucket::from_time_point(accepted_at).value();
    domain::DeviceDeliveryRecord pending_rec;
    pending_rec.device_id = device_id_;
    pending_rec.delivery_bucket = bucket;
    pending_rec.accepted_at = accepted_at;
    pending_rec.message_id = message_id_;
    pending_rec.conversation_id = conversation_id_;
    pending_rec.delivery_state = domain::DeliveryState::Delivering;
    delivery_repo_->save_pending_deliveries({pending_rec});

    DeliveryAckCommand cmd;
    cmd.message_id = message_id_;
    cmd.recipient_device_id = device_id_;
    cmd.caller_user_id = user_id_;
    cmd.delivered_at = accepted_at;
    cmd.conversation_id = conversation_id_;

    auto result = service_->acknowledge_delivery(cmd);

    ASSERT_TRUE(result);
    EXPECT_EQ(result.value.message_id, message_id_);
    EXPECT_EQ(result.value.state, v1::DELIVERY_STATE_DELIVERED);
    EXPECT_FALSE(result.value.is_idempotent_replay);

    // Verify ScyllaDB delivery ack was committed
    ASSERT_EQ(delivery_repo_->recorded_acks_.size(), 1u);
    EXPECT_EQ(delivery_repo_->recorded_acks_[0].message_id, message_id_);
    EXPECT_EQ(delivery_repo_->recorded_acks_[0].device_id, device_id_);

    // Verify pending record status updated to DELIVERED
    auto pending_updated = delivery_repo_->fetch_pending_for_device(device_id_, bucket, 10);
    ASSERT_EQ(pending_updated.size(), 1u);
    EXPECT_EQ(pending_updated[0].delivery_state, domain::DeliveryState::Delivered);

    // Verify MessageDelivered outbox event published
    ASSERT_EQ(outbox_repo_->enqueued_events_.size(), 1u);
    const auto& event = outbox_repo_->enqueued_events_[0];
    EXPECT_EQ(event.conversation_id, conversation_id_);
    EXPECT_EQ(event.event_type, domain::ConversationOutboxEventType::MessageDelivered);

    auto payload = nlohmann::json::parse(event.payload_json);
    EXPECT_EQ(payload["message_id"], message_id_.to_string());
    EXPECT_EQ(payload["recipient_device_id"], device_id_.str());
    EXPECT_EQ(payload["recipient_user_id"], user_id_.str());
}

TEST_F(DeliveryServiceTest, AcknowledgeDeliveryIdempotentWhenAlreadyDelivered) {
    const auto delivered_time = std::chrono::system_clock::now();
    RecipientDeliveryState delivered_state;
    delivered_state.message_id = message_id_;
    delivered_state.recipient_device_id = device_id_;
    delivered_state.recipient_user_id = user_id_;
    delivered_state.delivery_state = domain::DeliveryState::Delivered;
    delivered_state.delivered_at = delivered_time;
    delivery_repo_->save_recipient_delivery_states({delivered_state});

    DeliveryAckCommand cmd;
    cmd.message_id = message_id_;
    cmd.recipient_device_id = device_id_;
    cmd.caller_user_id = user_id_;
    cmd.delivered_at = delivered_time;

    auto result = service_->acknowledge_delivery(cmd);

    ASSERT_TRUE(result);
    EXPECT_EQ(result.value.message_id, message_id_);
    EXPECT_EQ(result.value.state, v1::DELIVERY_STATE_DELIVERED);
    EXPECT_TRUE(result.value.is_idempotent_replay);

    // Zero redundant ack recordings and zero new outbox events
    EXPECT_EQ(delivery_repo_->recorded_acks_.size(), 0u);
    EXPECT_EQ(outbox_repo_->enqueued_events_.size(), 0u);
}

TEST_F(DeliveryServiceTest, AcknowledgeDeliveryIdempotentWhenAlreadyRead) {
    const auto read_time = std::chrono::system_clock::now();
    RecipientDeliveryState read_state;
    read_state.message_id = message_id_;
    read_state.recipient_device_id = device_id_;
    read_state.recipient_user_id = user_id_;
    read_state.delivery_state = domain::DeliveryState::Read;
    read_state.read_at = read_time;
    delivery_repo_->save_recipient_delivery_states({read_state});

    DeliveryAckCommand cmd;
    cmd.message_id = message_id_;
    cmd.recipient_device_id = device_id_;
    cmd.caller_user_id = user_id_;
    cmd.delivered_at = read_time;

    auto result = service_->acknowledge_delivery(cmd);

    ASSERT_TRUE(result);
    EXPECT_EQ(result.value.message_id, message_id_);
    EXPECT_EQ(result.value.state, v1::DELIVERY_STATE_READ);
    EXPECT_TRUE(result.value.is_idempotent_replay);
    EXPECT_EQ(delivery_repo_->recorded_acks_.size(), 0u);
}

TEST_F(DeliveryServiceTest, AcknowledgeDeliveryFailsWhenDeviceNotFound) {
    // Empty repository: message not dispatched to this device
    DeliveryAckCommand cmd;
    cmd.message_id = message_id_;
    cmd.recipient_device_id = device_id_;
    cmd.caller_user_id = user_id_;

    auto result = service_->acknowledge_delivery(cmd);

    EXPECT_FALSE(result);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
}

TEST_F(DeliveryServiceTest, AcknowledgeDeliveryFailsWhenCallerNotRecipient) {
    RecipientDeliveryState state;
    state.message_id = message_id_;
    state.recipient_device_id = device_id_;
    state.recipient_user_id = user_id_;
    state.delivery_state = domain::DeliveryState::Delivering;
    delivery_repo_->save_recipient_delivery_states({state});

    // Different user attempts to ACK
    auto other_user = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    DeliveryAckCommand cmd;
    cmd.message_id = message_id_;
    cmd.recipient_device_id = device_id_;
    cmd.caller_user_id = other_user;

    auto result = service_->acknowledge_delivery(cmd);

    EXPECT_FALSE(result);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);
}

TEST_F(DeliveryServiceTest, AcknowledgeDeliveryFailsWhenExpired) {
    RecipientDeliveryState state;
    state.message_id = message_id_;
    state.recipient_device_id = device_id_;
    state.recipient_user_id = user_id_;
    state.delivery_state = domain::DeliveryState::Expired;
    delivery_repo_->save_recipient_delivery_states({state});

    DeliveryAckCommand cmd;
    cmd.message_id = message_id_;
    cmd.recipient_device_id = device_id_;
    cmd.caller_user_id = user_id_;

    auto result = service_->acknowledge_delivery(cmd);

    EXPECT_FALSE(result);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED);
}

TEST_F(DeliveryServiceTest, AcknowledgeDeliveryFailsOnEmptyDeviceId) {
    DeliveryAckCommand cmd;
    cmd.message_id = message_id_;
    cmd.recipient_device_id = DeviceId("");
    cmd.caller_user_id = user_id_;

    auto result = service_->acknowledge_delivery(cmd);

    EXPECT_FALSE(result);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
}

// ============================================================================
// In-Process gRPC Server Integration Test for AcknowledgeDelivery
// ============================================================================

class InProcessDeliveryAckGrpcTest : public ::testing::Test {
  protected:
    void SetUp() override {
        delivery_repo_ = std::make_shared<MockDeliveryStateRepo>();
        outbox_repo_ = std::make_shared<MockOutboxRepo>();
        delivery_service_ = std::make_shared<DeliveryService>(delivery_repo_, outbox_repo_);

        delivery_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(2, 16, "test_deliv");

        service_impl_ = std::make_unique<MessagingServiceImpl>(nullptr, delivery_pool_, nullptr, nullptr, nullptr,
                                                               delivery_service_);

        grpc::ServerBuilder builder;
        builder.RegisterService(service_impl_.get());
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);

        channel_ = server_->InProcessChannel(grpc::ChannelArguments{});
        ASSERT_NE(channel_, nullptr);
        stub_ = v1::MessagingService::NewStub(channel_);
        ASSERT_NE(stub_, nullptr);
    }

    void TearDown() override {
        if (delivery_pool_) {
            delivery_pool_->shutdown();
        }
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    std::shared_ptr<MockDeliveryStateRepo> delivery_repo_;
    std::shared_ptr<MockOutboxRepo> outbox_repo_;
    std::shared_ptr<DeliveryService> delivery_service_;
    std::shared_ptr<concurrency::BoundedWorkerPool> delivery_pool_;
    std::unique_ptr<MessagingServiceImpl> service_impl_;
    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::MessagingService::Stub> stub_;
};

TEST_F(InProcessDeliveryAckGrpcTest, EndToEndDeliveryAckRpcSuccess) {
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    auto message_id = MessageId::generate_v7();

    RecipientDeliveryState state;
    state.message_id = message_id;
    state.recipient_device_id = device_id;
    state.recipient_user_id = user_id;
    state.delivery_state = domain::DeliveryState::Delivering;
    delivery_repo_->save_recipient_delivery_states({state});

    grpc::ClientContext context;
    context.AddMetadata("x-user-id", user_id.str());
    context.AddMetadata("x-device-id", device_id.str());
    context.AddMetadata("x-correlation-id", "corr-ack-test-01");

    v1::AcknowledgeDeliveryRequest request;
    request.set_message_id(message_id.to_string());
    request.set_recipient_device_id(device_id.str());
    request.set_delivered_at_unix_ms(1760000000000);

    v1::AcknowledgeDeliveryResponse response;
    auto status = stub_->AcknowledgeDelivery(&context, request, &response);

    ASSERT_TRUE(status.ok()) << "gRPC error: " << status.error_message();
    EXPECT_EQ(response.message_id(), message_id.to_string());
    EXPECT_EQ(response.state(), v1::DELIVERY_STATE_DELIVERED);
    EXPECT_EQ(response.recorded_at_unix_ms(), 1760000000000);
}

} // namespace
} // namespace securecloud::messaging::service
