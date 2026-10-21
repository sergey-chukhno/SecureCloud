#include "concurrency/bounded_worker_pool.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/delivery_types.hpp"
#include "domain/outbox_event.hpp"
#include "domain/read_receipt_types.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/membership_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "service/messaging_service_impl.hpp"
#include "service/read_receipt_service.hpp"

#include <chrono>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::service::test {
namespace {

using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationParticipantEntity;
using domain::DeliveryState;
using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::MembershipStatus;
using domain::MessageDeliverySummary;
using domain::MessageId;
using domain::ParticipantRole;
using domain::ReadState;
using domain::RecipientDeliveryState;
using domain::UserId;

// ============================================================================
// Mocks
// ============================================================================

class MockDeliveryStateRepo final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>&) override {}

    std::vector<DeviceDeliveryRecord> fetch_pending_for_device(const DeviceId&, const std::string&, size_t) override {
        return {};
    }

    void update_device_delivery_status(const DeviceId&, const std::string&,
                                       const std::chrono::system_clock::time_point&, const MessageId&, DeliveryState,
                                       int32_t, std::optional<std::chrono::system_clock::time_point>) override {}

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& state : states) {
            recipient_states_[state.message_id].push_back(state);
        }
    }

    void record_delivery_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point& delivered_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = recipient_states_.find(message_id);
        if (it != recipient_states_.end()) {
            for (auto& s : it->second) {
                if (s.recipient_device_id == recipient_device_id) {
                    s.delivery_state = DeliveryState::Delivered;
                    s.delivered_at = delivered_at;
                    break;
                }
            }
        }
    }

    void record_read_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                         const std::chrono::system_clock::time_point& read_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        read_acks_count_++;
        auto it = recipient_states_.find(message_id);
        if (it != recipient_states_.end()) {
            for (auto& s : it->second) {
                if (s.recipient_device_id == recipient_device_id) {
                    s.read_at = read_at;
                    break;
                }
            }
        }
    }

    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = recipient_states_.find(message_id);
        if (it != recipient_states_.end()) {
            return it->second;
        }
        return {};
    }

    std::optional<MessageDeliverySummary> get_message_delivery_summary(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = recipient_states_.find(message_id);
        if (it == recipient_states_.end()) {
            return std::nullopt;
        }

        MessageDeliverySummary summary;
        summary.message_id = message_id;
        std::map<UserId, domain::LogicalRecipientReadStatus> read_map;

        for (const auto& s : it->second) {
            summary.total_targets++;
            if (s.delivery_state == DeliveryState::Delivered) {
                summary.delivered_targets++;
            } else if (s.delivery_state == DeliveryState::Expired) {
                summary.expired_targets++;
            } else {
                summary.pending_targets++;
            }

            domain::DeviceDeliveryStatus dev;
            dev.device_id = s.recipient_device_id;
            dev.recipient_user_id = s.recipient_user_id;
            dev.delivery_state = s.delivery_state;
            dev.delivered_at = s.delivered_at;
            summary.device_statuses.push_back(dev);

            auto& u = read_map[s.recipient_user_id];
            u.user_id = s.recipient_user_id;
            if (s.read_at.has_value()) {
                u.read_state = domain::ReadState::Read;
                u.read_at = s.read_at;
                u.reader_device_id = s.recipient_device_id;
            } else if (u.read_state != domain::ReadState::Read) {
                u.read_state = domain::ReadState::Unread;
            }
        }

        for (auto& [_, st] : read_map) {
            summary.recipient_read_statuses.push_back(st);
        }
        return summary;
    }

    size_t read_acks_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return read_acks_count_;
    }

  private:
    mutable std::mutex mutex_;
    std::unordered_map<MessageId, std::vector<RecipientDeliveryState>> recipient_states_;
    size_t read_acks_count_{0};
};

class MockMembershipRepo final : public repository::IMembershipRepository {
  public:
    void add_participant(const ConversationParticipantEntity& participant) override {
        std::lock_guard<std::mutex> lock(mutex_);
        participants_[participant.conversation_id][participant.user_id] = participant;
    }

    void update_participant(const ConversationParticipantEntity& participant) override {
        std::lock_guard<std::mutex> lock(mutex_);
        participants_[participant.conversation_id][participant.user_id] = participant;
    }

    std::optional<ConversationParticipantEntity> find_participant(const ConversationId& conv_id,
                                                                  const UserId& user_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto conv_it = participants_.find(conv_id);
        if (conv_it != participants_.end()) {
            auto user_it = conv_it->second.find(user_id);
            if (user_it != conv_it->second.end()) {
                return user_it->second;
            }
        }
        return std::nullopt;
    }

    std::vector<ConversationParticipantEntity> list_participants(const ConversationId& conv_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ConversationParticipantEntity> result;
        auto conv_it = participants_.find(conv_id);
        if (conv_it != participants_.end()) {
            for (const auto& [_, p] : conv_it->second) {
                result.push_back(p);
            }
        }
        return result;
    }

    std::vector<ConversationParticipantEntity> list_active_participants(const ConversationId& conv_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ConversationParticipantEntity> result;
        auto conv_it = participants_.find(conv_id);
        if (conv_it != participants_.end()) {
            for (const auto& [_, p] : conv_it->second) {
                if (p.status == MembershipStatus::Active) {
                    result.push_back(p);
                }
            }
        }
        return result;
    }

    void touch_user_conversation(const UserId&, const ConversationId&, domain::ConversationType, MembershipStatus,
                                 std::chrono::system_clock::time_point) override {}

    repository::UserConversationsPage list_user_conversations(const UserId&, int,
                                                              const std::optional<std::string>&) override {
        return {};
    }

  private:
    mutable std::mutex mutex_;
    std::unordered_map<ConversationId, std::unordered_map<UserId, ConversationParticipantEntity>> participants_;
};

class MockOutboxRepo final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string& = "") override {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.push_back(event);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }

    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

    size_t event_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return events_.size();
    }

  private:
    mutable std::mutex mutex_;
    std::vector<ConversationOutboxEvent> events_;
};

// ============================================================================
// In-Process gRPC Test Fixture
// ============================================================================

class MessagingDeliveryStateGrpcTest : public ::testing::Test {
  protected:
    void SetUp() override {
        delivery_repo_ = std::make_shared<MockDeliveryStateRepo>();
        membership_repo_ = std::make_shared<MockMembershipRepo>();
        outbox_repo_ = std::make_shared<MockOutboxRepo>();

        auto device_checker = [](const DeviceId& id) { return id.str() != "0191ec4d-91b4-7b4d-b6a9-8e41e3d36fee"; };

        read_receipt_service_ =
            std::make_shared<ReadReceiptService>(delivery_repo_, membership_repo_, outbox_repo_, device_checker);

        delivery_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(2, 16, "test_pool");

        service_impl_ = std::make_unique<MessagingServiceImpl>(nullptr, delivery_pool_, nullptr, nullptr, nullptr,
                                                               nullptr, read_receipt_service_);

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
    std::shared_ptr<MockMembershipRepo> membership_repo_;
    std::shared_ptr<MockOutboxRepo> outbox_repo_;
    std::shared_ptr<ReadReceiptService> read_receipt_service_;
    std::shared_ptr<concurrency::BoundedWorkerPool> delivery_pool_;
    std::unique_ptr<MessagingServiceImpl> service_impl_;
    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::MessagingService::Stub> stub_;
};

// ============================================================================
// SendReadReceipt Tests
// ============================================================================

TEST_F(MessagingDeliveryStateGrpcTest, SendReadReceiptRpc_Success) {
    auto conv_id = ConversationId::generate_v7();
    auto msg_id = MessageId::generate_v7();
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");

    // 1. Setup conversation membership
    ConversationParticipantEntity participant;
    participant.conversation_id = conv_id;
    participant.user_id = user_id;
    participant.status = MembershipStatus::Active;
    participant.role = ParticipantRole::Member;
    membership_repo_->add_participant(participant);

    // 2. Setup delivery state in repository
    RecipientDeliveryState state;
    state.message_id = msg_id;
    state.recipient_device_id = device_id;
    state.recipient_user_id = user_id;
    state.delivery_state = DeliveryState::Delivered;
    delivery_repo_->save_recipient_delivery_states({state});

    // 3. Make gRPC call
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", user_id.str());
    context.AddMetadata("x-device-id", device_id.str());
    context.AddMetadata("x-correlation-id", "corr-rr-01");

    v1::SendReadReceiptRequest request;
    request.set_conversation_id(conv_id.to_string());
    request.set_message_id(msg_id.to_string());
    request.set_reader_device_id(device_id.str());
    request.set_read_at_unix_ms(1760000000000);

    v1::SendReadReceiptResponse response;
    auto status = stub_->SendReadReceipt(&context, request, &response);

    ASSERT_TRUE(status.ok()) << "gRPC error: " << status.error_message();
    EXPECT_EQ(response.message_id(), msg_id.to_string());
    EXPECT_EQ(response.state(), v1::DELIVERY_STATE_READ);
    EXPECT_EQ(response.recorded_at_unix_ms(), 1760000000000);
    EXPECT_EQ(delivery_repo_->read_acks_count(), 1U);
    EXPECT_EQ(outbox_repo_->event_count(), 1U);
}

TEST_F(MessagingDeliveryStateGrpcTest, SendReadReceiptRpc_IdempotentReplay) {
    auto conv_id = ConversationId::generate_v7();
    auto msg_id = MessageId::generate_v7();
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");

    ConversationParticipantEntity participant;
    participant.conversation_id = conv_id;
    participant.user_id = user_id;
    participant.status = MembershipStatus::Active;
    membership_repo_->add_participant(participant);

    // Already marked read
    auto original_time = std::chrono::system_clock::time_point(std::chrono::milliseconds(1760000000000));
    RecipientDeliveryState state;
    state.message_id = msg_id;
    state.recipient_device_id = device_id;
    state.recipient_user_id = user_id;
    state.delivery_state = DeliveryState::Read;
    state.read_at = original_time;
    delivery_repo_->save_recipient_delivery_states({state});

    grpc::ClientContext context;
    context.AddMetadata("x-user-id", user_id.str());
    context.AddMetadata("x-device-id", device_id.str());

    v1::SendReadReceiptRequest request;
    request.set_conversation_id(conv_id.to_string());
    request.set_message_id(msg_id.to_string());
    request.set_reader_device_id(device_id.str());
    request.set_read_at_unix_ms(1760000099999); // Candidate timestamp

    v1::SendReadReceiptResponse response;
    auto status = stub_->SendReadReceipt(&context, request, &response);

    ASSERT_TRUE(status.ok());
    EXPECT_EQ(response.state(), v1::DELIVERY_STATE_READ);
    // Returns original recorded timestamp idempotently
    EXPECT_EQ(response.recorded_at_unix_ms(), 1760000000000);
    EXPECT_EQ(delivery_repo_->read_acks_count(), 0U);
    EXPECT_EQ(outbox_repo_->event_count(), 0U);
}

TEST_F(MessagingDeliveryStateGrpcTest, SendReadReceiptRpc_ImpersonationRejected) {
    auto conv_id = ConversationId::generate_v7();
    auto msg_id = MessageId::generate_v7();
    auto user_alice = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    auto user_bob = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    DeviceId dev_bob("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");

    ConversationParticipantEntity part_alice;
    part_alice.conversation_id = conv_id;
    part_alice.user_id = user_alice;
    part_alice.status = MembershipStatus::Active;
    membership_repo_->add_participant(part_alice);

    RecipientDeliveryState state;
    state.message_id = msg_id;
    state.recipient_device_id = dev_bob;
    state.recipient_user_id = user_bob;
    state.delivery_state = DeliveryState::Delivered;
    delivery_repo_->save_recipient_delivery_states({state});

    // Alice attempts to mark read for Bob's device
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", user_alice.str());
    context.AddMetadata("x-device-id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36004");

    v1::SendReadReceiptRequest request;
    request.set_conversation_id(conv_id.to_string());
    request.set_message_id(msg_id.to_string());
    request.set_reader_device_id(dev_bob.str());

    v1::SendReadReceiptResponse response;
    auto status = stub_->SendReadReceipt(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(MessagingDeliveryStateGrpcTest, SendReadReceiptRpc_RevokedDeviceRejected) {
    auto conv_id = ConversationId::generate_v7();
    auto msg_id = MessageId::generate_v7();
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId dev_revoked("0191ec4d-91b4-7b4d-b6a9-8e41e3d36fee");

    ConversationParticipantEntity participant;
    participant.conversation_id = conv_id;
    participant.user_id = user_id;
    participant.status = MembershipStatus::Active;
    membership_repo_->add_participant(participant);

    RecipientDeliveryState state;
    state.message_id = msg_id;
    state.recipient_device_id = dev_revoked;
    state.recipient_user_id = user_id;
    state.delivery_state = DeliveryState::Delivered;
    delivery_repo_->save_recipient_delivery_states({state});

    grpc::ClientContext context;
    context.AddMetadata("x-user-id", user_id.str());
    context.AddMetadata("x-device-id", dev_revoked.str());

    v1::SendReadReceiptRequest request;
    request.set_conversation_id(conv_id.to_string());
    request.set_message_id(msg_id.to_string());
    request.set_reader_device_id(dev_revoked.str());

    v1::SendReadReceiptResponse response;
    auto status = stub_->SendReadReceipt(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(MessagingDeliveryStateGrpcTest, SendReadReceiptRpc_NonParticipantRejected) {
    auto conv_id = ConversationId::generate_v7();
    auto msg_id = MessageId::generate_v7();
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    DeviceId dev_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");

    // Do NOT add user_id to conversation participants

    grpc::ClientContext context;
    context.AddMetadata("x-user-id", user_id.str());
    context.AddMetadata("x-device-id", dev_id.str());

    v1::SendReadReceiptRequest request;
    request.set_conversation_id(conv_id.to_string());
    request.set_message_id(msg_id.to_string());
    request.set_reader_device_id(dev_id.str());

    v1::SendReadReceiptResponse response;
    auto status = stub_->SendReadReceipt(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

// ============================================================================
// GetMessageDeliveryStatus Tests
// ============================================================================

TEST_F(MessagingDeliveryStateGrpcTest, GetMessageDeliveryStatusRpc_SuccessMultiDevice) {
    auto conv_id = ConversationId::generate_v7();
    auto msg_id = MessageId::generate_v7();
    auto user_alice = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    auto user_bob = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");

    DeviceId dev_bob_phone("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    DeviceId dev_bob_laptop("0191ec4d-91b4-7b4d-b6a9-8e41e3d36004");

    // Alice and Bob are participants
    ConversationParticipantEntity p_alice;
    p_alice.conversation_id = conv_id;
    p_alice.user_id = user_alice;
    p_alice.status = MembershipStatus::Active;
    membership_repo_->add_participant(p_alice);

    ConversationParticipantEntity p_bob;
    p_bob.conversation_id = conv_id;
    p_bob.user_id = user_bob;
    p_bob.status = MembershipStatus::Active;
    membership_repo_->add_participant(p_bob);

    // Message delivered and read on Bob's phone, still queued on Bob's laptop
    auto now = std::chrono::system_clock::now();
    RecipientDeliveryState s_phone;
    s_phone.message_id = msg_id;
    s_phone.recipient_device_id = dev_bob_phone;
    s_phone.recipient_user_id = user_bob;
    s_phone.delivery_state = DeliveryState::Delivered;
    s_phone.delivered_at = now;
    s_phone.read_at = now + std::chrono::seconds(2);

    RecipientDeliveryState s_laptop;
    s_laptop.message_id = msg_id;
    s_laptop.recipient_device_id = dev_bob_laptop;
    s_laptop.recipient_user_id = user_bob;
    s_laptop.delivery_state = DeliveryState::Queued;

    delivery_repo_->save_recipient_delivery_states({s_phone, s_laptop});

    grpc::ClientContext context;
    context.AddMetadata("x-user-id", user_alice.str());

    v1::GetMessageDeliveryStatusRequest request;
    request.set_conversation_id(conv_id.to_string());
    request.set_message_id(msg_id.to_string());

    v1::GetMessageDeliveryStatusResponse response;
    auto status = stub_->GetMessageDeliveryStatus(&context, request, &response);

    ASSERT_TRUE(status.ok()) << "gRPC error: " << status.error_message();
    EXPECT_EQ(response.message_id(), msg_id.to_string());
    EXPECT_EQ(response.conversation_id(), conv_id.to_string());

    const auto& sum = response.summary();
    EXPECT_EQ(sum.total_targets(), 2U);
    EXPECT_EQ(sum.delivered_targets(), 1U);
    EXPECT_EQ(sum.pending_targets(), 1U);
    EXPECT_EQ(sum.expired_targets(), 0U);

    ASSERT_EQ(response.device_statuses_size(), 2);
    ASSERT_EQ(response.recipient_read_statuses_size(), 1);

    const auto& bob_read = response.recipient_read_statuses(0);
    EXPECT_EQ(bob_read.user_id(), user_bob.str());
    EXPECT_TRUE(bob_read.is_read());
    EXPECT_EQ(bob_read.reader_device_id(), dev_bob_phone.str());
}

TEST_F(MessagingDeliveryStateGrpcTest, GetMessageDeliveryStatusRpc_SuccessGroupChat) {
    auto conv_id = ConversationId::generate_v7();
    auto msg_id = MessageId::generate_v7();
    auto user_alice = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    auto user_bob = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    auto user_charlie = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");

    DeviceId dev_bob("0191ec4d-91b4-7b4d-b6a9-8e41e3d36004");
    DeviceId dev_charlie("0191ec4d-91b4-7b4d-b6a9-8e41e3d36005");

    ConversationParticipantEntity p_alice{conv_id, user_alice, ParticipantRole::Member, MembershipStatus::Active};
    ConversationParticipantEntity p_bob{conv_id, user_bob, ParticipantRole::Member, MembershipStatus::Active};
    ConversationParticipantEntity p_charlie{conv_id, user_charlie, ParticipantRole::Member, MembershipStatus::Active};
    membership_repo_->add_participant(p_alice);
    membership_repo_->add_participant(p_bob);
    membership_repo_->add_participant(p_charlie);

    auto now = std::chrono::system_clock::now();
    RecipientDeliveryState s_bob;
    s_bob.message_id = msg_id;
    s_bob.recipient_device_id = dev_bob;
    s_bob.recipient_user_id = user_bob;
    s_bob.delivery_state = DeliveryState::Delivered;
    s_bob.delivered_at = now;
    s_bob.read_at = now + std::chrono::seconds(1);

    RecipientDeliveryState s_charlie;
    s_charlie.message_id = msg_id;
    s_charlie.recipient_device_id = dev_charlie;
    s_charlie.recipient_user_id = user_charlie;
    s_charlie.delivery_state = DeliveryState::Delivered;
    s_charlie.delivered_at = now;
    // Charlie has NOT read it

    delivery_repo_->save_recipient_delivery_states({s_bob, s_charlie});

    grpc::ClientContext context;
    context.AddMetadata("x-user-id", user_alice.str());

    v1::GetMessageDeliveryStatusRequest request;
    request.set_conversation_id(conv_id.to_string());
    request.set_message_id(msg_id.to_string());

    v1::GetMessageDeliveryStatusResponse response;
    auto status = stub_->GetMessageDeliveryStatus(&context, request, &response);

    ASSERT_TRUE(status.ok());
    EXPECT_EQ(response.summary().total_targets(), 2U);
    EXPECT_EQ(response.summary().delivered_targets(), 2U);

    ASSERT_EQ(response.recipient_read_statuses_size(), 2);
    std::unordered_map<std::string, bool> read_status_map;
    for (int i = 0; i < response.recipient_read_statuses_size(); ++i) {
        const auto& r = response.recipient_read_statuses(i);
        read_status_map[r.user_id()] = r.is_read();
    }

    EXPECT_TRUE(read_status_map[user_bob.str()]);
    EXPECT_FALSE(read_status_map[user_charlie.str()]);
}

TEST_F(MessagingDeliveryStateGrpcTest, GetMessageDeliveryStatusRpc_NonParticipantRejected) {
    auto conv_id = ConversationId::generate_v7();
    auto msg_id = MessageId::generate_v7();
    auto non_member = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36999");

    grpc::ClientContext context;
    context.AddMetadata("x-user-id", non_member.str());

    v1::GetMessageDeliveryStatusRequest request;
    request.set_conversation_id(conv_id.to_string());
    request.set_message_id(msg_id.to_string());

    v1::GetMessageDeliveryStatusResponse response;
    auto status = stub_->GetMessageDeliveryStatus(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(MessagingDeliveryStateGrpcTest, GetMessageDeliveryStatusRpc_MessageNotFound) {
    auto conv_id = ConversationId::generate_v7();
    auto msg_id = MessageId::generate_v7();
    auto user_id = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");

    ConversationParticipantEntity p{conv_id, user_id, ParticipantRole::Member, MembershipStatus::Active};
    membership_repo_->add_participant(p);

    grpc::ClientContext context;
    context.AddMetadata("x-user-id", user_id.str());

    v1::GetMessageDeliveryStatusRequest request;
    request.set_conversation_id(conv_id.to_string());
    request.set_message_id(msg_id.to_string());

    v1::GetMessageDeliveryStatusResponse response;
    auto status = stub_->GetMessageDeliveryStatus(&context, request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
}

} // namespace
} // namespace securecloud::messaging::service::test
