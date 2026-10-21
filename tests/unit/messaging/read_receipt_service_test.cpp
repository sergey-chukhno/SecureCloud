#include "domain/conversation_participant_entity.hpp"
#include "domain/delivery_types.hpp"
#include "domain/outbox_event.hpp"
#include "domain/read_receipt_types.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/membership_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "service/read_receipt_service.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::service {
namespace {

using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationOutboxEventType;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryState;
using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::MembershipStatus;
using domain::MessageId;
using domain::ParticipantRole;
using domain::ReadState;
using domain::RecipientDeliveryState;
using domain::UserId;

// ============================================================================
// Mocks
// ============================================================================

class MockDeliveryStateRepository final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.insert(pending_.end(), records.begin(), records.end());
    }

    std::vector<DeviceDeliveryRecord> fetch_pending_for_device(const DeviceId& device_id,
                                                               const std::string& delivery_bucket, size_t) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DeviceDeliveryRecord> result;
        for (const auto& rec : pending_) {
            if (rec.device_id == device_id && rec.delivery_bucket == delivery_bucket) {
                result.push_back(rec);
            }
        }
        return result;
    }

    void update_device_delivery_status(const DeviceId& device_id, const std::string& delivery_bucket,
                                       const std::chrono::system_clock::time_point& accepted_at,
                                       const MessageId& message_id, DeliveryState state, int32_t attempt_count,
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

    size_t read_acks_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return read_acks_count_;
    }

  private:
    mutable std::mutex mutex_;
    std::vector<DeviceDeliveryRecord> pending_;
    std::unordered_map<MessageId, std::vector<RecipientDeliveryState>> recipient_states_;
    size_t read_acks_count_{0};
};

class MockMembershipRepository final : public repository::IMembershipRepository {
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

    void touch_user_conversation(const UserId&, const ConversationId&, ConversationType, MembershipStatus,
                                 std::chrono::system_clock::time_point) override {}

    repository::UserConversationsPage list_user_conversations(const UserId&, int,
                                                              const std::optional<std::string>&) override {
        return {};
    }

  private:
    mutable std::mutex mutex_;
    std::unordered_map<ConversationId, std::unordered_map<UserId, ConversationParticipantEntity>> participants_;
};

class MockOutboxRepository final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string& = "") override {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.push_back(event);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }

    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

    std::vector<ConversationOutboxEvent> get_enqueued_events() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return events_;
    }

  private:
    mutable std::mutex mutex_;
    std::vector<ConversationOutboxEvent> events_;
};

// ============================================================================
// Test Fixture
// ============================================================================

class ReadReceiptServiceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        delivery_repo_ = std::make_shared<MockDeliveryStateRepository>();
        membership_repo_ = std::make_shared<MockMembershipRepository>();
        outbox_repo_ = std::make_shared<MockOutboxRepository>();

        user_alice_ = UserId("11111111-1111-1111-1111-111111111111");
        user_bob_ = UserId("22222222-2222-2222-2222-222222222222");
        user_charlie_ = UserId("33333333-3333-3333-3333-333333333333");

        device_bob1_ = DeviceId("bbbbbbbb-1111-1111-1111-111111111111");
        device_bob2_ = DeviceId("bbbbbbbb-2222-2222-2222-222222222222");
        device_charlie1_ = DeviceId("cccccccc-1111-1111-1111-111111111111");

        conversation_id_ = ConversationId::generate_v7();
        message_id_ = MessageId::generate_v7();

        // Register active participants
        auto now = std::chrono::system_clock::now();
        ConversationParticipantEntity part_alice{conversation_id_, user_alice_, ParticipantRole::Admin,
                                                 MembershipStatus::Active, now};
        ConversationParticipantEntity part_bob{conversation_id_, user_bob_, ParticipantRole::Member,
                                               MembershipStatus::Active, now};
        ConversationParticipantEntity part_charlie{conversation_id_, user_charlie_, ParticipantRole::Member,
                                                   MembershipStatus::Active, now};

        membership_repo_->add_participant(part_alice);
        membership_repo_->add_participant(part_bob);
        membership_repo_->add_participant(part_charlie);

        // Active device status predicate
        device_status_checker_ = [this](const DeviceId& id) {
            return revoked_devices_.find(id) == revoked_devices_.end();
        };

        service_ = std::make_unique<ReadReceiptService>(delivery_repo_, membership_repo_, outbox_repo_,
                                                        device_status_checker_);
    }

    std::shared_ptr<MockDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<MockMembershipRepository> membership_repo_;
    std::shared_ptr<MockOutboxRepository> outbox_repo_;
    ReadReceiptService::DeviceStatusChecker device_status_checker_;
    std::unordered_map<DeviceId, bool> revoked_devices_;
    std::unique_ptr<ReadReceiptService> service_;

    UserId user_alice_;
    UserId user_bob_;
    UserId user_charlie_;

    DeviceId device_bob1_;
    DeviceId device_bob2_;
    DeviceId device_charlie1_;

    ConversationId conversation_id_;
    MessageId message_id_;
};

// ============================================================================
// 1. Authorized Read Receipt Submission Success
// ============================================================================

TEST_F(ReadReceiptServiceTest, AuthorizedUserSubmitsReadReceiptSuccess) {
    // Setup message dispatched to Bob (Phone B1)
    RecipientDeliveryState bob_state;
    bob_state.message_id = message_id_;
    bob_state.recipient_device_id = device_bob1_;
    bob_state.recipient_user_id = user_bob_;
    bob_state.delivery_state = DeliveryState::Delivered;
    bob_state.delivered_at = std::chrono::system_clock::now();
    bob_state.read_at = std::nullopt;

    delivery_repo_->save_recipient_delivery_states({bob_state});

    ReadReceiptCommand cmd;
    cmd.message_id = message_id_;
    cmd.conversation_id = conversation_id_;
    cmd.caller_user_id = user_bob_;
    cmd.reader_device_id = device_bob1_;
    cmd.read_at = std::chrono::system_clock::now();

    auto result = service_->record_read_receipt(cmd);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.value.message_id, message_id_);
    EXPECT_EQ(result.value.conversation_id, conversation_id_);
    EXPECT_EQ(result.value.reader_user_id, user_bob_);
    EXPECT_EQ(result.value.reader_device_id, device_bob1_);
    EXPECT_EQ(result.value.state, v1::DELIVERY_STATE_READ);
    EXPECT_FALSE(result.value.is_idempotent_replay);

    // Verify durable record in delivery_repo
    auto states = delivery_repo_->get_delivery_states_for_message(message_id_);
    ASSERT_EQ(states.size(), 1u);
    EXPECT_TRUE(states[0].read_at.has_value());

    // Verify outbox domain event published
    auto events = outbox_repo_->get_enqueued_events();
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].event_type, ConversationOutboxEventType::MessageRead);
    EXPECT_EQ(events[0].conversation_id, conversation_id_);

    auto payload = nlohmann::json::parse(events[0].payload_json);
    EXPECT_EQ(payload["message_id"], message_id_.to_string());
    EXPECT_EQ(payload["conversation_id"], conversation_id_.to_string());
    EXPECT_EQ(payload["reader_device_id"], device_bob1_.str());
    EXPECT_EQ(payload["reader_user_id"], user_bob_.str());
}

// ============================================================================
// 2. Duplicate Read Receipt Idempotency
// ============================================================================

TEST_F(ReadReceiptServiceTest, DuplicateReadReceiptIsIdempotent) {
    RecipientDeliveryState bob_state;
    bob_state.message_id = message_id_;
    bob_state.recipient_device_id = device_bob1_;
    bob_state.recipient_user_id = user_bob_;
    bob_state.delivery_state = DeliveryState::Delivered;
    bob_state.delivered_at = std::chrono::system_clock::now();
    bob_state.read_at = std::nullopt;

    delivery_repo_->save_recipient_delivery_states({bob_state});

    ReadReceiptCommand cmd;
    cmd.message_id = message_id_;
    cmd.conversation_id = conversation_id_;
    cmd.caller_user_id = user_bob_;
    cmd.reader_device_id = device_bob1_;
    cmd.read_at = std::chrono::system_clock::now();

    // First submission
    auto res1 = service_->record_read_receipt(cmd);
    ASSERT_TRUE(res1);
    EXPECT_FALSE(res1.value.is_idempotent_replay);
    EXPECT_EQ(outbox_repo_->get_enqueued_events().size(), 1u);
    EXPECT_EQ(delivery_repo_->read_acks_count(), 1u);

    // Duplicate submission
    auto res2 = service_->record_read_receipt(cmd);
    ASSERT_TRUE(res2);
    EXPECT_TRUE(res2.value.is_idempotent_replay);
    EXPECT_EQ(res2.value.recorded_at, res1.value.recorded_at);

    // No duplicate outbox event or ScyllaDB write
    EXPECT_EQ(outbox_repo_->get_enqueued_events().size(), 1u);
    EXPECT_EQ(delivery_repo_->read_acks_count(), 1u);
}

// ============================================================================
// 3. Unauthorized User Impersonation Rejected
// ============================================================================

TEST_F(ReadReceiptServiceTest, UnauthorizedCallerClaimingAnotherUserReadFails) {
    RecipientDeliveryState bob_state;
    bob_state.message_id = message_id_;
    bob_state.recipient_device_id = device_bob1_;
    bob_state.recipient_user_id = user_bob_;
    bob_state.delivery_state = DeliveryState::Delivered;

    delivery_repo_->save_recipient_delivery_states({bob_state});

    // Alice attempts to mark read on Bob's device
    ReadReceiptCommand cmd;
    cmd.message_id = message_id_;
    cmd.conversation_id = conversation_id_;
    cmd.caller_user_id = user_alice_; // Alice calling for Bob's device
    cmd.reader_device_id = device_bob1_;
    cmd.read_at = std::chrono::system_clock::now();

    auto result = service_->record_read_receipt(cmd);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);
}

// ============================================================================
// 4. Non-Participant in Conversation Rejected
// ============================================================================

TEST_F(ReadReceiptServiceTest, NonParticipantInConversationFails) {
    UserId user_eve("99999999-9999-9999-9999-999999999999");
    DeviceId device_eve("eeeeeeee-9999-9999-9999-999999999999");

    ReadReceiptCommand cmd;
    cmd.message_id = message_id_;
    cmd.conversation_id = conversation_id_;
    cmd.caller_user_id = user_eve;
    cmd.reader_device_id = device_eve;

    auto result = service_->record_read_receipt(cmd);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);
}

// ============================================================================
// 5. Revoked Device Rejected
// ============================================================================

TEST_F(ReadReceiptServiceTest, RevokedDeviceFails) {
    RecipientDeliveryState bob_state;
    bob_state.message_id = message_id_;
    bob_state.recipient_device_id = device_bob1_;
    bob_state.recipient_user_id = user_bob_;
    bob_state.delivery_state = DeliveryState::Delivered;

    delivery_repo_->save_recipient_delivery_states({bob_state});

    // Mark device_bob1_ as revoked
    revoked_devices_[device_bob1_] = true;

    ReadReceiptCommand cmd;
    cmd.message_id = message_id_;
    cmd.conversation_id = conversation_id_;
    cmd.caller_user_id = user_bob_;
    cmd.reader_device_id = device_bob1_;

    auto result = service_->record_read_receipt(cmd);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED);
}

// ============================================================================
// 6. Device Not Dispatched To Fails
// ============================================================================

TEST_F(ReadReceiptServiceTest, DeviceNotDispatchedToFails) {
    RecipientDeliveryState bob_state;
    bob_state.message_id = message_id_;
    bob_state.recipient_device_id = device_bob1_;
    bob_state.recipient_user_id = user_bob_;
    bob_state.delivery_state = DeliveryState::Delivered;

    delivery_repo_->save_recipient_delivery_states({bob_state});

    // Bob tries to mark read using device_bob2_, which was not in the dispatch list
    ReadReceiptCommand cmd;
    cmd.message_id = message_id_;
    cmd.conversation_id = conversation_id_;
    cmd.caller_user_id = user_bob_;
    cmd.reader_device_id = device_bob2_;

    auto result = service_->record_read_receipt(cmd);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
}

// ============================================================================
// 7. Multi-Device User Read Aggregation
// ============================================================================

TEST_F(ReadReceiptServiceTest, MultiDeviceUserReadAggregation) {
    // Bob has two devices: B1 (Phone) and B2 (Laptop)
    RecipientDeliveryState bob_b1;
    bob_b1.message_id = message_id_;
    bob_b1.recipient_device_id = device_bob1_;
    bob_b1.recipient_user_id = user_bob_;
    bob_b1.delivery_state = DeliveryState::Delivered;

    RecipientDeliveryState bob_b2;
    bob_b2.message_id = message_id_;
    bob_b2.recipient_device_id = device_bob2_;
    bob_b2.recipient_user_id = user_bob_;
    bob_b2.delivery_state = DeliveryState::Queued; // Laptop offline

    delivery_repo_->save_recipient_delivery_states({bob_b1, bob_b2});

    // Before read: Bob is unread
    auto initial_status = service_->get_message_read_status(conversation_id_, message_id_, user_alice_);
    ASSERT_TRUE(initial_status);
    EXPECT_EQ(initial_status.value.total_recipients, 1u);
    EXPECT_EQ(initial_status.value.read_recipients, 0u);
    EXPECT_EQ(initial_status.value.recipient_read_statuses[0].read_state, ReadState::Unread);

    // Bob reads on Phone B1
    auto now = std::chrono::system_clock::now();
    ReadReceiptCommand cmd;
    cmd.message_id = message_id_;
    cmd.conversation_id = conversation_id_;
    cmd.caller_user_id = user_bob_;
    cmd.reader_device_id = device_bob1_;
    cmd.read_at = now;

    auto read_res = service_->record_read_receipt(cmd);
    ASSERT_TRUE(read_res);

    // After read: Bob is marked as Read, even though Laptop B2 is still queued
    auto updated_status = service_->get_message_read_status(conversation_id_, message_id_, user_alice_);
    ASSERT_TRUE(updated_status);
    EXPECT_EQ(updated_status.value.total_recipients, 1u);
    EXPECT_EQ(updated_status.value.read_recipients, 1u);
    ASSERT_EQ(updated_status.value.recipient_read_statuses.size(), 1u);

    const auto& bob_read = updated_status.value.recipient_read_statuses[0];
    EXPECT_EQ(bob_read.user_id, user_bob_);
    EXPECT_EQ(bob_read.read_state, ReadState::Read);
    EXPECT_EQ(bob_read.reader_device_id, device_bob1_);
    EXPECT_TRUE(bob_read.read_at.has_value());
}

// ============================================================================
// 8. Group Conversation Read Breakdown (No Global Read)
// ============================================================================

TEST_F(ReadReceiptServiceTest, GroupConversationReadBreakdown) {
    // Message sent to Bob (B1) and Charlie (C1)
    RecipientDeliveryState bob_state;
    bob_state.message_id = message_id_;
    bob_state.recipient_device_id = device_bob1_;
    bob_state.recipient_user_id = user_bob_;
    bob_state.delivery_state = DeliveryState::Delivered;

    RecipientDeliveryState charlie_state;
    charlie_state.message_id = message_id_;
    charlie_state.recipient_device_id = device_charlie1_;
    charlie_state.recipient_user_id = user_charlie_;
    charlie_state.delivery_state = DeliveryState::Delivered;

    delivery_repo_->save_recipient_delivery_states({bob_state, charlie_state});

    // Bob opens and reads the message
    ReadReceiptCommand cmd;
    cmd.message_id = message_id_;
    cmd.conversation_id = conversation_id_;
    cmd.caller_user_id = user_bob_;
    cmd.reader_device_id = device_bob1_;
    cmd.read_at = std::chrono::system_clock::now();

    auto res = service_->record_read_receipt(cmd);
    ASSERT_TRUE(res);

    // Sender Alice inspects message read status
    auto status = service_->get_message_read_status(conversation_id_, message_id_, user_alice_);
    ASSERT_TRUE(status);
    EXPECT_EQ(status.value.total_recipients, 2u);
    EXPECT_EQ(status.value.read_recipients, 1u); // Only Bob read!

    // Verify Bob is Read and Charlie is Unread
    bool found_bob = false;
    bool found_charlie = false;
    for (const auto& r : status.value.recipient_read_statuses) {
        if (r.user_id == user_bob_) {
            found_bob = true;
            EXPECT_EQ(r.read_state, ReadState::Read);
            EXPECT_EQ(r.reader_device_id, device_bob1_);
        } else if (r.user_id == user_charlie_) {
            found_charlie = true;
            EXPECT_EQ(r.read_state, ReadState::Unread);
            EXPECT_FALSE(r.read_at.has_value());
        }
    }
    EXPECT_TRUE(found_bob);
    EXPECT_TRUE(found_charlie);
}

// ============================================================================
// 9. Input Validation Rejections
// ============================================================================

TEST_F(ReadReceiptServiceTest, InputValidationRejections) {
    // Empty message ID
    ReadReceiptCommand cmd_empty_msg;
    cmd_empty_msg.caller_user_id = user_bob_;
    cmd_empty_msg.reader_device_id = device_bob1_;
    EXPECT_FALSE(service_->record_read_receipt(cmd_empty_msg));

    // Empty reader device ID
    ReadReceiptCommand cmd_empty_dev;
    cmd_empty_dev.message_id = message_id_;
    cmd_empty_dev.caller_user_id = user_bob_;
    EXPECT_FALSE(service_->record_read_receipt(cmd_empty_dev));

    // Empty caller user ID
    ReadReceiptCommand cmd_empty_user;
    cmd_empty_user.message_id = message_id_;
    cmd_empty_user.reader_device_id = device_bob1_;
    EXPECT_FALSE(service_->record_read_receipt(cmd_empty_user));
}

} // namespace
} // namespace securecloud::messaging::service
