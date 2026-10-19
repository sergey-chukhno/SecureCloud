#include "messaging/client/auth_crypto_directory_client_interface.hpp"
#include "messaging/domain/conversation_entity.hpp"
#include "messaging/domain/conversation_participant_entity.hpp"
#include "messaging/domain/envelope_types.hpp"
#include "messaging/domain/submission_fingerprint.hpp"
#include "messaging/domain/submission_types.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/service/conversation_authorization_service.hpp"
#include "messaging/service/e2e_envelope_validator.hpp"
#include "messaging/service/idempotency_guard.hpp"
#include "messaging/service/in_memory_sequence_allocator.hpp"
#include "messaging/service/message_submission_service.hpp"
#include "messaging/service/recipient_device_resolution_service.hpp"
#include "messaging/util/zero_plaintext_guard.hpp"
#include "securecloud/auth/v1/auth.pb.h"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::service::test {
namespace {

using client::DeviceCryptoRecord;
using client::IAuthCryptoDirectoryClient;
using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeviceDeliveryRecord;
using domain::DeviceDeliveryTarget;
using domain::DeviceId;
using domain::E2EAlgorithm;
using domain::E2EProtocolVersion;
using domain::IdempotencyRecord;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::MessagePriority;
using domain::MessageSubmissionCommand;
using domain::ParticipantRole;
using domain::RecipientDeliveryState;
using domain::UserId;

// ============================================================================
// Mock Repositories & Clients
// ============================================================================

class MockMessageRepository : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override { saved_messages.push_back(msg); }

    std::optional<MessageEntity> find_by_id(const ConversationId&, const MessageBucket&, const MessageId&) override {
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId&, const MessageBucket&, uint64_t,
                                                               uint64_t, size_t) override {
        return {};
    }

    uint64_t get_last_sequence(const ConversationId&, const MessageBucket&) override { return 0; }

    std::vector<MessageEntity> saved_messages;
};

class MockDeliveryStateRepository : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        saved_pending.insert(saved_pending.end(), records.begin(), records.end());
    }

    std::vector<DeviceDeliveryRecord> fetch_pending_for_device(const DeviceId&, const std::string&, size_t) override {
        return {};
    }

    void update_device_delivery_status(const DeviceId&, const std::string&,
                                       const std::chrono::system_clock::time_point&, const MessageId&,
                                       domain::DeliveryState, int32_t,
                                       std::optional<std::chrono::system_clock::time_point>) override {}

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        saved_recipient_states.insert(saved_recipient_states.end(), states.begin(), states.end());
    }

    void record_delivery_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {
    }

    void record_read_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {}

    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId&) override { return {}; }

    std::vector<DeviceDeliveryRecord> saved_pending;
    std::vector<RecipientDeliveryState> saved_recipient_states;
};

class MockOutboxRepository : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string&) override {
        enqueued_events.push_back(event);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }

    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

    std::vector<ConversationOutboxEvent> enqueued_events;
};

class MockIdempotencyRepository : public repository::IIdempotencyRepository {
  public:
    std::optional<IdempotencyRecord> find_submission(const DeviceId& sender_device_id,
                                                     const std::string& idempotency_key) override {
        const auto key = sender_device_id.str() + ":" + idempotency_key;
        auto it = records_.find(key);
        if (it != records_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void save_submission(const IdempotencyRecord& record) override {
        const auto key = record.sender_device_id.str() + ":" + record.idempotency_key;
        records_[key] = record;
    }

    std::unordered_map<std::string, IdempotencyRecord> records_;
};

class MockAuthCryptoClient : public IAuthCryptoDirectoryClient {
  public:
    void set_user_devices(const UserId& user_id, std::vector<DeviceCryptoRecord> devices) {
        user_devices_[user_id.str()] = std::move(devices);
    }

    client::Result<std::vector<DeviceCryptoRecord>, client::CryptoDirectoryError>
    get_user_device_crypto_records(const domain::UserId& user_id,
                                   std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) override {
        (void)timeout;
        auto it = user_devices_.find(user_id.str());
        if (it != user_devices_.end()) {
            return it->second;
        }
        return std::vector<DeviceCryptoRecord>{};
    }

    client::Result<DeviceCryptoRecord, client::CryptoDirectoryError>
    get_device_crypto_identity(const domain::DeviceId& device_id,
                               std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) override {
        (void)timeout;
        for (const auto& [_, devices] : user_devices_) {
            for (const auto& dev : devices) {
                if (dev.device_id == device_id) {
                    return dev;
                }
            }
        }
        return client::CryptoDirectoryError{
            .kind = client::CryptoDirectoryErrorKind::NotFound,
            .message = "Device not found",
            .grpc_code = ::grpc::StatusCode::NOT_FOUND,
        };
    }

  private:
    std::unordered_map<std::string, std::vector<DeviceCryptoRecord>> user_devices_;
};

// ============================================================================
// Test Fixture
// ============================================================================

class MessageSubmissionEnvelopeIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        memb_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *memb_repo_);
        sequence_allocator_ = std::make_shared<InMemorySequenceAllocator>();
        idempotency_repo_ = std::make_shared<MockIdempotencyRepository>();
        idempotency_guard_ = std::make_shared<MessageSubmissionIdempotencyGuard>(idempotency_repo_);
        message_repo_ = std::make_shared<MockMessageRepository>();
        delivery_repo_ = std::make_shared<MockDeliveryStateRepository>();
        outbox_repo_ = std::make_shared<MockOutboxRepository>();

        auth_crypto_client_ = std::make_shared<MockAuthCryptoClient>();
        resolution_service_ = std::make_shared<RecipientDeviceResolutionService>(auth_crypto_client_);
        envelope_validator_ = std::make_shared<E2EEnvelopeValidator>(resolution_service_);

        service_ = std::make_unique<MessageSubmissionService>(auth_service_, sequence_allocator_, idempotency_guard_,
                                                              message_repo_, delivery_repo_, outbox_repo_,
                                                              envelope_validator_, resolution_service_);

        // Setup test users & devices
        test_conv_id_ = ConversationId::generate_v7();
        alice_id_ = UserId("018d0000-0000-7000-8000-000000000001");
        bob_id_ = UserId("018d0000-0000-7000-8000-000000000002");
        alice_device_ = DeviceId("dev-alice-phone");
        bob_device_ = DeviceId("dev-bob-phone");

        // Save conversation
        ConversationEntity conv{test_conv_id_, ConversationType::Direct, alice_id_};
        conv_repo_->save_conversation(conv);

        auto now = std::chrono::system_clock::now();
        ConversationParticipantEntity p_alice{test_conv_id_, alice_id_, ParticipantRole::Member,
                                              MembershipStatus::Active, now};
        ConversationParticipantEntity p_bob{test_conv_id_, bob_id_, ParticipantRole::Member, MembershipStatus::Active,
                                            now};
        memb_repo_->add_participant(p_alice);
        memb_repo_->add_participant(p_bob);

        // Register active devices in Auth crypto directory
        DeviceCryptoRecord alice_dev_rec;
        alice_dev_rec.device_id = alice_device_;
        alice_dev_rec.user_id = alice_id_;
        alice_dev_rec.status = securecloud::auth::v1::DEVICE_STATUS_ACTIVE;
        alice_dev_rec.identity_key = std::vector<uint8_t>(32, 0x11);
        auth_crypto_client_->set_user_devices(alice_id_, {alice_dev_rec});

        DeviceCryptoRecord bob_dev_rec;
        bob_dev_rec.device_id = bob_device_;
        bob_dev_rec.user_id = bob_id_;
        bob_dev_rec.status = securecloud::auth::v1::DEVICE_STATUS_ACTIVE;
        bob_dev_rec.identity_key = std::vector<uint8_t>(32, 0x22);
        auth_crypto_client_->set_user_devices(bob_id_, {bob_dev_rec});
    }

    DeviceDeliveryTarget create_valid_target(const UserId& user_id, const DeviceId& device_id) {
        DeviceDeliveryTarget target;
        target.recipient_user_id = user_id;
        target.recipient_device_id = device_id;
        target.ciphertext_blob = std::string("\x89\xAB\xCD\xEF\x01\x23\x45\x67\x89\xAB\xCD\xEF", 12);
        target.ephemeral_public_key = std::vector<uint8_t>(32, 0xEE);
        target.iv = std::vector<uint8_t>(24, 0x12);
        target.auth_tag = std::vector<uint8_t>(16, 0xAA);
        target.algorithm = "XChaCha20-Poly1305";
        target.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
        target.one_time_prekey_id = "otk-prekey-123";
        return target;
    }

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> memb_repo_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<InMemorySequenceAllocator> sequence_allocator_;
    std::shared_ptr<MockIdempotencyRepository> idempotency_repo_;
    std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard_;
    std::shared_ptr<MockMessageRepository> message_repo_;
    std::shared_ptr<MockDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<MockOutboxRepository> outbox_repo_;

    std::shared_ptr<MockAuthCryptoClient> auth_crypto_client_;
    std::shared_ptr<RecipientDeviceResolutionService> resolution_service_;
    std::shared_ptr<E2EEnvelopeValidator> envelope_validator_;
    std::unique_ptr<MessageSubmissionService> service_;

    ConversationId test_conv_id_;
    UserId alice_id_;
    UserId bob_id_;
    DeviceId alice_device_;
    DeviceId bob_device_;
};

// ============================================================================
// Test Scenarios
// ============================================================================

TEST_F(MessageSubmissionEnvelopeIntegrationTest, HappyPathSubmissionWithEnvelopesPersistsPerDeviceRecords) {
    MessageSubmissionCommand cmd;
    cmd.caller_user_id = alice_id_;
    cmd.sender_device_id = alice_device_;
    cmd.conversation_id = test_conv_id_;
    cmd.client_idempotency_token = "idem-token-001";
    cmd.priority = MessagePriority::Normal;
    cmd.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
    cmd.delivery_targets.push_back(create_valid_target(bob_id_, bob_device_));

    auto result = service_->submit_message(cmd);
    ASSERT_TRUE(result.success) << "Submission failed: " << result.error_message;

    EXPECT_FALSE(result.value.is_replay);
    EXPECT_EQ(result.value.conversation_id, test_conv_id_);
    EXPECT_EQ(result.value.message_sequence, 1U);

    // Verify MessageEntity saved
    ASSERT_EQ(message_repo_->saved_messages.size(), 1U);
    EXPECT_EQ(message_repo_->saved_messages[0].sender_user_id, alice_id_);
    EXPECT_EQ(message_repo_->saved_messages[0].sender_device_id, alice_device_);

    // CRITICAL: Verify per-device delivery record contains all 7 envelope columns!
    ASSERT_EQ(delivery_repo_->saved_pending.size(), 1U);
    const auto& d_rec = delivery_repo_->saved_pending[0];
    EXPECT_EQ(d_rec.device_id, bob_device_);
    EXPECT_EQ(d_rec.ciphertext_blob, cmd.delivery_targets[0].ciphertext_blob);
    EXPECT_EQ(d_rec.ephemeral_public_key, cmd.delivery_targets[0].ephemeral_public_key);
    EXPECT_EQ(d_rec.iv, cmd.delivery_targets[0].iv);
    EXPECT_EQ(d_rec.auth_tag, cmd.delivery_targets[0].auth_tag);
    EXPECT_EQ(d_rec.algorithm, E2EAlgorithm::XChaCha20_Poly1305);
    EXPECT_EQ(d_rec.protocol_version, E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet);
    ASSERT_TRUE(d_rec.one_time_prekey_id.has_value());
    EXPECT_EQ(d_rec.one_time_prekey_id.value(), "otk-prekey-123");

    // Verify Outbox event published (metadata only, zero payload leakage)
    ASSERT_EQ(outbox_repo_->enqueued_events.size(), 1U);
    EXPECT_NE(outbox_repo_->enqueued_events[0].payload_json.find("recipient_device_count"), std::string::npos);
    EXPECT_EQ(outbox_repo_->enqueued_events[0].payload_json.find(cmd.delivery_targets[0].ciphertext_blob),
              std::string::npos);
}

TEST_F(MessageSubmissionEnvelopeIntegrationTest, RejectsSubmissionWhenEnvelopeValidatorDetectsPlaintext) {
    MessageSubmissionCommand cmd;
    cmd.caller_user_id = alice_id_;
    cmd.sender_device_id = alice_device_;
    cmd.conversation_id = test_conv_id_;
    cmd.client_idempotency_token = "idem-token-plaintext";
    cmd.priority = MessagePriority::Normal;

    auto target = create_valid_target(bob_id_, bob_device_);
    target.ciphertext_blob = "{\"text\": \"unencrypted plaintext leaked accidentally!\"}";
    cmd.delivery_targets.push_back(target);

    auto result = service_->submit_message(cmd);
    ASSERT_FALSE(result.success);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);

    // Assert zero persistence side-effects
    EXPECT_TRUE(message_repo_->saved_messages.empty());
    EXPECT_TRUE(delivery_repo_->saved_pending.empty());
    EXPECT_TRUE(outbox_repo_->enqueued_events.empty());
}

TEST_F(MessageSubmissionEnvelopeIntegrationTest, RejectsSubmissionWhenCryptoBoundsViolated) {
    MessageSubmissionCommand cmd;
    cmd.caller_user_id = alice_id_;
    cmd.sender_device_id = alice_device_;
    cmd.conversation_id = test_conv_id_;
    cmd.client_idempotency_token = "idem-token-short-iv";

    auto target = create_valid_target(bob_id_, bob_device_);
    target.iv = std::vector<uint8_t>(10, 0x11); // Short IV (< 24B for XChaCha20)
    cmd.delivery_targets.push_back(target);

    auto result = service_->submit_message(cmd);
    ASSERT_FALSE(result.success);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);

    EXPECT_TRUE(message_repo_->saved_messages.empty());
    EXPECT_TRUE(delivery_repo_->saved_pending.empty());
}

TEST_F(MessageSubmissionEnvelopeIntegrationTest, RejectsSubmissionWhenActiveDeviceOmitted) {
    // Enroll a second active device for Bob
    DeviceId bob_second_device("dev-bob-laptop");
    DeviceCryptoRecord bob_laptop;
    bob_laptop.device_id = bob_second_device;
    bob_laptop.user_id = bob_id_;
    bob_laptop.status = securecloud::auth::v1::DEVICE_STATUS_ACTIVE;
    bob_laptop.identity_key = std::vector<uint8_t>(32, 0x33);

    auto existing_bob_devs = auth_crypto_client_->get_user_device_crypto_records(bob_id_).value();
    existing_bob_devs.push_back(bob_laptop);
    auth_crypto_client_->set_user_devices(bob_id_, existing_bob_devs);

    MessageSubmissionCommand cmd;
    cmd.caller_user_id = alice_id_;
    cmd.sender_device_id = alice_device_;
    cmd.conversation_id = test_conv_id_;
    cmd.client_idempotency_token = "idem-token-omission";
    // Only target bob_device_, omitting bob_second_device
    cmd.delivery_targets.push_back(create_valid_target(bob_id_, bob_device_));

    auto result = service_->submit_message(cmd);
    ASSERT_FALSE(result.success);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);

    EXPECT_TRUE(message_repo_->saved_messages.empty());
    EXPECT_TRUE(delivery_repo_->saved_pending.empty());
}

TEST_F(MessageSubmissionEnvelopeIntegrationTest, IdempotentReplayWithEnvelopesReturnsCachedResult) {
    MessageSubmissionCommand cmd;
    cmd.caller_user_id = alice_id_;
    cmd.sender_device_id = alice_device_;
    cmd.conversation_id = test_conv_id_;
    cmd.client_idempotency_token = "idem-token-replay";
    cmd.priority = MessagePriority::Normal;
    cmd.delivery_targets.push_back(create_valid_target(bob_id_, bob_device_));

    // First submission
    auto res1 = service_->submit_message(cmd);
    ASSERT_TRUE(res1.success);
    EXPECT_FALSE(res1.value.is_replay);
    EXPECT_EQ(message_repo_->saved_messages.size(), 1U);
    EXPECT_EQ(delivery_repo_->saved_pending.size(), 1U);

    // Second submission (identical idempotency token and payload)
    auto res2 = service_->submit_message(cmd);
    ASSERT_TRUE(res2.success);
    EXPECT_TRUE(res2.value.is_replay);
    EXPECT_EQ(res2.value.message_id, res1.value.message_id);
    EXPECT_EQ(res2.value.message_sequence, res1.value.message_sequence);

    // Ensure NO duplicate database records created
    EXPECT_EQ(message_repo_->saved_messages.size(), 1U);
    EXPECT_EQ(delivery_repo_->saved_pending.size(), 1U);
}

TEST_F(MessageSubmissionEnvelopeIntegrationTest, ConflictingPayloadWithAlteredEnvelopeRejectedWith409) {
    MessageSubmissionCommand cmd;
    cmd.caller_user_id = alice_id_;
    cmd.sender_device_id = alice_device_;
    cmd.conversation_id = test_conv_id_;
    cmd.client_idempotency_token = "idem-token-conflict";
    cmd.delivery_targets.push_back(create_valid_target(bob_id_, bob_device_));

    auto res1 = service_->submit_message(cmd);
    ASSERT_TRUE(res1.success);

    // Submit with same idempotency token but altered ciphertext
    MessageSubmissionCommand altered_cmd = cmd;
    altered_cmd.delivery_targets[0].ciphertext_blob =
        std::string("\xFF\xEE\xDD\xCC\xBB\xAA\x00\x11\x22\x33\x44\x55", 12);

    auto res2 = service_->submit_message(altered_cmd);
    ASSERT_FALSE(res2.success);
    EXPECT_EQ(res2.error_code, v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT);
}

} // namespace
} // namespace securecloud::messaging::service::test
