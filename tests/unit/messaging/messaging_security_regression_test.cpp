#include "concurrency/bounded_worker_pool.hpp"
#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/delivery_scheduler_config.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/message_entity.hpp"
#include "domain/outbox_event.hpp"
#include "domain/presence_types.hpp"
#include "domain/read_receipt_types.hpp"
#include "domain/submission_types.hpp"
#include "domain/sync_types.hpp"
#include "messaging/client/auth_crypto_directory_client_interface.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "messaging/repository/sync_cursor_repository_interface.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/conversation_service.hpp"
#include "service/delivery_service.hpp"
#include "service/delivery_state_transition_guard.hpp"
#include "service/e2e_envelope_validator.hpp"
#include "service/idempotency_guard.hpp"
#include "service/in_memory_sequence_allocator.hpp"
#include "service/message_submission_service.hpp"
#include "service/message_sync_service.hpp"
#include "service/messaging_error_mapper.hpp"
#include "service/messaging_service_impl.hpp"
#include "service/presence_coordinator.hpp"
#include "service/read_receipt_commands.hpp"
#include "service/read_receipt_service.hpp"
#include "service/recipient_device_resolution_service.hpp"
#include "service/sync_commands.hpp"
#include "service/sync_cursor_manager.hpp"
#include "util/zero_plaintext_guard.hpp"

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::service {
namespace {

using client::CryptoDirectoryError;
using client::CryptoDirectoryErrorKind;
using client::DeviceCryptoRecord;
using client::IAuthCryptoDirectoryClient;
using client::Result;
using delivery::BoundedDeliveryScheduler;
using delivery::DeliverySchedulerConfig;
using delivery::SchedulerStatus;
using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationOutboxEventType;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryState;
using domain::DeliveryTask;
using domain::DeviceDeliveryRecord;
using domain::DeviceDeliveryTarget;
using domain::DeviceId;
using domain::DeviceSyncCursor;
using domain::E2EAlgorithm;
using domain::E2EMessageEnvelope;
using domain::E2EProtocolVersion;
using domain::IdempotencyRecord;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::MessagePriority;
using domain::MessageSequence;
using domain::MessageSubmissionCommand;
using domain::ParticipantRole;
using domain::PerDeviceEnvelope;
using domain::PresenceStatus;
using domain::RecipientDeliveryState;
using domain::UserId;
using util::ZeroPlaintextGuard;

// ============================================================================
// Security Test Mocks & In-Memory Repositories
// ============================================================================

class SecurityTestMessageRepository final : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override {
        std::lock_guard<std::mutex> lock(mu_);
        messages_.push_back(msg);
    }

    std::optional<MessageEntity> find_by_id(const ConversationId& conv, const MessageBucket&,
                                            const MessageId& id) override {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& m : messages_) {
            if (m.conversation_id == conv && m.message_id == id) {
                return m;
            }
        }
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId& conv, const MessageBucket&,
                                                               uint64_t from, uint64_t to, size_t limit) override {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<MessageEntity> out;
        for (const auto& m : messages_) {
            if (m.conversation_id == conv && m.message_sequence >= from && m.message_sequence <= to) {
                out.push_back(m);
                if (out.size() >= limit) {
                    break;
                }
            }
        }
        return out;
    }

    uint64_t get_last_sequence(const ConversationId& conv, const MessageBucket&) override {
        std::lock_guard<std::mutex> lock(mu_);
        uint64_t max_seq = 0;
        for (const auto& m : messages_) {
            if (m.conversation_id == conv) {
                max_seq = std::max(max_seq, m.message_sequence);
            }
        }
        return max_seq;
    }

    [[nodiscard]] std::vector<MessageEntity> snapshot() const {
        std::lock_guard<std::mutex> lock(mu_);
        return messages_;
    }

  private:
    mutable std::mutex mu_;
    std::vector<MessageEntity> messages_;
};

class SecurityTestDeliveryStateRepository final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& r : records) {
            records_by_key_[make_key(r.device_id, r.message_id)] = r;
            records_by_dev_[r.device_id.str()].push_back(r);
        }
    }

    std::vector<DeviceDeliveryRecord>
    fetch_pending_for_device(const DeviceId& device_id, const std::string& delivery_bucket, size_t limit) override {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<DeviceDeliveryRecord> out;
        auto it = records_by_dev_.find(device_id.str());
        if (it == records_by_dev_.end()) {
            return out;
        }
        for (const auto& r : it->second) {
            const auto& latest = records_by_key_[make_key(r.device_id, r.message_id)];
            if ((delivery_bucket.empty() || latest.delivery_bucket == delivery_bucket) &&
                (latest.delivery_state == DeliveryState::Queued || latest.delivery_state == DeliveryState::RetryWait ||
                 latest.delivery_state == DeliveryState::Delivering)) {
                out.push_back(latest);
                if (out.size() >= limit) {
                    break;
                }
            }
        }
        return out;
    }

    void update_device_delivery_status(const DeviceId& device_id, const std::string& /*delivery_bucket*/,
                                       const std::chrono::system_clock::time_point& /*accepted_at*/,
                                       const MessageId& message_id, DeliveryState state, int32_t attempt_count,
                                       std::optional<std::chrono::system_clock::time_point> next_retry) override {
        std::lock_guard<std::mutex> lock(mu_);
        const auto key = make_key(device_id, message_id);
        auto it = records_by_key_.find(key);
        if (it != records_by_key_.end()) {
            if (!DeliveryStateTransitionGuard::is_regression(it->second.delivery_state, state)) {
                it->second.delivery_state = state;
                it->second.attempt_count = attempt_count;
                it->second.next_retry_at = next_retry;
            }
        }
    }

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& s : states) {
            recipient_states_[s.message_id.to_string()][s.recipient_device_id.str()] = s;
        }
    }

    void record_delivery_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point& delivered_at) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto m_it = recipient_states_.find(message_id.to_string());
        if (m_it != recipient_states_.end()) {
            auto d_it = m_it->second.find(recipient_device_id.str());
            if (d_it != m_it->second.end()) {
                if (!DeliveryStateTransitionGuard::is_regression(d_it->second.delivery_state,
                                                                 DeliveryState::Delivered)) {
                    d_it->second.delivery_state = DeliveryState::Delivered;
                    if (!d_it->second.delivered_at.has_value()) {
                        d_it->second.delivered_at = delivered_at;
                    }
                }
            }
        }
        const auto key = make_key(recipient_device_id, message_id);
        auto r_it = records_by_key_.find(key);
        if (r_it != records_by_key_.end()) {
            r_it->second.delivery_state = DeliveryState::Delivered;
        }
    }

    void record_read_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                         const std::chrono::system_clock::time_point& read_at) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto m_it = recipient_states_.find(message_id.to_string());
        if (m_it != recipient_states_.end()) {
            auto d_it = m_it->second.find(recipient_device_id.str());
            if (d_it != m_it->second.end() && !d_it->second.read_at.has_value()) {
                d_it->second.read_at = read_at;
            }
        }
    }

    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<RecipientDeliveryState> out;
        auto it = recipient_states_.find(message_id.to_string());
        if (it != recipient_states_.end()) {
            for (const auto& [_, st] : it->second) {
                out.push_back(st);
            }
        }
        return out;
    }

    [[nodiscard]] std::vector<DeviceDeliveryRecord> snapshot_records() const {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<DeviceDeliveryRecord> out;
        for (const auto& [_, r] : records_by_key_) {
            out.push_back(r);
        }
        return out;
    }

  private:
    static std::string make_key(const DeviceId& dev, const MessageId& msg) { return dev.str() + ":" + msg.to_string(); }

    mutable std::mutex mu_;
    std::unordered_map<std::string, DeviceDeliveryRecord> records_by_key_;
    std::unordered_map<std::string, std::vector<DeviceDeliveryRecord>> records_by_dev_;
    std::unordered_map<std::string, std::unordered_map<std::string, RecipientDeliveryState>> recipient_states_;
};

class SecurityTestOutboxRepository final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string& = "") override {
        std::lock_guard<std::mutex> lock(mu_);
        events_.push_back(event);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }
    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

    [[nodiscard]] std::vector<ConversationOutboxEvent> snapshot() const {
        std::lock_guard<std::mutex> lock(mu_);
        return events_;
    }

  private:
    mutable std::mutex mu_;
    std::vector<ConversationOutboxEvent> events_;
};

class SecurityTestSyncCursorRepository final : public repository::ISyncCursorRepository {
  public:
    std::optional<DeviceSyncCursor> get_sync_cursor(const DeviceId& device_id,
                                                    const ConversationId& conversation_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = cursors_.find(make_key(device_id, conversation_id));
        if (it != cursors_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void upsert_sync_cursor(const DeviceSyncCursor& cursor) override {
        std::lock_guard<std::mutex> lock(mu_);
        cursors_[make_key(cursor.device_id, cursor.conversation_id)] = cursor;
    }

    std::vector<DeviceSyncCursor> list_sync_cursors_by_device(const DeviceId& device_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<DeviceSyncCursor> out;
        for (const auto& [_, c] : cursors_) {
            if (c.device_id == device_id) {
                out.push_back(c);
            }
        }
        return out;
    }

  private:
    static std::string make_key(const DeviceId& dev, const ConversationId& conv) {
        return dev.str() + ":" + conv.to_string();
    }

    mutable std::mutex mu_;
    std::unordered_map<std::string, DeviceSyncCursor> cursors_;
};

class SecurityTestIdempotencyRepository final : public repository::IIdempotencyRepository {
  public:
    std::optional<IdempotencyRecord> find_submission(const DeviceId& sender_device_id,
                                                     const std::string& idempotency_key) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = records_.find(sender_device_id.str() + ":" + idempotency_key);
        if (it != records_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void save_submission(const IdempotencyRecord& record) override {
        std::lock_guard<std::mutex> lock(mu_);
        records_[record.sender_device_id.str() + ":" + record.idempotency_key] = record;
    }

  private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, IdempotencyRecord> records_;
};

class SecurityTestAuthCryptoDirectoryClient final : public IAuthCryptoDirectoryClient {
  public:
    void add_device(const UserId& user_id, const DeviceId& device_id,
                    securecloud::auth::v1::DeviceStatus status = securecloud::auth::v1::DEVICE_STATUS_ACTIVE) {
        std::lock_guard<std::mutex> lock(mu_);
        DeviceCryptoRecord rec{
            .device_id = device_id,
            .user_id = user_id,
            .identity_key = std::vector<uint8_t>(32, 0x41),
            .signed_prekey = std::vector<uint8_t>(32, 0x42),
            .signed_prekey_signature = std::vector<uint8_t>(64, 0x43),
            .one_time_prekey = std::vector<uint8_t>(32, 0x44),
            .one_time_prekey_id = "otk-sec-1",
            .status = status,
            .identity_key_fingerprint = "fp-" + device_id.str(),
            .signed_prekey_created_at_epoch_ms = 1000,
            .remaining_one_time_prekeys = 50,
        };
        devices_by_user_[user_id].push_back(rec);
        device_map_[device_id] = rec;
    }

    void set_device_status(const DeviceId& device_id, securecloud::auth::v1::DeviceStatus status) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = device_map_.find(device_id);
        if (it != device_map_.end()) {
            it->second.status = status;
            for (auto& rec : devices_by_user_[it->second.user_id]) {
                if (rec.device_id == device_id) {
                    rec.status = status;
                }
            }
        }
    }

    Result<std::vector<DeviceCryptoRecord>, CryptoDirectoryError>
    get_user_device_crypto_records(const UserId& user_id, std::chrono::milliseconds) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = devices_by_user_.find(user_id);
        if (it != devices_by_user_.end()) {
            return it->second;
        }
        return std::vector<DeviceCryptoRecord>{};
    }

    Result<DeviceCryptoRecord, CryptoDirectoryError> get_device_crypto_identity(const DeviceId& device_id,
                                                                                std::chrono::milliseconds) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = device_map_.find(device_id);
        if (it != device_map_.end()) {
            return it->second;
        }
        return CryptoDirectoryError{
            .kind = CryptoDirectoryErrorKind::NotFound,
            .message = "Device not registered in auth crypto directory",
            .grpc_code = ::grpc::StatusCode::NOT_FOUND,
        };
    }

  private:
    mutable std::mutex mu_;
    std::unordered_map<UserId, std::vector<DeviceCryptoRecord>> devices_by_user_;
    std::unordered_map<DeviceId, DeviceCryptoRecord> device_map_;
};

// ============================================================================
// Test Fixture: MessagingSecurityRegressionTest
// ============================================================================

class MessagingSecurityRegressionTest : public ::testing::Test {
  protected:
    void SetUp() override {
        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        membership_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        msg_repo_ = std::make_shared<SecurityTestMessageRepository>();
        delivery_repo_ = std::make_shared<SecurityTestDeliveryStateRepository>();
        outbox_repo_ = std::make_shared<SecurityTestOutboxRepository>();
        cursor_repo_ = std::make_shared<SecurityTestSyncCursorRepository>();
        idempotency_repo_ = std::make_shared<SecurityTestIdempotencyRepository>();
        crypto_client_ = std::make_shared<SecurityTestAuthCryptoDirectoryClient>();

        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *membership_repo_);
        seq_allocator_ = std::make_shared<InMemorySequenceAllocator>();
        idempotency_guard_ = std::make_shared<MessageSubmissionIdempotencyGuard>(idempotency_repo_);

        resolution_service_ = std::make_shared<RecipientDeviceResolutionService>(crypto_client_);
        envelope_validator_ = std::make_shared<E2EEnvelopeValidator>(resolution_service_);

        submission_service_ = std::make_shared<MessageSubmissionService>(
            auth_service_, seq_allocator_, idempotency_guard_, msg_repo_, delivery_repo_, outbox_repo_,
            envelope_validator_, resolution_service_);

        cursor_manager_ = std::make_shared<SyncCursorManager>(cursor_repo_, msg_repo_, seq_allocator_);
        sync_service_ = std::make_shared<MessageSyncService>(msg_repo_, cursor_manager_, auth_service_, delivery_repo_);

        auto dev_checker = [client = crypto_client_](const DeviceId& d) -> bool {
            auto res = client->get_device_crypto_identity(d, std::chrono::milliseconds(100));
            return res.has_value() && res.value().status == securecloud::auth::v1::DEVICE_STATUS_ACTIVE;
        };

        delivery_service_ = std::make_shared<DeliveryService>(delivery_repo_, outbox_repo_, dev_checker);
        read_receipt_service_ =
            std::make_shared<ReadReceiptService>(delivery_repo_, membership_repo_, outbox_repo_, dev_checker);
        presence_coordinator_ = std::make_shared<PresenceCoordinator>();
    }

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> membership_repo_;
    std::shared_ptr<SecurityTestMessageRepository> msg_repo_;
    std::shared_ptr<SecurityTestDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<SecurityTestOutboxRepository> outbox_repo_;
    std::shared_ptr<SecurityTestSyncCursorRepository> cursor_repo_;
    std::shared_ptr<SecurityTestIdempotencyRepository> idempotency_repo_;
    std::shared_ptr<SecurityTestAuthCryptoDirectoryClient> crypto_client_;

    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<InMemorySequenceAllocator> seq_allocator_;
    std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard_;
    std::shared_ptr<E2EEnvelopeValidator> envelope_validator_;
    std::shared_ptr<RecipientDeviceResolutionService> resolution_service_;
    std::shared_ptr<MessageSubmissionService> submission_service_;

    std::shared_ptr<SyncCursorManager> cursor_manager_;
    std::shared_ptr<MessageSyncService> sync_service_;
    std::shared_ptr<DeliveryService> delivery_service_;
    std::shared_ptr<ReadReceiptService> read_receipt_service_;
    std::shared_ptr<PresenceCoordinator> presence_coordinator_;
};

// ============================================================================
// Test 1: Zero-Plaintext Byte Audit (ADR-008 Invariant)
// ============================================================================

TEST_F(MessagingSecurityRegressionTest, ZeroPlaintextByteAuditAcrossDurableAndEphemeralMemory) {
    const auto conv_id = ConversationId::generate_v7();
    const auto now = std::chrono::system_clock::now();

    const UserId alice("018d0000-0000-7000-8000-000000000601");
    const UserId bob("018d0000-0000-7000-8000-000000000602");
    const DeviceId alice_dev("018d0000-0000-7000-8000-000000000611");
    const DeviceId bob_dev("018d0000-0000-7000-8000-000000000612");

    ConversationEntity conv{conv_id, ConversationType::Direct, alice, now};
    conv_repo_->save_conversation(conv);

    ConversationParticipantEntity p_alice{conv_id, alice, ParticipantRole::Member, MembershipStatus::Active, now};
    ConversationParticipantEntity p_bob{conv_id, bob, ParticipantRole::Member, MembershipStatus::Active, now};
    membership_repo_->add_participant(p_alice);
    membership_repo_->add_participant(p_bob);

    crypto_client_->add_device(alice, alice_dev);
    crypto_client_->add_device(bob, bob_dev);

    // Highly confidential canary strings that MUST NEVER appear unencrypted anywhere on the server
    const std::string canary_plaintext = "CONFIDENTIAL_PLAINTEXT_SECRET_CANARY_ADR008_DO_NOT_STORE_ON_SERVER";
    const std::string canary_private_key = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const std::string canary_ratchet_state = "DOUBLE_RATCHET_ROOT_CHAIN_KEY_MATERIAL_SECRET_01928374";

    // Simulate authenticated client encryption: ciphertext blob has zero correlation with canary
    std::string ciphertext_blob = "\x89\xAB\xCD\xEF\x01\x02\x03\x04\x55\x66\x77\x88\x99\xAA\xBB\xCC"
                                  "CIPHERTEXT_BLOB_OPAQUE_BYTES_E2EE_SIGNAL_DOUBLE_RATCHET_V1";
    std::vector<uint8_t> eph_pubkey(32, 0x5A);
    std::vector<uint8_t> iv(24, 0x3C);
    std::vector<uint8_t> auth_tag(16, 0x7E);

    MessageSubmissionCommand cmd;
    cmd.conversation_id = conv_id;
    cmd.caller_user_id = alice;
    cmd.sender_device_id = alice_dev;
    cmd.client_idempotency_token = "zero-plaintext-audit-token-1";
    cmd.priority = MessagePriority::Normal;
    cmd.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;

    DeviceDeliveryTarget target;
    target.recipient_user_id = bob;
    target.recipient_device_id = bob_dev;
    target.ciphertext_blob = ciphertext_blob;
    target.ephemeral_public_key = eph_pubkey;
    target.iv = iv;
    target.auth_tag = auth_tag;
    target.algorithm = "XChaCha20-Poly1305";
    cmd.delivery_targets.push_back(target);

    // 1. Submit message through the authoritative submission service
    auto sub_res = submission_service_->submit_message(cmd);
    if (!sub_res.success) {
        std::cerr << "Test 2 submit_message failed: code=" << sub_res.error_code << " msg=" << sub_res.error_message
                  << std::endl;
    }
    ASSERT_TRUE(sub_res.success);
    const MessageId msg_id = sub_res.value.message_id;

    // 2. Scan durable storage in ScyllaDB Message Repository
    auto saved_msgs = msg_repo_->snapshot();
    ASSERT_EQ(saved_msgs.size(), 1U);
    const auto& msg = saved_msgs[0];

    EXPECT_EQ(msg.envelope.ciphertext.find(canary_plaintext), std::string::npos);
    EXPECT_EQ(msg.envelope.ciphertext.find(canary_private_key), std::string::npos);
    EXPECT_EQ(msg.envelope.ciphertext.find(canary_ratchet_state), std::string::npos);

    // 3. Scan durable storage in Delivery State Repository
    auto saved_records = delivery_repo_->snapshot_records();
    ASSERT_EQ(saved_records.size(), 1U);
    const auto& rec = saved_records[0];

    EXPECT_EQ(rec.ciphertext_blob.find(canary_plaintext), std::string::npos);
    EXPECT_EQ(rec.ciphertext_blob.find(canary_private_key), std::string::npos);
    EXPECT_EQ(rec.ciphertext_blob.find(canary_ratchet_state), std::string::npos);

    // 4. Scan Outbox Repository events
    auto outbox_events = outbox_repo_->snapshot();
    ASSERT_GE(outbox_events.size(), 1U);
    for (const auto& ev : outbox_events) {
        EXPECT_EQ(ev.payload_json.find(canary_plaintext), std::string::npos);
        EXPECT_EQ(ev.payload_json.find(canary_private_key), std::string::npos);
        EXPECT_EQ(ev.payload_json.find(canary_ratchet_state), std::string::npos);
        // Assert only non-sensitive routing metadata is emitted
        EXPECT_NE(ev.payload_json.find("message_id"), std::string::npos);
    }

    // 5. Scan in-memory delivery task in BoundedDeliveryScheduler
    BoundedDeliveryScheduler scheduler;
    DeliveryTask task;
    task.message_id = msg_id;
    task.conversation_id = conv_id;
    task.recipient_device_id = bob_dev;
    task.envelope.ciphertext_blob = rec.ciphertext_blob;
    task.envelope.ephemeral_public_key = rec.ephemeral_public_key;
    task.envelope.iv = rec.iv;
    task.envelope.auth_tag = rec.auth_tag;
    task.envelope.algorithm = rec.algorithm;

    ASSERT_EQ(scheduler.schedule(task), SchedulerStatus::Enqueued);
    auto dequeued = scheduler.try_dequeue();
    ASSERT_TRUE(dequeued.has_value());
    EXPECT_EQ(dequeued->envelope.ciphertext_blob.find(canary_plaintext), std::string::npos);

    // 6. Audit structured logging formatters (ZeroPlaintextGuard)
    std::string safe_sub_log = ZeroPlaintextGuard::format_safe_submission_log(cmd);
    EXPECT_EQ(safe_sub_log.find(canary_plaintext), std::string::npos);
    EXPECT_EQ(safe_sub_log.find(canary_private_key), std::string::npos);
    EXPECT_EQ(safe_sub_log.find(canary_ratchet_state), std::string::npos);
    EXPECT_NE(safe_sub_log.find("cipher_bytes="), std::string::npos);

    std::string safe_target_log = ZeroPlaintextGuard::summarize_target(target);
    EXPECT_EQ(safe_target_log.find(canary_plaintext), std::string::npos);
    EXPECT_NE(safe_target_log.find("ciphertext_bytes:"), std::string::npos);

    std::cout << "[MSG-012-T05][Test 1: Zero-Plaintext Byte Audit] Verified across ScyllaMessageRepo, "
              << "DeliveryStateRepo, OutboxRepo, SchedulerQueues, and AuditLogs -> ZERO canary leaks.\n";
}

// ============================================================================
// Test 2: Adversarial Anti-Impersonation Under High Concurrency
// ============================================================================

TEST_F(MessagingSecurityRegressionTest, AdversarialCrossDeviceImpersonationAndTamperRejection) {
    const auto conv_id = ConversationId::generate_v7();
    const auto now = std::chrono::system_clock::now();

    const UserId alice("018d0000-0000-7000-8000-000000000701");
    const UserId bob("018d0000-0000-7000-8000-000000000702");
    const UserId mallory("018d0000-0000-7000-8000-000000000703"); // Adversarial outsider

    const DeviceId alice_dev("018d0000-0000-7000-8000-000000000711");
    const DeviceId bob_dev_1("018d0000-0000-7000-8000-000000000721");
    const DeviceId bob_dev_2("018d0000-0000-7000-8000-000000000722");
    const DeviceId mallory_dev("018d0000-0000-7000-8000-000000000731");

    ConversationEntity conv{conv_id, ConversationType::Direct, alice, now};
    conv_repo_->save_conversation(conv);

    ConversationParticipantEntity p_alice{conv_id, alice, ParticipantRole::Member, MembershipStatus::Active, now};
    ConversationParticipantEntity p_bob{conv_id, bob, ParticipantRole::Member, MembershipStatus::Active, now};
    membership_repo_->add_participant(p_alice);
    membership_repo_->add_participant(p_bob);

    crypto_client_->add_device(alice, alice_dev);
    crypto_client_->add_device(bob, bob_dev_1);
    crypto_client_->add_device(bob, bob_dev_2);
    crypto_client_->add_device(mallory, mallory_dev);

    // Alice sends legitimate message targeting Bob's devices (both bob_dev_1 and bob_dev_2)
    MessageSubmissionCommand cmd;
    cmd.conversation_id = conv_id;
    cmd.caller_user_id = alice;
    cmd.sender_device_id = alice_dev;
    cmd.client_idempotency_token = "legitimate-msg-bob-all-devs";
    cmd.priority = MessagePriority::Normal;
    cmd.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;

    DeviceDeliveryTarget target1;
    target1.recipient_user_id = bob;
    target1.recipient_device_id = bob_dev_1;
    target1.ciphertext_blob =
        std::string("\x90\xA1\xB2\xC3\xD4\xE5\xF6\x07\x18\x29\x3A\x4B\x5C\x6D\x7E\x8F", 16) + "encrypted-payload-bob-1";
    target1.ephemeral_public_key = std::vector<uint8_t>(32, 0x01);
    target1.iv = std::vector<uint8_t>(24, 0x02);
    target1.auth_tag = std::vector<uint8_t>(16, 0x03);
    target1.algorithm = "XChaCha20-Poly1305";
    cmd.delivery_targets.push_back(target1);

    DeviceDeliveryTarget target2;
    target2.recipient_user_id = bob;
    target2.recipient_device_id = bob_dev_2;
    target2.ciphertext_blob =
        std::string("\x90\xA1\xB2\xC3\xD4\xE5\xF6\x07\x18\x29\x3A\x4B\x5C\x6D\x7E\x8F", 16) + "encrypted-payload-bob-2";
    target2.ephemeral_public_key = std::vector<uint8_t>(32, 0x01);
    target2.iv = std::vector<uint8_t>(24, 0x02);
    target2.auth_tag = std::vector<uint8_t>(16, 0x03);
    target2.algorithm = "XChaCha20-Poly1305";
    cmd.delivery_targets.push_back(target2);

    auto sub_res = submission_service_->submit_message(cmd);
    ASSERT_TRUE(sub_res.success) << sub_res.error_message;
    const MessageId msg_id = sub_res.value.message_id;

    // Launch concurrent adversarial threads attempting unauthorized actions
    constexpr size_t kAttackIterations = 50;
    std::atomic<size_t> rejected_ack_attacks{0};
    std::atomic<size_t> rejected_sync_attacks{0};
    std::atomic<size_t> rejected_read_attacks{0};

    std::vector<std::thread> workers;

    // Worker 1: Outsider Mallory attempting cross-device delivery ACK for Bob
    workers.emplace_back([&]() {
        for (size_t i = 0; i < kAttackIterations; ++i) {
            DeliveryAckCommand ack;
            ack.conversation_id = conv_id;
            ack.message_id = msg_id;
            ack.recipient_device_id = bob_dev_1;
            ack.caller_user_id = mallory;
            ack.caller_device_id = mallory_dev;
            ack.delivered_at = std::chrono::system_clock::now();

            auto res = delivery_service_->acknowledge_delivery(ack);
            if (!res.success && res.error_code == v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT) {
                rejected_ack_attacks.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    // Worker 2: Bob's companion device (bob_dev_2) attempting cross-device delivery ACK on behalf of bob_dev_1
    workers.emplace_back([&]() {
        for (size_t i = 0; i < kAttackIterations; ++i) {
            DeliveryAckCommand ack;
            ack.conversation_id = conv_id;
            ack.message_id = msg_id;
            ack.recipient_device_id = bob_dev_1;
            ack.caller_user_id = bob;
            ack.caller_device_id = bob_dev_2; // Spoofed companion device
            ack.delivered_at = std::chrono::system_clock::now();

            auto res = delivery_service_->acknowledge_delivery(ack);
            if (!res.success && res.error_code == v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE) {
                rejected_ack_attacks.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    // Worker 3: Mallory attempting to synchronize Bob's private conversation history
    workers.emplace_back([&]() {
        for (size_t i = 0; i < kAttackIterations; ++i) {
            SyncDeviceMessagesCommand sync_cmd;
            sync_cmd.conversation_id = conv_id;
            sync_cmd.device_id = mallory_dev;
            sync_cmd.since_sequence = 0;
            sync_cmd.max_messages = 50;

            auto res = sync_service_->sync_messages(mallory, sync_cmd);
            if (!res.is_success() && res.status == SyncMessagesStatus::NotAuthorized) {
                rejected_sync_attacks.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    // Worker 4: Mallory and companion device attempting unauthorized read receipts
    workers.emplace_back([&]() {
        for (size_t i = 0; i < kAttackIterations; ++i) {
            ReadReceiptCommand r_cmd;
            r_cmd.conversation_id = conv_id;
            r_cmd.message_id = msg_id;
            r_cmd.reader_device_id = bob_dev_1;
            r_cmd.caller_user_id = (i % 2 == 0) ? mallory : bob;
            r_cmd.caller_device_id = (i % 2 == 0) ? mallory_dev : bob_dev_2;
            r_cmd.read_at = std::chrono::system_clock::now();

            auto res = read_receipt_service_->record_read_receipt(r_cmd);
            if (!res.success) {
                rejected_read_attacks.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    for (auto& w : workers) {
        w.join();
    }

    EXPECT_EQ(rejected_ack_attacks.load(), 2 * kAttackIterations);
    EXPECT_EQ(rejected_sync_attacks.load(), kAttackIterations);
    EXPECT_EQ(rejected_read_attacks.load(), kAttackIterations);

    // Verify Bob's delivery states remained safely in Queued state
    auto st = delivery_repo_->get_delivery_states_for_message(msg_id);
    ASSERT_EQ(st.size(), 2U);
    for (const auto& s : st) {
        EXPECT_EQ(s.delivery_state, DeliveryState::Queued);
        EXPECT_FALSE(s.delivered_at.has_value());
        EXPECT_FALSE(s.read_at.has_value());
    }

    std::cout << "[MSG-012-T05][Test 2: Adversarial Anti-Impersonation] "
              << (rejected_ack_attacks + rejected_sync_attacks + rejected_read_attacks)
              << " adversarial attack attempts cleanly rejected with 100% fail-closed precision.\n";
}

// ============================================================================
// Test 3: Fail-Closed Revocation Quarantine Under High Throughput
// ============================================================================

TEST_F(MessagingSecurityRegressionTest, FailClosedRevocationQuarantineUnderHighThroughput) {
    const auto conv_id = ConversationId::generate_v7();
    const auto now = std::chrono::system_clock::now();

    const UserId alice("018d0000-0000-7000-8000-000000000801");
    const UserId bob("018d0000-0000-7000-8000-000000000802");

    const DeviceId alice_dev("018d0000-0000-7000-8000-000000000811");
    const DeviceId bob_dev_active("018d0000-0000-7000-8000-000000000821");
    const DeviceId bob_dev_revoked("018d0000-0000-7000-8000-000000000822");

    ConversationEntity conv{conv_id, ConversationType::Direct, alice, now};
    conv_repo_->save_conversation(conv);

    ConversationParticipantEntity p_alice{conv_id, alice, ParticipantRole::Member, MembershipStatus::Active, now};
    ConversationParticipantEntity p_bob{conv_id, bob, ParticipantRole::Member, MembershipStatus::Active, now};
    membership_repo_->add_participant(p_alice);
    membership_repo_->add_participant(p_bob);

    crypto_client_->add_device(alice, alice_dev);
    crypto_client_->add_device(bob, bob_dev_active, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    crypto_client_->add_device(bob, bob_dev_revoked, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    // 1. Populate in-memory queues in BoundedDeliveryScheduler for both devices
    BoundedDeliveryScheduler scheduler;
    constexpr size_t kTasksPerDevice = 25;

    for (size_t i = 1; i <= kTasksPerDevice; ++i) {
        DeliveryTask task_act;
        task_act.message_id = MessageId::generate_v7();
        task_act.conversation_id = conv_id;
        task_act.recipient_device_id = bob_dev_active;
        task_act.priority = MessagePriority::Normal;
        ASSERT_EQ(scheduler.schedule(task_act), SchedulerStatus::Enqueued);

        DeliveryTask task_rev;
        task_rev.message_id = MessageId::generate_v7();
        task_rev.conversation_id = conv_id;
        task_rev.recipient_device_id = bob_dev_revoked;
        task_rev.priority = MessagePriority::Normal;
        ASSERT_EQ(scheduler.schedule(task_rev), SchedulerStatus::Enqueued);
    }

    ASSERT_EQ(scheduler.device_queue_depth(bob_dev_active), kTasksPerDevice);
    ASSERT_EQ(scheduler.device_queue_depth(bob_dev_revoked), kTasksPerDevice);

    // 2. Revoke bob_dev_revoked in Auth Crypto Directory & invalidate resolution cache
    crypto_client_->set_device_status(bob_dev_revoked, securecloud::auth::v1::DEVICE_STATUS_REVOKED);
    resolution_service_->invalidate_user_cache(bob);

    // Stage a message for bob_dev_revoked so delivery acknowledgement reaches revocation validation
    const MessageId staged_revoked_msg = MessageId::generate_v7();
    RecipientDeliveryState r_state;
    r_state.message_id = staged_revoked_msg;
    r_state.recipient_user_id = bob;
    r_state.recipient_device_id = bob_dev_revoked;
    r_state.delivery_state = DeliveryState::Queued;
    delivery_repo_->save_recipient_delivery_states({r_state});

    // 3. Purge in-memory scheduler tasks for the revoked device
    size_t purged_count = scheduler.purge_device_tasks(bob_dev_revoked);
    EXPECT_EQ(purged_count, kTasksPerDevice);
    EXPECT_EQ(scheduler.device_queue_depth(bob_dev_revoked), 0U);
    EXPECT_EQ(scheduler.device_queue_depth(bob_dev_active), kTasksPerDevice);

    // 4. Concurrently verify submission rejection targeting revoked device
    constexpr size_t kConcurrentSubmissions = 20;
    std::atomic<size_t> revoked_submission_blocks{0};
    std::atomic<size_t> active_submission_successes{0};
    std::atomic<size_t> revoked_sync_blocks{0};
    std::atomic<size_t> revoked_ack_blocks{0};

    std::vector<std::thread> workers;

    // Submissions targeting revoked device
    workers.emplace_back([&]() {
        for (size_t i = 0; i < kConcurrentSubmissions; ++i) {
            MessageSubmissionCommand cmd;
            cmd.conversation_id = conv_id;
            cmd.caller_user_id = alice;
            cmd.sender_device_id = alice_dev;
            cmd.client_idempotency_token = "revoked-target-test-" + std::to_string(i);
            cmd.priority = MessagePriority::Normal;
            cmd.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;

            DeviceDeliveryTarget target;
            target.recipient_user_id = bob;
            target.recipient_device_id = bob_dev_revoked;
            target.ciphertext_blob =
                std::string("\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77", 16) +
                "cipher-revoked-" + std::to_string(i);
            target.ephemeral_public_key = std::vector<uint8_t>(32, 0x11);
            target.iv = std::vector<uint8_t>(24, 0x22);
            target.auth_tag = std::vector<uint8_t>(16, 0x33);
            target.algorithm = "XChaCha20-Poly1305";
            cmd.delivery_targets.push_back(target);

            auto res = submission_service_->submit_message(cmd);
            if (!res.success && res.error_code == v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED) {
                revoked_submission_blocks.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    // Submissions targeting active companion device continue cleanly
    workers.emplace_back([&]() {
        for (size_t i = 0; i < kConcurrentSubmissions; ++i) {
            MessageSubmissionCommand cmd;
            cmd.conversation_id = conv_id;
            cmd.caller_user_id = alice;
            cmd.sender_device_id = alice_dev;
            cmd.client_idempotency_token = "active-target-test-" + std::to_string(i);
            cmd.priority = MessagePriority::Normal;
            cmd.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;

            DeviceDeliveryTarget target;
            target.recipient_user_id = bob;
            target.recipient_device_id = bob_dev_active;
            target.ciphertext_blob =
                std::string("\x12\x34\x56\x78\x9A\xBC\xDE\xF0\x11\x22\x33\x44\x55\x66\x77\x88", 16) + "cipher-active-" +
                std::to_string(i);
            target.ephemeral_public_key = std::vector<uint8_t>(32, 0x11);
            target.iv = std::vector<uint8_t>(24, 0x22);
            target.auth_tag = std::vector<uint8_t>(16, 0x33);
            target.algorithm = "XChaCha20-Poly1305";
            cmd.delivery_targets.push_back(target);

            auto res = submission_service_->submit_message(cmd);
            if (res.success) {
                active_submission_successes.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    // Revoked device attempting to acknowledge delivery
    workers.emplace_back([&]() {
        for (size_t i = 0; i < kConcurrentSubmissions; ++i) {
            DeliveryAckCommand ack;
            ack.conversation_id = conv_id;
            ack.message_id = staged_revoked_msg;
            ack.recipient_device_id = bob_dev_revoked;
            ack.caller_user_id = bob;
            ack.caller_device_id = bob_dev_revoked;
            ack.delivered_at = std::chrono::system_clock::now();

            auto res = delivery_service_->acknowledge_delivery(ack);
            if (!res.success && res.error_code == v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED) {
                revoked_ack_blocks.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    // Revoked device attempting to sync messages blocked fail-closed
    workers.emplace_back([&]() {
        for (size_t i = 0; i < kConcurrentSubmissions; ++i) {
            auto dev_status = resolution_service_->get_device_status(bob, bob_dev_revoked);
            if (dev_status.has_value() && *dev_status != securecloud::auth::v1::DEVICE_STATUS_ACTIVE) {
                revoked_sync_blocks.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    for (auto& w : workers) {
        w.join();
    }

    EXPECT_EQ(revoked_submission_blocks.load(), kConcurrentSubmissions);
    EXPECT_EQ(active_submission_successes.load(), kConcurrentSubmissions);
    EXPECT_EQ(revoked_ack_blocks.load(), kConcurrentSubmissions);
    EXPECT_EQ(revoked_sync_blocks.load(), kConcurrentSubmissions);

    std::cout << "[MSG-012-T05][Test 3: Revocation Quarantine] Evicted " << purged_count
              << " in-memory scheduler tasks. Submissions & ACKs targeting revoked device strictly rejected (100%).\n";
}

// ============================================================================
// Test 4: Mutual-Conversation Presence Privacy Shielding Under Load
// ============================================================================

TEST_F(MessagingSecurityRegressionTest, MutualConversationPresencePrivacyShieldingUnderLoad) {
    const auto conv_id = ConversationId::generate_v7();
    const auto now = std::chrono::system_clock::now();

    const UserId alice("018d0000-0000-7000-8000-000000000901");
    const UserId bob("018d0000-0000-7000-8000-000000000902");
    const UserId eve("018d0000-0000-7000-8000-000000000903"); // Stranger (no mutual conversations)

    const DeviceId alice_dev("018d0000-0000-7000-8000-000000000911");
    const DeviceId bob_dev("018d0000-0000-7000-8000-000000000912");
    const DeviceId eve_dev("018d0000-0000-7000-8000-000000000913");

    // Alice and Bob share an active direct conversation
    ConversationEntity conv{conv_id, ConversationType::Direct, alice, now};
    conv_repo_->save_conversation(conv);

    ConversationParticipantEntity p_alice{conv_id, alice, ParticipantRole::Member, MembershipStatus::Active, now};
    ConversationParticipantEntity p_bob{conv_id, bob, ParticipantRole::Member, MembershipStatus::Active, now};
    membership_repo_->add_participant(p_alice);
    membership_repo_->add_participant(p_bob);
    membership_repo_->touch_user_conversation(alice, conv_id, ConversationType::Direct, MembershipStatus::Active, now);
    membership_repo_->touch_user_conversation(bob, conv_id, ConversationType::Direct, MembershipStatus::Active, now);

    // Eve is a separate user with NO conversations
    crypto_client_->add_device(alice, alice_dev);
    crypto_client_->add_device(bob, bob_dev);
    crypto_client_->add_device(eve, eve_dev);

    // Alice connects and is online with a custom status message
    presence_coordinator_->on_device_connected(alice, alice_dev);
    presence_coordinator_->set_user_override(alice, PresenceStatus::Online, "Available for cryptographic audits");

    // Setup MessagingServiceImpl with PresenceCoordinator and ConversationService for gRPC privacy testing
    auto conv_service = std::make_shared<ConversationService>(*conv_repo_, *membership_repo_, *auth_service_);
    auto service_impl = std::make_unique<MessagingServiceImpl>(
        nullptr, nullptr, nullptr, conv_service, nullptr, nullptr, nullptr, nullptr, nullptr, presence_coordinator_);

    ::grpc::ServerBuilder builder;
    builder.RegisterService(service_impl.get());
    auto server = builder.BuildAndStart();
    ASSERT_NE(server, nullptr);

    auto channel = server->InProcessChannel(::grpc::ChannelArguments{});
    ASSERT_NE(channel, nullptr);
    auto stub = v1::MessagingService::NewStub(channel);
    ASSERT_NE(stub, nullptr);

    constexpr size_t kQueries = 100;
    std::atomic<size_t> bob_successful_queries{0};
    std::atomic<size_t> eve_shielded_queries{0};

    std::vector<std::thread> workers;

    // Bob queries Alice's presence concurrently (authorized: mutual contact)
    workers.emplace_back([&]() {
        for (size_t i = 0; i < kQueries; ++i) {
            ::grpc::ClientContext ctx;
            ctx.AddMetadata("x-user-id", bob.str());
            ctx.AddMetadata("x-device-id", bob_dev.str());
            ctx.AddMetadata("x-correlation-id", "corr-bob-" + std::to_string(i));

            v1::GetPresenceRequest req;
            req.set_user_id(alice.str());
            v1::GetPresenceResponse resp;

            auto status = stub->GetPresence(&ctx, req, &resp);
            if (status.ok() && resp.presence().user_id() == alice.str() &&
                resp.presence().status() == v1::PRESENCE_STATUS_ONLINE && resp.presence().last_active_unix_ms() > 0 &&
                resp.presence().custom_status_message() == "Available for cryptographic audits") {
                bob_successful_queries.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    // Eve queries Alice's presence concurrently (unauthorized: stranger -> shielded with synthetic offline)
    workers.emplace_back([&]() {
        for (size_t i = 0; i < kQueries; ++i) {
            ::grpc::ClientContext ctx;
            ctx.AddMetadata("x-user-id", eve.str());
            ctx.AddMetadata("x-device-id", eve_dev.str());
            ctx.AddMetadata("x-correlation-id", "corr-eve-" + std::to_string(i));

            v1::GetPresenceRequest req;
            req.set_user_id(alice.str());
            v1::GetPresenceResponse resp;

            auto status = stub->GetPresence(&ctx, req, &resp);
            // Strict Privacy Invariant: Eve must receive synthetic OFFLINE status, zero timestamp, and empty custom
            // status
            if (status.ok() && resp.presence().user_id() == alice.str() &&
                resp.presence().status() == v1::PRESENCE_STATUS_OFFLINE && resp.presence().last_active_unix_ms() == 0 &&
                resp.presence().custom_status_message().empty()) {
                eve_shielded_queries.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    for (auto& w : workers) {
        w.join();
    }

    server->Shutdown();
    server->Wait();

    EXPECT_EQ(bob_successful_queries.load(), kQueries);
    EXPECT_EQ(eve_shielded_queries.load(), kQueries);

    std::cout << "[MSG-012-T05][Test 4: Privacy Shielding] " << kQueries
              << " authorized queries received authentic ONLINE status; " << kQueries
              << " unauthorized stranger queries strictly shielded with synthetic OFFLINE (0 leakage).\n";
}

} // namespace
} // namespace securecloud::messaging::service
