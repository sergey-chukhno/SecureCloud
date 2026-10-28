#include "domain/conversation_entity.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/message_entity.hpp"
#include "domain/outbox_event.hpp"
#include "domain/read_receipt_types.hpp"
#include "domain/submission_types.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/delivery_service.hpp"
#include "service/delivery_state_transition_guard.hpp"
#include "service/idempotency_guard.hpp"
#include "service/in_memory_sequence_allocator.hpp"
#include "service/message_submission_service.hpp"
#include "service/read_receipt_commands.hpp"
#include "service/read_receipt_service.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::service {
namespace {

using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationOutboxEventType;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryState;
using domain::DeviceDeliveryRecord;
using domain::DeviceDeliveryTarget;
using domain::DeviceId;
using domain::IdempotencyRecord;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::MessageSubmissionCommand;
using domain::ParticipantRole;
using domain::ReadState;
using domain::RecipientDeliveryState;
using domain::UserId;

// ============================================================================
// Thread-Safe In-Memory Repositories for High-Concurrency Stress Testing
// ============================================================================

class ThreadSafeMessageRepo final : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override {
        std::lock_guard<std::mutex> lock(mutex_);
        saved_count_++;
        messages_[msg.conversation_id.to_string()].push_back(msg);
    }

    std::optional<MessageEntity> find_by_id(const ConversationId& conv, const MessageBucket& /*bucket*/,
                                            const MessageId& id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = messages_.find(conv.to_string());
        if (it == messages_.end()) {
            return std::nullopt;
        }
        for (const auto& m : it->second) {
            if (m.message_id == id) {
                return m;
            }
        }
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId& conv,
                                                               const MessageBucket& /*bucket*/, uint64_t from,
                                                               uint64_t to, size_t limit) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<MessageEntity> out;
        auto it = messages_.find(conv.to_string());
        if (it == messages_.end()) {
            return out;
        }
        for (const auto& m : it->second) {
            if (m.message_sequence >= from && m.message_sequence <= to) {
                out.push_back(m);
                if (out.size() >= limit) {
                    break;
                }
            }
        }
        return out;
    }

    uint64_t get_last_sequence(const ConversationId& conv, const MessageBucket& /*bucket*/) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = messages_.find(conv.to_string());
        if (it == messages_.end() || it->second.empty()) {
            return 0;
        }
        uint64_t max_seq = 0;
        for (const auto& m : it->second) {
            max_seq = std::max(max_seq, m.message_sequence);
        }
        return max_seq;
    }

    size_t saved_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return saved_count_;
    }

  private:
    mutable std::mutex mutex_;
    size_t saved_count_{0};
    std::unordered_map<std::string, std::vector<MessageEntity>> messages_;
};

class ThreadSafeDeliveryStateRepo final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_batches_saved_++;
        for (const auto& rec : records) {
            pending_[rec.device_id.str()].push_back(rec);
        }
    }

    std::vector<DeviceDeliveryRecord>
    fetch_pending_for_device(const DeviceId& device_id, const std::string& delivery_bucket, size_t limit) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DeviceDeliveryRecord> result;
        auto it = pending_.find(device_id.str());
        if (it == pending_.end()) {
            return result;
        }
        for (const auto& rec : it->second) {
            if (delivery_bucket.empty() || rec.delivery_bucket == delivery_bucket) {
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
                                       const MessageId& message_id, DeliveryState state, int32_t attempt_count,
                                       std::optional<std::chrono::system_clock::time_point> next_retry) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pending_.find(device_id.str());
        if (it == pending_.end()) {
            return;
        }
        for (auto& rec : it->second) {
            if (rec.delivery_bucket == delivery_bucket && rec.accepted_at == accepted_at &&
                rec.message_id == message_id) {
                // Enforce monotonic guard against backward state regression
                if (!DeliveryStateTransitionGuard::is_regression(rec.delivery_state, state)) {
                    rec.delivery_state = state;
                    rec.attempt_count = attempt_count;
                    rec.next_retry_at = next_retry;
                }
                break;
            }
        }
    }

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& s : states) {
            recipient_states_[s.message_id].push_back(s);
        }
    }

    void record_delivery_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point& delivered_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        delivery_ack_commits_++;
        auto it = recipient_states_.find(message_id);
        if (it != recipient_states_.end()) {
            for (auto& s : it->second) {
                if (s.recipient_device_id == recipient_device_id) {
                    // Non-Conflation Axiom (ADR-008): Per-device DeliveryState terminates at Delivered;
                    // s.read_at is NEVER overwritten or cleared by a delivery ACK.
                    if (!DeliveryStateTransitionGuard::is_regression(s.delivery_state, DeliveryState::Delivered)) {
                        s.delivery_state = DeliveryState::Delivered;
                        if (!s.delivered_at.has_value()) {
                            s.delivered_at = delivered_at;
                        }
                    }
                    break;
                }
            }
        }
    }

    void record_read_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                         const std::chrono::system_clock::time_point& read_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        read_ack_commits_++;
        auto it = recipient_states_.find(message_id);
        if (it != recipient_states_.end()) {
            for (auto& s : it->second) {
                if (s.recipient_device_id == recipient_device_id) {
                    // Non-Conflation Axiom (ADR-008): Recording a read receipt sets read_at for logical
                    // recipient aggregation without conflating per-device DeliveryState into Read.
                    if (!s.read_at.has_value()) {
                        s.read_at = read_at;
                    }
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

    size_t pending_batches_saved() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pending_batches_saved_;
    }

    size_t delivery_ack_commits() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return delivery_ack_commits_;
    }

    size_t read_ack_commits() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return read_ack_commits_;
    }

  private:
    mutable std::mutex mutex_;
    size_t pending_batches_saved_{0};
    size_t delivery_ack_commits_{0};
    size_t read_ack_commits_{0};
    std::unordered_map<std::string, std::vector<DeviceDeliveryRecord>> pending_;
    std::unordered_map<MessageId, std::vector<RecipientDeliveryState>> recipient_states_;
};

class ThreadSafeOutboxRepo final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string& /*bucket*/) override {
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

    size_t count_by_type(ConversationOutboxEventType type) const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& ev : events_) {
            if (ev.event_type == type) {
                ++count;
            }
        }
        return count;
    }

  private:
    mutable std::mutex mutex_;
    std::vector<ConversationOutboxEvent> events_;
};

class ThreadSafeIdempotencyRepo final : public repository::IIdempotencyRepository {
  public:
    std::optional<IdempotencyRecord> find_submission(const DeviceId& sender_device_id,
                                                     const std::string& idempotency_key) override {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto key = sender_device_id.str() + ":" + idempotency_key;
        auto it = records_.find(key);
        if (it != records_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void save_submission(const IdempotencyRecord& record) override {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto key = record.sender_device_id.str() + ":" + record.idempotency_key;
        records_[key] = record;
    }

  private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, IdempotencyRecord> records_;
};

// ============================================================================
// Test Fixture for MSG-012-T01 Stress Harness
// ============================================================================

class MessagingConcurrencyStressTest : public ::testing::Test {
  protected:
    void SetUp() override {
        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        membership_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *membership_repo_);
        sequence_allocator_ = std::make_shared<InMemorySequenceAllocator>();
        idempotency_repo_ = std::make_shared<ThreadSafeIdempotencyRepo>();
        idempotency_guard_ = std::make_shared<MessageSubmissionIdempotencyGuard>(idempotency_repo_);
        message_repo_ = std::make_shared<ThreadSafeMessageRepo>();
        delivery_repo_ = std::make_shared<ThreadSafeDeliveryStateRepo>();
        outbox_repo_ = std::make_shared<ThreadSafeOutboxRepo>();

        submission_service_ = std::make_shared<MessageSubmissionService>(
            auth_service_, sequence_allocator_, idempotency_guard_, message_repo_, delivery_repo_, outbox_repo_);

        delivery_service_ = std::make_shared<DeliveryService>(delivery_repo_, outbox_repo_);
        read_receipt_service_ = std::make_shared<ReadReceiptService>(delivery_repo_, membership_repo_, outbox_repo_);

        conv_id_ = ConversationId::generate_v7();
        alice_user_ = UserId("018f1234-5678-7000-8000-000000000001");
        bob_user_ = UserId("018f1234-5678-7000-8000-000000000002");
        carol_user_ = UserId("018f1234-5678-7000-8000-000000000003");

        alice_dev_1_ = DeviceId("018f1234-5678-7000-8000-0000000000a1");
        bob_dev_1_ = DeviceId("018f1234-5678-7000-8000-0000000000b1");
        bob_dev_2_ = DeviceId("018f1234-5678-7000-8000-0000000000b2");
        carol_dev_1_ = DeviceId("018f1234-5678-7000-8000-0000000000c1");

        const auto now = std::chrono::system_clock::now();
        ConversationEntity conv;
        conv.conversation_id = conv_id_;
        conv.type = ConversationType::Group;
        conv.created_by_user_id = alice_user_;
        conv.created_at = now;
        conv.metadata_version = 1;
        conv_repo_->save_conversation(conv);

        for (const auto& uid : {alice_user_, bob_user_, carol_user_}) {
            ConversationParticipantEntity part;
            part.conversation_id = conv_id_;
            part.user_id = uid;
            part.role = (uid == alice_user_) ? ParticipantRole::Admin : ParticipantRole::Member;
            part.status = MembershipStatus::Active;
            part.joined_at = now;
            membership_repo_->add_participant(part);
        }
    }

    MessageSubmissionCommand make_valid_submission_command(const std::string& idempotency_token,
                                                           const std::string& ciphertext_prefix) const {
        MessageSubmissionCommand cmd;
        cmd.caller_user_id = alice_user_;
        cmd.sender_device_id = alice_dev_1_;
        cmd.conversation_id = conv_id_;
        cmd.client_idempotency_token = idempotency_token;

        DeviceDeliveryTarget target_b1;
        target_b1.recipient_user_id = bob_user_;
        target_b1.recipient_device_id = bob_dev_1_;
        target_b1.ciphertext_blob = ciphertext_prefix + "_BOB_DEV_1";
        target_b1.ephemeral_public_key = std::vector<uint8_t>(32, 0x11);
        target_b1.iv = std::vector<uint8_t>(24, 0x22);
        target_b1.auth_tag = std::vector<uint8_t>(16, 0x33);
        target_b1.algorithm = "XChaCha20-Poly1305";

        DeviceDeliveryTarget target_b2;
        target_b2.recipient_user_id = bob_user_;
        target_b2.recipient_device_id = bob_dev_2_;
        target_b2.ciphertext_blob = ciphertext_prefix + "_BOB_DEV_2";
        target_b2.ephemeral_public_key = std::vector<uint8_t>(32, 0x44);
        target_b2.iv = std::vector<uint8_t>(24, 0x55);
        target_b2.auth_tag = std::vector<uint8_t>(16, 0x66);
        target_b2.algorithm = "XChaCha20-Poly1305";

        cmd.delivery_targets = {target_b1, target_b2};
        return cmd;
    }

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> membership_repo_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<InMemorySequenceAllocator> sequence_allocator_;
    std::shared_ptr<ThreadSafeIdempotencyRepo> idempotency_repo_;
    std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard_;
    std::shared_ptr<ThreadSafeMessageRepo> message_repo_;
    std::shared_ptr<ThreadSafeDeliveryStateRepo> delivery_repo_;
    std::shared_ptr<ThreadSafeOutboxRepo> outbox_repo_;

    std::shared_ptr<MessageSubmissionService> submission_service_;
    std::shared_ptr<DeliveryService> delivery_service_;
    std::shared_ptr<ReadReceiptService> read_receipt_service_;

    ConversationId conv_id_;
    UserId alice_user_;
    UserId bob_user_;
    UserId carol_user_;
    DeviceId alice_dev_1_;
    DeviceId bob_dev_1_;
    DeviceId bob_dev_2_;
    DeviceId carol_dev_1_;
};

// ============================================================================
// 1. 100-Thread Concurrent Duplicate Submission Stress Test
// ============================================================================

TEST_F(MessagingConcurrencyStressTest, HundredThreadsIdenticalIdempotencyTokenAllocatesSingleSequence) {
    constexpr size_t kNumThreads = 100;
    const MessageSubmissionCommand cmd =
        make_valid_submission_command("idem-stress-token-001", "OPAQUE_E2E_CIPHERTEXT");

    std::atomic<size_t> ready_count{0};
    std::atomic<bool> start_gun{false};

    std::vector<ServiceResult<MessageSubmissionResponse>> results(
        kNumThreads, ServiceResult<MessageSubmissionResponse>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "init"));
    std::vector<std::thread> workers;
    workers.reserve(kNumThreads);

    for (size_t i = 0; i < kNumThreads; ++i) {
        workers.emplace_back([&, i]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (!start_gun.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            results[i] = submission_service_->submit_message(cmd);
        });
    }

    while (ready_count.load(std::memory_order_acquire) < kNumThreads) {
        std::this_thread::yield();
    }
    start_gun.store(true, std::memory_order_release);

    for (auto& t : workers) {
        t.join();
    }

    size_t original_commits = 0;
    size_t replay_commits = 0;
    std::optional<MessageId> canonical_msg_id;
    std::optional<std::chrono::system_clock::time_point> canonical_accepted_at;

    for (size_t i = 0; i < kNumThreads; ++i) {
        ASSERT_TRUE(results[i].success) << "Thread " << i << " failed: " << results[i].error_message;
        const auto& resp = results[i].value;
        EXPECT_EQ(resp.conversation_id, conv_id_);
        EXPECT_EQ(resp.message_sequence, 1u);

        if (!canonical_msg_id.has_value()) {
            canonical_msg_id = resp.message_id;
            canonical_accepted_at = resp.accepted_at;
        } else {
            EXPECT_EQ(resp.message_id, *canonical_msg_id);
            EXPECT_EQ(resp.accepted_at, *canonical_accepted_at);
        }

        if (resp.is_replay) {
            ++replay_commits;
        } else {
            ++original_commits;
        }
    }

    // Exactly 1 thread performed the original commit and 99 threads received the cached replay
    EXPECT_EQ(original_commits, 1u);
    EXPECT_EQ(replay_commits, kNumThreads - 1);

    // Zero duplicate sequence allocations, zero duplicate message rows, zero duplicate outbox events
    ASSERT_TRUE(canonical_accepted_at.has_value());
    const auto bucket = MessageBucket::from_time_point(*canonical_accepted_at);
    EXPECT_EQ(sequence_allocator_->peek_sequence(conv_id_, bucket), 1u);
    EXPECT_EQ(message_repo_->saved_count(), 1u);
    EXPECT_EQ(delivery_repo_->pending_batches_saved(), 1u);
    EXPECT_EQ(outbox_repo_->event_count(), 1u);
}

// ============================================================================
// 2. 100-Thread Conflicting Payload Detection Under Concurrency
// ============================================================================

TEST_F(MessagingConcurrencyStressTest, HundredThreadsConflictingPayloadsSameTokenDeterministicConflictDetection) {
    constexpr size_t kNumThreads = 100;
    const MessageSubmissionCommand valid_cmd =
        make_valid_submission_command("idem-conflict-token-002", "ORIGINAL_CIPHERTEXT_V1");
    const MessageSubmissionCommand conflicting_cmd =
        make_valid_submission_command("idem-conflict-token-002", "TAMPERED_CIPHERTEXT_V2");

    // Seed original submission first or let thread 0 race: to make which payload wins deterministic,
    // commit the canonical command once, then race 50 identical replays against 50 conflicting payloads.
    auto initial_res = submission_service_->submit_message(valid_cmd);
    ASSERT_TRUE(initial_res.success);
    EXPECT_FALSE(initial_res.value.is_replay);
    const MessageId expected_id = initial_res.value.message_id;

    std::atomic<size_t> ready_count{0};
    std::atomic<bool> start_gun{false};
    std::atomic<size_t> replay_successes{0};
    std::atomic<size_t> conflict_rejections{0};

    std::vector<std::thread> workers;
    workers.reserve(kNumThreads);

    for (size_t i = 0; i < kNumThreads; ++i) {
        workers.emplace_back([&, i]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (!start_gun.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            if (i % 2 == 0) {
                auto res = submission_service_->submit_message(valid_cmd);
                if (res.success && res.value.is_replay && res.value.message_id == expected_id &&
                    res.value.message_sequence == 1u) {
                    replay_successes.fetch_add(1, std::memory_order_relaxed);
                }
            } else {
                auto res = submission_service_->submit_message(conflicting_cmd);
                if (!res.success && res.error_code == v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT) {
                    conflict_rejections.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    while (ready_count.load(std::memory_order_acquire) < kNumThreads) {
        std::this_thread::yield();
    }
    start_gun.store(true, std::memory_order_release);

    for (auto& t : workers) {
        t.join();
    }

    EXPECT_EQ(replay_successes.load(), kNumThreads / 2);
    EXPECT_EQ(conflict_rejections.load(), kNumThreads / 2);
    EXPECT_EQ(message_repo_->saved_count(), 1u);
}

// ============================================================================
// 3. 1,000-Message Interleaved Delivery ACK & Read Receipt Race Harness
// ============================================================================

TEST_F(MessagingConcurrencyStressTest, ThousandMessagesConcurrentAckAndReadReceiptMonotonicNonConflation) {
    constexpr size_t kNumMessages = 1000;
    const auto base_time = std::chrono::system_clock::now();

    std::vector<MessageId> message_ids;
    message_ids.reserve(kNumMessages);

    // Stage 1,000 multi-device messages across Bob (2 devices) and Carol (1 device)
    for (size_t i = 0; i < kNumMessages; ++i) {
        const MessageId msg_id = MessageId::generate_v7();
        message_ids.push_back(msg_id);

        RecipientDeliveryState st_bob_1;
        st_bob_1.message_id = msg_id;
        st_bob_1.recipient_user_id = bob_user_;
        st_bob_1.recipient_device_id = bob_dev_1_;
        st_bob_1.delivery_state = DeliveryState::Delivering;

        RecipientDeliveryState st_bob_2;
        st_bob_2.message_id = msg_id;
        st_bob_2.recipient_user_id = bob_user_;
        st_bob_2.recipient_device_id = bob_dev_2_;
        st_bob_2.delivery_state = DeliveryState::Queued;

        RecipientDeliveryState st_carol_1;
        st_carol_1.message_id = msg_id;
        st_carol_1.recipient_user_id = carol_user_;
        st_carol_1.recipient_device_id = carol_dev_1_;
        st_carol_1.delivery_state = DeliveryState::Delivering;

        delivery_repo_->save_recipient_delivery_states({st_bob_1, st_bob_2, st_carol_1});
    }

    std::atomic<size_t> ready_count{0};
    std::atomic<bool> start_gun{false};
    constexpr size_t kTotalWorkers = 12;
    std::vector<std::thread> workers;
    workers.reserve(kTotalWorkers);

    // 4 threads concurrently acknowledging delivery for bob_dev_1 & carol_dev_1
    for (size_t w = 0; w < 4; ++w) {
        workers.emplace_back([&, w]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (!start_gun.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (size_t i = w; i < kNumMessages; i += 4) {
                DeliveryAckCommand ack_bob;
                ack_bob.message_id = message_ids[i];
                ack_bob.recipient_device_id = bob_dev_1_;
                ack_bob.caller_user_id = bob_user_;
                ack_bob.caller_device_id = bob_dev_1_;
                ack_bob.delivered_at = base_time + std::chrono::milliseconds(10);
                ack_bob.conversation_id = conv_id_;
                auto res_bob = delivery_service_->acknowledge_delivery(ack_bob);
                EXPECT_TRUE(res_bob.success);

                DeliveryAckCommand ack_carol;
                ack_carol.message_id = message_ids[i];
                ack_carol.recipient_device_id = carol_dev_1_;
                ack_carol.caller_user_id = carol_user_;
                ack_carol.caller_device_id = carol_dev_1_;
                ack_carol.delivered_at = base_time + std::chrono::milliseconds(15);
                ack_carol.conversation_id = conv_id_;
                auto res_carol = delivery_service_->acknowledge_delivery(ack_carol);
                EXPECT_TRUE(res_carol.success);
            }
        });
    }

    // 4 threads concurrently recording read receipts for bob_dev_1
    for (size_t w = 0; w < 4; ++w) {
        workers.emplace_back([&, w]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (!start_gun.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (size_t i = w; i < kNumMessages; i += 4) {
                ReadReceiptCommand read_cmd;
                read_cmd.conversation_id = conv_id_;
                read_cmd.message_id = message_ids[i];
                read_cmd.caller_user_id = bob_user_;
                read_cmd.caller_device_id = bob_dev_1_;
                read_cmd.reader_device_id = bob_dev_1_;
                read_cmd.read_at = base_time + std::chrono::milliseconds(20);
                auto res = read_receipt_service_->record_read_receipt(read_cmd);
                EXPECT_TRUE(res.success);
            }
        });
    }

    // 4 threads issuing delayed/duplicate delivery ACKs for bob_dev_1 + querying read status concurrently
    for (size_t w = 0; w < 4; ++w) {
        workers.emplace_back([&, w]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (!start_gun.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (size_t i = w; i < kNumMessages; i += 4) {
                DeliveryAckCommand delayed_ack;
                delayed_ack.message_id = message_ids[i];
                delayed_ack.recipient_device_id = bob_dev_1_;
                delayed_ack.caller_user_id = bob_user_;
                delayed_ack.caller_device_id = bob_dev_1_;
                delayed_ack.delivered_at = base_time + std::chrono::milliseconds(50);
                delayed_ack.conversation_id = conv_id_;
                auto res = delivery_service_->acknowledge_delivery(delayed_ack);
                EXPECT_TRUE(res.success);

                // Verify DeliveryStateTransitionGuard never permits Delivered -> Queued/Delivering/RetryWait
                EXPECT_TRUE(
                    DeliveryStateTransitionGuard::is_regression(DeliveryState::Delivered, DeliveryState::Queued));
                EXPECT_TRUE(
                    DeliveryStateTransitionGuard::is_regression(DeliveryState::Delivered, DeliveryState::Delivering));
                EXPECT_TRUE(
                    DeliveryStateTransitionGuard::is_regression(DeliveryState::Delivered, DeliveryState::RetryWait));
            }
        });
    }

    while (ready_count.load(std::memory_order_acquire) < kTotalWorkers) {
        std::this_thread::yield();
    }
    start_gun.store(true, std::memory_order_release);

    for (auto& t : workers) {
        t.join();
    }

    // Verify all 1,000 messages satisfy the Non-Conflation Axiom and monotonic state invariants
    for (size_t i = 0; i < kNumMessages; ++i) {
        const auto states = delivery_repo_->get_delivery_states_for_message(message_ids[i]);
        ASSERT_EQ(states.size(), 3u);

        for (const auto& st : states) {
            if (st.recipient_device_id == bob_dev_1_) {
                // Per-device DeliveryState terminates at Delivered (never conflated with Read)
                EXPECT_EQ(st.delivery_state, DeliveryState::Delivered);
                EXPECT_TRUE(st.delivered_at.has_value());
                // Read timestamp is preserved despite delayed delivery ACKs
                EXPECT_TRUE(st.read_at.has_value());
            } else if (st.recipient_device_id == bob_dev_2_) {
                // Companion device bob_dev_2 was never ACKed, so it remains independently Queued
                EXPECT_EQ(st.delivery_state, DeliveryState::Queued);
                EXPECT_FALSE(st.read_at.has_value());
            } else if (st.recipient_device_id == carol_dev_1_) {
                EXPECT_EQ(st.delivery_state, DeliveryState::Delivered);
                EXPECT_FALSE(st.read_at.has_value());
            }
        }

        // Verify logical per-user read status aggregation
        auto read_status_res = read_receipt_service_->get_message_read_status(conv_id_, message_ids[i], alice_user_);
        ASSERT_TRUE(read_status_res.success);
        EXPECT_EQ(read_status_res.value.total_recipients, 2u);
        EXPECT_EQ(read_status_res.value.read_recipients, 1u);

        for (const auto& rs : read_status_res.value.recipient_read_statuses) {
            if (rs.user_id == bob_user_) {
                EXPECT_EQ(rs.read_state, ReadState::Read);
                EXPECT_EQ(rs.reader_device_id, bob_dev_1_);
            } else if (rs.user_id == carol_user_) {
                EXPECT_EQ(rs.read_state, ReadState::Unread);
            }
        }
    }
}

// ============================================================================
// 4. 64-Thread Duplicate Delivery ACK & Read Receipt Lock-Stripe Verification
// ============================================================================

TEST_F(MessagingConcurrencyStressTest, ConcurrentDuplicateDeliveryAcksAndReadReceiptsEmitSingleOutboxEventEach) {
    constexpr size_t kThreadsPerOp = 64;
    const MessageId msg_id = MessageId::generate_v7();
    const auto fixed_time = std::chrono::system_clock::now();

    RecipientDeliveryState st_bob_1;
    st_bob_1.message_id = msg_id;
    st_bob_1.recipient_user_id = bob_user_;
    st_bob_1.recipient_device_id = bob_dev_1_;
    st_bob_1.delivery_state = DeliveryState::Delivering;
    delivery_repo_->save_recipient_delivery_states({st_bob_1});

    std::atomic<size_t> ready_count{0};
    std::atomic<bool> start_gun{false};
    std::atomic<size_t> ack_initial_count{0};
    std::atomic<size_t> ack_replay_count{0};
    std::atomic<size_t> read_initial_count{0};
    std::atomic<size_t> read_replay_count{0};

    std::vector<std::thread> workers;
    workers.reserve(kThreadsPerOp * 2);

    for (size_t i = 0; i < kThreadsPerOp; ++i) {
        workers.emplace_back([&]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (!start_gun.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            DeliveryAckCommand ack_cmd;
            ack_cmd.message_id = msg_id;
            ack_cmd.recipient_device_id = bob_dev_1_;
            ack_cmd.caller_user_id = bob_user_;
            ack_cmd.caller_device_id = bob_dev_1_;
            ack_cmd.delivered_at = fixed_time;
            ack_cmd.conversation_id = conv_id_;

            auto res = delivery_service_->acknowledge_delivery(ack_cmd);
            ASSERT_TRUE(res.success);
            if (res.value.is_idempotent_replay) {
                ack_replay_count.fetch_add(1, std::memory_order_relaxed);
            } else {
                ack_initial_count.fetch_add(1, std::memory_order_relaxed);
            }
        });

        workers.emplace_back([&]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (!start_gun.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            ReadReceiptCommand read_cmd;
            read_cmd.conversation_id = conv_id_;
            read_cmd.message_id = msg_id;
            read_cmd.caller_user_id = bob_user_;
            read_cmd.caller_device_id = bob_dev_1_;
            read_cmd.reader_device_id = bob_dev_1_;
            read_cmd.read_at = fixed_time + std::chrono::milliseconds(5);

            auto res = read_receipt_service_->record_read_receipt(read_cmd);
            ASSERT_TRUE(res.success);
            if (res.value.is_idempotent_replay) {
                read_replay_count.fetch_add(1, std::memory_order_relaxed);
            } else {
                read_initial_count.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    while (ready_count.load(std::memory_order_acquire) < kThreadsPerOp * 2) {
        std::this_thread::yield();
    }
    start_gun.store(true, std::memory_order_release);

    for (auto& t : workers) {
        t.join();
    }

    EXPECT_EQ(ack_initial_count.load(), 1u);
    EXPECT_EQ(ack_replay_count.load(), kThreadsPerOp - 1);
    EXPECT_EQ(read_initial_count.load(), 1u);
    EXPECT_EQ(read_replay_count.load(), kThreadsPerOp - 1);

    EXPECT_EQ(delivery_repo_->delivery_ack_commits(), 1u);
    EXPECT_EQ(delivery_repo_->read_ack_commits(), 1u);
    EXPECT_EQ(outbox_repo_->count_by_type(ConversationOutboxEventType::MessageDelivered), 1u);
    EXPECT_EQ(outbox_repo_->count_by_type(ConversationOutboxEventType::MessageRead), 1u);
}

// ============================================================================
// 5. 64-Thread InMemorySequenceAllocator 100,000-Sequence Contiguity Stress
// ============================================================================

TEST_F(MessagingConcurrencyStressTest, SixtyFourThreadsHundredThousandSequenceAllocationsZeroGapsOrDuplicates) {
    constexpr size_t kNumThreads = 64;
    constexpr size_t kTotalSequences = 100000;
    const auto bucket = MessageBucket::from_year_month(2026, 10);

    std::atomic<size_t> ready_count{0};
    std::atomic<bool> start_gun{false};

    std::vector<std::vector<uint64_t>> per_thread_sequences(kNumThreads);
    std::vector<std::thread> workers;
    workers.reserve(kNumThreads);

    const size_t base_per_thread = kTotalSequences / kNumThreads;
    const size_t remainder = kTotalSequences % kNumThreads;

    for (size_t t = 0; t < kNumThreads; ++t) {
        const size_t count_for_thread = base_per_thread + (t < remainder ? 1 : 0);
        per_thread_sequences[t].reserve(count_for_thread);

        workers.emplace_back([&, t, count_for_thread]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (!start_gun.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (size_t i = 0; i < count_for_thread; ++i) {
                const uint64_t seq = sequence_allocator_->allocate_sequence(conv_id_, bucket);
                per_thread_sequences[t].push_back(seq);
            }
        });
    }

    while (ready_count.load(std::memory_order_acquire) < kNumThreads) {
        std::this_thread::yield();
    }
    start_gun.store(true, std::memory_order_release);

    for (auto& w : workers) {
        w.join();
    }

    // Flatten and sort all 100,000 allocated sequences
    std::vector<uint64_t> all_sequences;
    all_sequences.reserve(kTotalSequences);
    for (const auto& vec : per_thread_sequences) {
        // Also assert per-thread observations are strictly increasing
        for (size_t i = 1; i < vec.size(); ++i) {
            EXPECT_GT(vec[i], vec[i - 1]);
        }
        all_sequences.insert(all_sequences.end(), vec.begin(), vec.end());
    }

    ASSERT_EQ(all_sequences.size(), kTotalSequences);
    std::sort(all_sequences.begin(), all_sequences.end());

    for (size_t i = 0; i < kTotalSequences; ++i) {
        ASSERT_EQ(all_sequences[i], static_cast<uint64_t>(i + 1)) << "Sequence gap or duplicate at index " << i;
    }

    EXPECT_EQ(sequence_allocator_->peek_sequence(conv_id_, bucket), kTotalSequences);
}

} // namespace
} // namespace securecloud::messaging::service
