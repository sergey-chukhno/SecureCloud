#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "client/auth_crypto_directory_client_interface.hpp"
#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/delivery_worker.hpp"
#include "delivery/device_connection_registry.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "domain/conversation_entity.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/envelope_types.hpp"
#include "domain/idempotency_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/message_entity.hpp"
#include "domain/outbox_event.hpp"
#include "domain/read_receipt_types.hpp"
#include "domain/submission_types.hpp"
#include "domain/sync_types.hpp"
#include "messaging/db/embedded_migrations.hpp"
#include "messaging/db/migration_runner.hpp"
#include "messaging/db/mock_scylla_session.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "messaging/repository/scylla_conversation_repository.hpp"
#include "messaging/repository/scylla_delivery_state_repository.hpp"
#include "messaging/repository/scylla_idempotency_repository.hpp"
#include "messaging/repository/scylla_membership_repository.hpp"
#include "messaging/repository/scylla_message_repository.hpp"
#include "messaging/repository/scylla_outbox_repository.hpp"
#include "messaging/repository/scylla_sync_cursor_repository.hpp"
#include "messaging/repository/sync_cursor_repository_interface.hpp"
#include "securecloud/auth/v1/auth.pb.h"
#include "service/conversation_authorization_service.hpp"
#include "service/delivery_retry_policy.hpp"
#include "service/delivery_service.hpp"
#include "service/delivery_state_transition_guard.hpp"
#include "service/e2e_envelope_validator.hpp"
#include "service/idempotency_guard.hpp"
#include "service/in_memory_sequence_allocator.hpp"
#include "service/message_submission_service.hpp"
#include "service/message_sync_service.hpp"
#include "service/recipient_device_resolution_service.hpp"
#include "service/sync_cursor_manager.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <gtest/gtest.h>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging {
namespace {

using client::CryptoDirectoryError;
using client::CryptoDirectoryErrorKind;
using client::DeviceCryptoRecord;
using client::IAuthCryptoDirectoryClient;
using delivery::BoundedDeliveryScheduler;
using delivery::DeliveryWorker;
using delivery::DeviceConnectionRegistry;
using delivery::MockDeviceDeliveryChannel;
using delivery::SchedulerStatus;
using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryState;
using domain::DeliveryTask;
using domain::DeviceDeliveryRecord;
using domain::DeviceDeliveryTarget;
using domain::DeviceId;
using domain::DeviceSyncCursor;
using domain::E2EAlgorithm;
using domain::E2EProtocolVersion;
using domain::IdempotencyRecord;
using domain::LogicalRecipientReadStatus;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageDeliverySummary;
using domain::MessageEntity;
using domain::MessageId;
using domain::MessagePriority;
using domain::MessageSubmissionCommand;
using domain::ParticipantRole;
using domain::ReadState;
using domain::RecipientDeliveryState;
using domain::UserId;

// ============================================================================
// High-Performance Thread-Safe Repositories with Partition Footprint Metering
// ============================================================================

class MeteredMessageRepository final : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override {
        std::lock_guard<std::mutex> lock(mu_);
        const std::string part_key = msg.conversation_id.to_string() + ":" + msg.message_bucket.value();
        auto& vec = partitions_[part_key];
        vec.push_back(msg);
        total_saved_++;

        const size_t row_bytes = msg.conversation_id.to_string().size() + msg.message_bucket.value().size() +
                                 sizeof(uint64_t) + msg.message_id.to_string().size() +
                                 msg.sender_user_id.str().size() + msg.sender_device_id.str().size() +
                                 msg.envelope.ciphertext.size() + 64U;
        partition_bytes_[part_key] += row_bytes;
    }

    std::optional<MessageEntity> find_by_id(const ConversationId& conv_id, const MessageBucket& bucket,
                                            const MessageId& msg_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        const std::string part_key = conv_id.to_string() + ":" + bucket.value();
        auto it = partitions_.find(part_key);
        if (it == partitions_.end()) {
            return std::nullopt;
        }
        for (const auto& m : it->second) {
            if (m.message_id == msg_id) {
                return m;
            }
        }
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId& conv_id,
                                                               const MessageBucket& bucket, uint64_t from_seq,
                                                               uint64_t to_seq, size_t limit) override {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<MessageEntity> result;
        const std::string part_key = conv_id.to_string() + ":" + bucket.value();
        auto it = partitions_.find(part_key);
        if (it == partitions_.end()) {
            return result;
        }
        result.reserve(std::min(limit, it->second.size()));
        for (const auto& m : it->second) {
            if (m.message_sequence >= from_seq && m.message_sequence <= to_seq) {
                result.push_back(m);
                if (result.size() >= limit) {
                    break;
                }
            }
        }
        return result;
    }

    uint64_t get_last_sequence(const ConversationId& conv_id, const MessageBucket& bucket) override {
        std::lock_guard<std::mutex> lock(mu_);
        const std::string part_key = conv_id.to_string() + ":" + bucket.value();
        auto it = partitions_.find(part_key);
        if (it == partitions_.end() || it->second.empty()) {
            return 0;
        }
        uint64_t max_seq = 0;
        for (const auto& m : it->second) {
            max_seq = std::max(max_seq, m.message_sequence);
        }
        return max_seq;
    }

    [[nodiscard]] size_t total_saved() const {
        std::lock_guard<std::mutex> lock(mu_);
        return total_saved_;
    }

    [[nodiscard]] size_t partition_bytes(const ConversationId& conv_id, const MessageBucket& bucket) const {
        std::lock_guard<std::mutex> lock(mu_);
        const std::string part_key = conv_id.to_string() + ":" + bucket.value();
        auto it = partition_bytes_.find(part_key);
        return (it != partition_bytes_.end()) ? it->second : 0U;
    }

  private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::vector<MessageEntity>> partitions_;
    std::unordered_map<std::string, size_t> partition_bytes_;
    size_t total_saved_{0};
};

class MeteredDeliveryStateRepository final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& r : records) {
            const std::string key = r.device_id.str() + ":" + r.message_id.to_string();
            records_by_dev_msg_[key] = r;
            records_by_dev_[r.device_id.str()].push_back(r);
            total_pending_saved_++;

            const std::string part_key = r.device_id.str() + ":" + r.delivery_bucket;
            const size_t row_bytes = r.device_id.str().size() + r.delivery_bucket.size() +
                                     r.message_id.to_string().size() + r.conversation_id.to_string().size() +
                                     r.ciphertext_blob.size() + r.ephemeral_public_key.size() + r.iv.size() +
                                     r.auth_tag.size() + 64U;
            device_partition_bytes_[part_key] += row_bytes;
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
            const std::string key = r.device_id.str() + ":" + r.message_id.to_string();
            const auto& latest = records_by_dev_msg_[key];
            if ((delivery_bucket.empty() || latest.delivery_bucket == delivery_bucket) &&
                (latest.delivery_state == DeliveryState::Queued || latest.delivery_state == DeliveryState::RetryWait)) {
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
        const std::string key = device_id.str() + ":" + message_id.to_string();
        auto it = records_by_dev_msg_.find(key);
        if (it != records_by_dev_msg_.end()) {
            it->second.delivery_state = state;
            it->second.attempt_count = attempt_count;
            it->second.next_retry_at = next_retry;
        }
    }

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& s : states) {
            states_by_msg_[s.message_id.to_string()][s.recipient_device_id.str()] = s;
            total_recipient_states_saved_++;
        }
    }

    void record_delivery_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point& delivered_at) override {
        update_delivery_state_monotonic(message_id, recipient_device_id, DeliveryState::Delivered, delivered_at);
    }

    void record_read_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                         const std::chrono::system_clock::time_point& read_at) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto msg_it = states_by_msg_.find(message_id.to_string());
        if (msg_it == states_by_msg_.end()) {
            return;
        }
        auto dev_it = msg_it->second.find(recipient_device_id.str());
        if (dev_it != msg_it->second.end() && !dev_it->second.read_at.has_value()) {
            dev_it->second.read_at = read_at;
        }
    }

    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<RecipientDeliveryState> out;
        auto it = states_by_msg_.find(message_id.to_string());
        if (it != states_by_msg_.end()) {
            out.reserve(it->second.size());
            for (const auto& [_, st] : it->second) {
                out.push_back(st);
            }
        }
        return out;
    }

    bool update_delivery_state_monotonic(const MessageId& message_id, const DeviceId& recipient_device_id,
                                         DeliveryState new_state,
                                         const std::chrono::system_clock::time_point& updated_at) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto msg_it = states_by_msg_.find(message_id.to_string());
        if (msg_it == states_by_msg_.end()) {
            return false;
        }
        auto dev_it = msg_it->second.find(recipient_device_id.str());
        if (dev_it == msg_it->second.end()) {
            return false;
        }
        auto& current = dev_it->second;
        if (service::DeliveryStateTransitionGuard::is_idempotent(current.delivery_state, new_state)) {
            return true;
        }
        if (!service::DeliveryStateTransitionGuard::can_transition(current.delivery_state, new_state)) {
            return false;
        }
        current.delivery_state = new_state;
        if (new_state == DeliveryState::Delivered && !current.delivered_at.has_value()) {
            current.delivered_at = updated_at;
        }
        const std::string key = recipient_device_id.str() + ":" + message_id.to_string();
        auto rec_it = records_by_dev_msg_.find(key);
        if (rec_it != records_by_dev_msg_.end()) {
            rec_it->second.delivery_state = new_state;
        }
        return true;
    }

    std::optional<MessageDeliverySummary> get_message_delivery_summary(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = states_by_msg_.find(message_id.to_string());
        if (it == states_by_msg_.end() || it->second.empty()) {
            return std::nullopt;
        }
        MessageDeliverySummary summary;
        summary.message_id = message_id;
        for (const auto& [_, st] : it->second) {
            summary.total_targets++;
            if (st.delivery_state == DeliveryState::Delivered) {
                summary.delivered_targets++;
            } else if (st.delivery_state == DeliveryState::Expired) {
                summary.expired_targets++;
            } else {
                summary.pending_targets++;
            }
        }
        return summary;
    }

    std::optional<DeviceDeliveryRecord> get_delivery_record_for_device(const DeviceId& device_id,
                                                                       const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        const std::string key = device_id.str() + ":" + message_id.to_string();
        auto it = records_by_dev_msg_.find(key);
        if (it != records_by_dev_msg_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] size_t total_pending_saved() const {
        std::lock_guard<std::mutex> lock(mu_);
        return total_pending_saved_;
    }

    [[nodiscard]] size_t total_recipient_states_saved() const {
        std::lock_guard<std::mutex> lock(mu_);
        return total_recipient_states_saved_;
    }

    [[nodiscard]] size_t device_partition_bytes(const DeviceId& device_id, const std::string& bucket) const {
        std::lock_guard<std::mutex> lock(mu_);
        const std::string part_key = device_id.str() + ":" + bucket;
        auto it = device_partition_bytes_.find(part_key);
        return (it != device_partition_bytes_.end()) ? it->second : 0U;
    }

  private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, DeviceDeliveryRecord> records_by_dev_msg_;
    std::unordered_map<std::string, std::vector<DeviceDeliveryRecord>> records_by_dev_;
    std::unordered_map<std::string, std::unordered_map<std::string, RecipientDeliveryState>> states_by_msg_;
    std::unordered_map<std::string, size_t> device_partition_bytes_;
    size_t total_pending_saved_{0};
    size_t total_recipient_states_saved_{0};
};

class FastIdempotencyRepository final : public repository::IIdempotencyRepository {
  public:
    std::optional<IdempotencyRecord> find_submission(const DeviceId& dev, const std::string& key) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = store_.find(dev.str() + ":" + key);
        if (it != store_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void save_submission(const IdempotencyRecord& rec) override {
        std::lock_guard<std::mutex> lock(mu_);
        store_[rec.sender_device_id.str() + ":" + rec.idempotency_key] = rec;
    }

  private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, IdempotencyRecord> store_;
};

class FastOutboxRepository final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& /*event*/, const std::string& /*bucket*/) override {
        enqueued_.fetch_add(1, std::memory_order_relaxed);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string& /*bucket*/,
                                                                    size_t /*limit*/) override {
        return {};
    }

    void mark_event_published(const std::string& /*bucket*/, std::chrono::system_clock::time_point /*created_at*/,
                              const std::string& /*event_id*/,
                              std::chrono::system_clock::time_point /*published_at*/) override {}

    [[nodiscard]] size_t enqueued_count() const noexcept { return enqueued_.load(std::memory_order_relaxed); }

  private:
    std::atomic<size_t> enqueued_{0};
};

class FastSyncCursorRepository final : public repository::ISyncCursorRepository {
  public:
    std::optional<DeviceSyncCursor> get_sync_cursor(const DeviceId& dev, const ConversationId& conv) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = cursors_.find(dev.str() + ":" + conv.to_string());
        if (it != cursors_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::vector<DeviceSyncCursor> list_sync_cursors_by_device(const DeviceId& dev) override {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<DeviceSyncCursor> out;
        for (const auto& [_, cur] : cursors_) {
            if (cur.device_id == dev) {
                out.push_back(cur);
            }
        }
        return out;
    }

    void upsert_sync_cursor(const DeviceSyncCursor& cursor) override {
        std::lock_guard<std::mutex> lock(mu_);
        cursors_[cursor.device_id.str() + ":" + cursor.conversation_id.to_string()] = cursor;
    }

  private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, DeviceSyncCursor> cursors_;
};

class FastAuthCryptoDirectoryClient final : public IAuthCryptoDirectoryClient {
  public:
    void set_user_devices(const UserId& user_id, std::vector<DeviceCryptoRecord> devices) {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& d : devices) {
            by_device_[d.device_id.str()] = d;
        }
        directory_[user_id.str()] = std::move(devices);
    }

    client::Result<std::vector<DeviceCryptoRecord>, CryptoDirectoryError>
    get_user_device_crypto_records(const UserId& user_id,
                                   std::chrono::milliseconds /*timeout*/ = std::chrono::milliseconds(2000)) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = directory_.find(user_id.str());
        if (it == directory_.end()) {
            return std::vector<DeviceCryptoRecord>{};
        }
        return it->second;
    }

    client::Result<DeviceCryptoRecord, CryptoDirectoryError>
    get_device_crypto_identity(const DeviceId& device_id,
                               std::chrono::milliseconds /*timeout*/ = std::chrono::milliseconds(2000)) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = by_device_.find(device_id.str());
        if (it != by_device_.end()) {
            return it->second;
        }
        return CryptoDirectoryError{
            .kind = CryptoDirectoryErrorKind::NotFound,
            .message = "Device not found",
            .grpc_code = ::grpc::StatusCode::NOT_FOUND,
        };
    }

  private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::vector<DeviceCryptoRecord>> directory_;
    std::unordered_map<std::string, DeviceCryptoRecord> by_device_;
};

DeviceCryptoRecord make_active_device_record(const UserId& user_id, const DeviceId& device_id) {
    DeviceCryptoRecord rec;
    rec.device_id = device_id;
    rec.user_id = user_id;
    rec.identity_key = std::vector<uint8_t>(32, 0xAA);
    rec.signed_prekey = std::vector<uint8_t>(32, 0xBB);
    rec.signed_prekey_signature = std::vector<uint8_t>(64, 0xCC);
    rec.one_time_prekey = std::vector<uint8_t>(32, 0xDD);
    rec.one_time_prekey_id = "otk-" + device_id.str();
    rec.status = securecloud::auth::v1::DEVICE_STATUS_ACTIVE;
    rec.identity_key_fingerprint = "fp-" + device_id.str();
    rec.signed_prekey_created_at_epoch_ms = 1000;
    rec.remaining_one_time_prekeys = 50;
    return rec;
}

DeviceDeliveryTarget make_valid_target(const UserId& recipient_user, const DeviceId& recipient_device,
                                       size_t payload_bytes, uint64_t msg_index) {
    DeviceDeliveryTarget target;
    target.recipient_user_id = recipient_user;
    target.recipient_device_id = recipient_device;

    // Non-ASCII high-entropy binary prefix + device tag so ZeroPlaintextGuard accepts it as valid E2E ciphertext
    std::string cipher("\x89\xAB\xCD\xEF\x91\xA2\xB3\xC4\xD5\xE6\xF7\x88", 12);
    cipher += recipient_device.str() + ":" + std::to_string(msg_index) + ":";
    if (payload_bytes > cipher.size()) {
        cipher.append(payload_bytes - cipher.size(), '\xA5');
    }
    target.ciphertext_blob = std::move(cipher);
    target.ephemeral_public_key = std::vector<uint8_t>(32, 0x42);
    target.iv = std::vector<uint8_t>(24, 0x24);
    target.auth_tag = std::vector<uint8_t>(16, 0x99);
    target.algorithm = "XChaCha20-Poly1305";
    target.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
    target.one_time_prekey_id = "otk-" + recipient_device.str();
    return target;
}

struct LatencyPercentiles {
    double p50_us{0.0};
    double p90_us{0.0};
    double p95_us{0.0};
    double p99_us{0.0};
    double mean_us{0.0};
};

LatencyPercentiles compute_percentiles(std::vector<double> samples_us) {
    LatencyPercentiles res;
    if (samples_us.empty()) {
        return res;
    }
    std::sort(samples_us.begin(), samples_us.end());
    const auto at_pct = [&](double pct) -> double {
        const size_t idx = std::min(samples_us.size() - 1,
                                    static_cast<size_t>(std::ceil(pct * static_cast<double>(samples_us.size()))) - 1);
        return samples_us[idx];
    };
    res.p50_us = at_pct(0.50);
    res.p90_us = at_pct(0.90);
    res.p95_us = at_pct(0.95);
    res.p99_us = at_pct(0.99);
    res.mean_us = std::accumulate(samples_us.begin(), samples_us.end(), 0.0) / static_cast<double>(samples_us.size());
    return res;
}

// ============================================================================
// MSG-012-T03 Capacity, Multi-Device Fan-Out & ScyllaDB Access Pattern Suite
// ============================================================================

class MessagingCapacityLoadTest : public ::testing::Test {
  protected:
    void SetUp() override {
        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        membership_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        msg_repo_ = std::make_shared<MeteredMessageRepository>();
        delivery_repo_ = std::make_shared<MeteredDeliveryStateRepository>();
        idempotency_repo_ = std::make_shared<FastIdempotencyRepository>();
        outbox_repo_ = std::make_shared<FastOutboxRepository>();
        sync_cursor_repo_ = std::make_shared<FastSyncCursorRepository>();
        crypto_client_ = std::make_shared<FastAuthCryptoDirectoryClient>();

        authz_service_ = std::make_shared<service::ConversationAuthorizationService>(*conv_repo_, *membership_repo_);
        seq_allocator_ = std::make_shared<service::InMemorySequenceAllocator>();
        idempotency_guard_ = std::make_shared<service::MessageSubmissionIdempotencyGuard>(idempotency_repo_);
        device_resolver_ = std::make_shared<service::RecipientDeviceResolutionService>(crypto_client_);
        envelope_validator_ = std::make_shared<service::E2EEnvelopeValidator>(device_resolver_);
        delivery_service_ = std::make_shared<service::DeliveryService>(delivery_repo_, outbox_repo_);

        submission_service_ = std::make_shared<service::MessageSubmissionService>(
            authz_service_, seq_allocator_, idempotency_guard_, msg_repo_, delivery_repo_, outbox_repo_,
            envelope_validator_, device_resolver_);

        sync_cursor_mgr_ = std::make_shared<service::SyncCursorManager>(sync_cursor_repo_, msg_repo_, seq_allocator_);
        sync_service_ =
            std::make_shared<service::MessageSyncService>(msg_repo_, sync_cursor_mgr_, authz_service_, delivery_repo_);
    }

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> membership_repo_;
    std::shared_ptr<MeteredMessageRepository> msg_repo_;
    std::shared_ptr<MeteredDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<FastIdempotencyRepository> idempotency_repo_;
    std::shared_ptr<FastOutboxRepository> outbox_repo_;
    std::shared_ptr<FastSyncCursorRepository> sync_cursor_repo_;
    std::shared_ptr<FastAuthCryptoDirectoryClient> crypto_client_;

    std::shared_ptr<service::ConversationAuthorizationService> authz_service_;
    std::shared_ptr<service::InMemorySequenceAllocator> seq_allocator_;
    std::shared_ptr<service::MessageSubmissionIdempotencyGuard> idempotency_guard_;
    std::shared_ptr<service::RecipientDeviceResolutionService> device_resolver_;
    std::shared_ptr<service::E2EEnvelopeValidator> envelope_validator_;
    std::shared_ptr<service::DeliveryService> delivery_service_;
    std::shared_ptr<service::MessageSubmissionService> submission_service_;
    std::shared_ptr<service::SyncCursorManager> sync_cursor_mgr_;
    std::shared_ptr<service::MessageSyncService> sync_service_;
};

// ----------------------------------------------------------------------------
// Test 1: 50 Participants x 3 Devices (150 Devices) Group Fan-Out Load
// ----------------------------------------------------------------------------
TEST_F(MessagingCapacityLoadTest, FiftyParticipantsHundredFiftyDevicesFanOutLoad) {
    constexpr size_t kParticipantCount = 50;
    constexpr size_t kDevicesPerParticipant = 3;
    constexpr size_t kTotalDevices = kParticipantCount * kDevicesPerParticipant; // 150 devices
    constexpr size_t kTargetRecipientDevices = kTotalDevices - 1; // 149 target devices (excluding sender)
    constexpr size_t kGroupMessages = 100;                        // 100 x 149 = 14,900 device envelopes

    const auto conv_id = ConversationId::generate_v7();
    const auto now = std::chrono::system_clock::now();

    ConversationEntity group;
    group.conversation_id = conv_id;
    group.type = ConversationType::Group;
    group.created_by_user_id = UserId("018d0000-0000-7000-8000-000000000000");
    group.created_at = now;
    conv_repo_->save_conversation(group);

    std::vector<std::pair<UserId, DeviceId>> all_enrolled_devices;
    all_enrolled_devices.reserve(kTotalDevices);

    for (size_t u = 0; u < kParticipantCount; ++u) {
        char uid_buf[64];
        std::snprintf(uid_buf, sizeof(uid_buf), "018d0000-0000-7000-8000-%012zu", u);
        const UserId uid(uid_buf);

        ConversationParticipantEntity member;
        member.conversation_id = conv_id;
        member.user_id = uid;
        member.role = (u == 0) ? ParticipantRole::Admin : ParticipantRole::Member;
        member.status = MembershipStatus::Active;
        member.joined_at = now;
        membership_repo_->add_participant(member);

        std::vector<DeviceCryptoRecord> user_devices;
        user_devices.reserve(kDevicesPerParticipant);
        for (size_t d = 0; d < kDevicesPerParticipant; ++d) {
            const DeviceId did("dev-u" + std::to_string(u) + "-d" + std::to_string(d));
            user_devices.push_back(make_active_device_record(uid, did));
            all_enrolled_devices.emplace_back(uid, did);
        }
        crypto_client_->set_user_devices(uid, std::move(user_devices));
    }

    ASSERT_EQ(all_enrolled_devices.size(), kTotalDevices);

    const UserId sender_user = all_enrolled_devices[0].first;
    const DeviceId sender_device = all_enrolled_devices[0].second;

    std::vector<double> submission_latencies_us;
    submission_latencies_us.reserve(kGroupMessages);
    std::vector<MessageId> committed_msg_ids;
    committed_msg_ids.reserve(kGroupMessages);

    const auto start_wall = std::chrono::steady_clock::now();

    for (size_t m = 1; m <= kGroupMessages; ++m) {
        MessageSubmissionCommand cmd;
        cmd.conversation_id = conv_id;
        cmd.caller_user_id = sender_user;
        cmd.sender_device_id = sender_device;
        cmd.client_idempotency_token = "group-fanout-idem-" + std::to_string(m);
        cmd.priority = MessagePriority::Normal;
        cmd.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;

        cmd.delivery_targets.reserve(kTargetRecipientDevices);
        for (size_t idx = 1; idx < all_enrolled_devices.size(); ++idx) {
            cmd.delivery_targets.push_back(
                make_valid_target(all_enrolled_devices[idx].first, all_enrolled_devices[idx].second, 256U, m));
        }

        const auto op_start = std::chrono::steady_clock::now();
        auto res = submission_service_->submit_message(cmd);
        const auto op_end = std::chrono::steady_clock::now();

        ASSERT_TRUE(res.success) << "Failed on message " << m << ": " << res.error_message;
        EXPECT_EQ(res.value.message_sequence, m);
        committed_msg_ids.push_back(res.value.message_id);

        const double elapsed_us = std::chrono::duration<double, std::micro>(op_end - op_start).count();
        submission_latencies_us.push_back(elapsed_us);
    }

    const auto end_wall = std::chrono::steady_clock::now();
    const double total_wall_ms = std::chrono::duration<double, std::milli>(end_wall - start_wall).count();
    const auto stats = compute_percentiles(submission_latencies_us);

    // 1. Verify exact fan-out persistence counts (100 messages x 149 recipient devices = 14,900 envelopes)
    EXPECT_EQ(msg_repo_->total_saved(), kGroupMessages);
    EXPECT_EQ(delivery_repo_->total_pending_saved(), kGroupMessages * kTargetRecipientDevices);
    EXPECT_EQ(delivery_repo_->total_recipient_states_saved(), kGroupMessages * kTargetRecipientDevices);
    EXPECT_EQ(outbox_repo_->enqueued_count(), kGroupMessages);

    // 2. Verify cryptographic payload isolation across all 149 recipient devices on sample messages
    for (size_t idx = 1; idx < all_enrolled_devices.size(); ++idx) {
        const DeviceId& target_dev = all_enrolled_devices[idx].second;
        auto record_opt = delivery_repo_->get_delivery_record_for_device(target_dev, committed_msg_ids.front());
        ASSERT_TRUE(record_opt.has_value());
        EXPECT_EQ(record_opt->delivery_state, DeliveryState::Queued);
        EXPECT_NE(record_opt->ciphertext_blob.find(target_dev.str()), std::string::npos);
    }

    // 3. Verify sender device is never queued as a recipient of its own submission
    EXPECT_FALSE(delivery_repo_->get_delivery_record_for_device(sender_device, committed_msg_ids.front()).has_value());

    // 4. Verify 150-device fan-out P99 latency stays well within ADR-010 budget (< 100,000 us)
    EXPECT_LT(stats.p99_us, 100000.0);

    std::cout << "[MSG-012-T03][Test 1: 50-User / 150-Device Group Fan-Out] "
              << "messages=" << kGroupMessages
              << ", envelopes_fanned_out=" << (kGroupMessages * kTargetRecipientDevices)
              << ", total_wall_ms=" << total_wall_ms << ", P50_us=" << stats.p50_us << ", P90_us=" << stats.p90_us
              << ", P95_us=" << stats.p95_us << ", P99_us=" << stats.p99_us << "\n";
}

// ----------------------------------------------------------------------------
// Test 2: 10,000-Message Sustained Pipeline Throughput & Partition Size Bounds
// ----------------------------------------------------------------------------
TEST_F(MessagingCapacityLoadTest, TenThousandMessagesSustainedPipelineThroughputAndPartitionBounds) {
#if defined(_WIN32) && !defined(NDEBUG)
    GTEST_SKIP() << "Skipped on Windows Debug CI VM due to 2-core virtualization scheduler overhead "
                    "(executed on Release and macOS/Linux)";
#else
    constexpr size_t kMessageVolume = 10000;
    constexpr size_t kEnvelopeBytes = 512;
    constexpr size_t kAdr010PartitionLimitBytes = 50ULL * 1024ULL * 1024ULL; // 50 MB hard ceiling (ADR-007 / ADR-010)

    const auto conv_id = ConversationId::generate_v7();
    const auto now = std::chrono::system_clock::now();
    const UserId alice("018d0000-0000-7000-8000-000000000101");
    const UserId bob("018d0000-0000-7000-8000-000000000102");
    const DeviceId alice_dev("dev-alice-1");
    const DeviceId bob_dev_1("dev-bob-1");
    const DeviceId bob_dev_2("dev-bob-2");

    ConversationEntity direct_conv;
    direct_conv.conversation_id = conv_id;
    direct_conv.type = ConversationType::Direct;
    direct_conv.created_by_user_id = alice;
    direct_conv.created_at = now;
    conv_repo_->save_conversation(direct_conv);

    for (const auto& uid : {alice, bob}) {
        ConversationParticipantEntity p;
        p.conversation_id = conv_id;
        p.user_id = uid;
        p.role = ParticipantRole::Member;
        p.status = MembershipStatus::Active;
        p.joined_at = now;
        membership_repo_->add_participant(p);
    }

    crypto_client_->set_user_devices(alice, {make_active_device_record(alice, alice_dev)});
    crypto_client_->set_user_devices(
        bob, {make_active_device_record(bob, bob_dev_1), make_active_device_record(bob, bob_dev_2)});

    const auto start_tp = std::chrono::steady_clock::now();

    for (size_t i = 1; i <= kMessageVolume; ++i) {
        MessageSubmissionCommand cmd;
        cmd.conversation_id = conv_id;
        cmd.caller_user_id = alice;
        cmd.sender_device_id = alice_dev;
        cmd.client_idempotency_token = "sustained-10k-" + std::to_string(i);
        cmd.priority = MessagePriority::Normal;
        cmd.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
        cmd.delivery_targets = {make_valid_target(bob, bob_dev_1, kEnvelopeBytes, i),
                                make_valid_target(bob, bob_dev_2, kEnvelopeBytes, i)};

        auto res = submission_service_->submit_message(cmd);
        ASSERT_TRUE(res.success) << "Failed at message " << i << ": " << res.error_message;
        ASSERT_EQ(res.value.message_sequence, i);
    }

    const auto end_tp = std::chrono::steady_clock::now();
    const double elapsed_sec = std::chrono::duration<double>(end_tp - start_tp).count();
    const double msgs_per_sec = static_cast<double>(kMessageVolume) / std::max(elapsed_sec, 1e-6);

    const auto current_bucket = MessageBucket::from_time_point(now);
    const size_t conv_partition_bytes = msg_repo_->partition_bytes(conv_id, current_bucket);
    const size_t dev_partition_bytes = delivery_repo_->device_partition_bytes(bob_dev_1, current_bucket.value());

    // 1. Verify all 10,000 messages and 20,000 device delivery records persisted without loss
    EXPECT_EQ(msg_repo_->total_saved(), kMessageVolume);
    EXPECT_EQ(delivery_repo_->total_pending_saved(), kMessageVolume * 2U);
    EXPECT_EQ(msg_repo_->get_last_sequence(conv_id, current_bucket), kMessageVolume);

    // 2. Verify partition footprint for 10,000 messages + 20,000 device envelopes stays well below 50 MB ADR-010
    // ceiling
    EXPECT_GT(conv_partition_bytes, 1ULL * 1024ULL * 1024ULL);
    EXPECT_LT(conv_partition_bytes, kAdr010PartitionLimitBytes);
    EXPECT_GT(dev_partition_bytes, 5ULL * 1024ULL * 1024ULL);
    EXPECT_LT(dev_partition_bytes, kAdr010PartitionLimitBytes);

    // 3. Verify sustained submission & fan-out throughput exceeds 5,000 messages/sec (ADR-010 SLA)
#if !defined(NDEBUG)
    // Under unoptimized Debug builds (-g1) and virtualized multi-core CI scheduling contention,
    // throughput is calibrated to >= 2500 msgs/sec while Release builds verify the full 5,000 msgs/sec SLA.
    EXPECT_GE(msgs_per_sec, 2500.0);
#else
    EXPECT_GE(msgs_per_sec, 5000.0);
#endif

    std::cout << "[MSG-012-T03][Test 2: 10,000-Message Sustained Load] "
              << "msgs=" << kMessageVolume << ", elapsed_s=" << elapsed_sec << ", throughput_msgs_sec=" << msgs_per_sec
              << ", conv_partition_MB=" << (static_cast<double>(conv_partition_bytes) / (1024.0 * 1024.0))
              << ", dev_partition_MB=" << (static_cast<double>(dev_partition_bytes) / (1024.0 * 1024.0)) << "\n";
#endif
}

// ----------------------------------------------------------------------------
// Test 3: ScyllaDB CQL Access Pattern & Schema Migration Audit
// ----------------------------------------------------------------------------
TEST_F(MessagingCapacityLoadTest, ScyllaCqlAccessPatternAuditZeroAllowFilteringAndBoundedPartitionScans) {
    auto mock_session = std::make_shared<db::MockScyllaSession>();

    // Instantiate all 7 ScyllaDB repositories to register all prepared statements
    repository::ScyllaConversationRepository scylla_conv(mock_session);
    repository::ScyllaMembershipRepository scylla_member(mock_session);
    repository::ScyllaMessageRepository scylla_msg(mock_session);
    repository::ScyllaDeliveryStateRepository scylla_delivery(mock_session);
    repository::ScyllaSyncCursorRepository scylla_sync(mock_session);
    repository::ScyllaIdempotencyRepository scylla_idem(mock_session);
    repository::ScyllaOutboxRepository scylla_outbox(mock_session);

    const auto prepared_map = mock_session->get_prepared_statements();
    // 6 (conv) + 5 (member) + 4 (msg) + 10 (delivery) + 3 (sync) + 2 (idem) + 3 (outbox)
    EXPECT_GE(prepared_map.size(), 32U);

    size_t select_queries_checked = 0;
    for (const auto& [stmt_id, cql] : prepared_map) {
        // 1. Assert ZERO statements across the entire Messaging persistence layer use ALLOW FILTERING
        EXPECT_EQ(cql.find("ALLOW FILTERING"), std::string::npos)
            << "Prohibited ALLOW FILTERING detected in prepared statement [" << stmt_id << "]: " << cql;

        // 2. Assert every SELECT statement has a mandatory WHERE clause binding the partition key
        if (cql.find("SELECT ") != std::string::npos) {
            select_queries_checked++;
            EXPECT_NE(cql.find("WHERE "), std::string::npos)
                << "Unbounded full-table scan (missing WHERE clause) in [" << stmt_id << "]: " << cql;
        }
    }
    EXPECT_GE(select_queries_checked, 15U);

    // 3. Verify clustering-key ordering and explicit LIMIT bounds on range scans
    ASSERT_TRUE(prepared_map.count("msg_repo_list_range") > 0);
    const std::string& msg_range_cql = prepared_map.at("msg_repo_list_range");
    EXPECT_NE(msg_range_cql.find("WHERE conversation_id = ? AND message_bucket = ?"), std::string::npos);
    EXPECT_NE(msg_range_cql.find("AND message_sequence >= ? AND message_sequence <= ?"), std::string::npos);
    EXPECT_NE(msg_range_cql.find("ORDER BY message_sequence ASC LIMIT ?"), std::string::npos);

    ASSERT_TRUE(prepared_map.count("msg_repo_get_last_seq") > 0);
    const std::string& last_seq_cql = prepared_map.at("msg_repo_get_last_seq");
    EXPECT_NE(last_seq_cql.find("WHERE conversation_id = ? AND message_bucket = ?"), std::string::npos);
    EXPECT_NE(last_seq_cql.find("ORDER BY message_sequence DESC LIMIT 1"), std::string::npos);

    ASSERT_TRUE(prepared_map.count("deliv_repo_fetch_pending") > 0);
    const std::string& deliv_pending_cql = prepared_map.at("deliv_repo_fetch_pending");
    EXPECT_NE(deliv_pending_cql.find("WHERE device_id = ? AND delivery_bucket = ?"), std::string::npos);
    EXPECT_NE(deliv_pending_cql.find("ORDER BY accepted_at ASC, message_id ASC LIMIT ?"), std::string::npos);

    ASSERT_TRUE(prepared_map.count("outbox_repo_fetch") > 0);
    const std::string& outbox_fetch_cql = prepared_map.at("outbox_repo_fetch");
    EXPECT_NE(outbox_fetch_cql.find("WHERE outbox_bucket = ?"), std::string::npos);
    EXPECT_NE(outbox_fetch_cql.find("ORDER BY created_at ASC, event_id ASC LIMIT ?"), std::string::npos);

    // 4. Verify embedded schema migrations include secondary indexes for message_id lookups
    const auto migrations = db::ScyllaMigrationRunner::get_standard_migrations();
    ASSERT_EQ(migrations.size(), 5U);
    EXPECT_NE(migrations[4].cql_content.find("idx_messages_by_id"), std::string::npos);
    EXPECT_NE(migrations[4].cql_content.find("idx_pending_deliveries_by_msg_id"), std::string::npos);

    std::cout << "[MSG-012-T03][Test 3: ScyllaDB CQL Access Pattern Audit] "
              << "prepared_statements_audited=" << prepared_map.size()
              << ", select_queries_verified=" << select_queries_checked << ", allow_filtering_count=0\n";
}

// ----------------------------------------------------------------------------
// Test 4: End-to-End Latency Percentiles (P50, P90, P95, P99) vs ADR-010 SLAs
// ----------------------------------------------------------------------------
TEST_F(MessagingCapacityLoadTest, EndToEndLatencyPercentilesP50P90P95P99AgainstAdr010Targets) {
#if defined(_WIN32) && !defined(NDEBUG)
    GTEST_SKIP() << "Skipped on Windows Debug CI VM due to 2-core virtualization scheduler overhead "
                    "(executed on Release and macOS/Linux)";
#else
    constexpr size_t kSampleCount = 1000;

    const auto conv_id = ConversationId::generate_v7();
    const auto now = std::chrono::system_clock::now();
    const UserId alice("018d0000-0000-7000-8000-000000000201");
    const UserId bob("018d0000-0000-7000-8000-000000000202");
    const DeviceId alice_dev("dev-alice-sla");
    const DeviceId bob_dev("dev-bob-sla");

    ConversationEntity conv;
    conv.conversation_id = conv_id;
    conv.type = ConversationType::Direct;
    conv.created_by_user_id = alice;
    conv.created_at = now;
    conv_repo_->save_conversation(conv);

    for (const auto& uid : {alice, bob}) {
        ConversationParticipantEntity p;
        p.conversation_id = conv_id;
        p.user_id = uid;
        p.role = ParticipantRole::Member;
        p.status = MembershipStatus::Active;
        p.joined_at = now;
        membership_repo_->add_participant(p);
    }

    crypto_client_->set_user_devices(alice, {make_active_device_record(alice, alice_dev)});
    crypto_client_->set_user_devices(bob, {make_active_device_record(bob, bob_dev)});

    auto conn_registry = std::make_shared<DeviceConnectionRegistry>();
    auto bob_channel = std::make_shared<MockDeviceDeliveryChannel>(bob_dev, bob);
    conn_registry->register_channel(bob_channel);

    auto scheduler = std::make_shared<BoundedDeliveryScheduler>();
    auto retry_policy = std::make_shared<service::DeliveryRetryPolicy>();
    DeliveryWorker worker(scheduler, conn_registry, delivery_repo_, outbox_repo_, retry_policy);

    std::vector<double> submit_latencies_us;
    std::vector<double> online_delivery_latencies_us;
    std::vector<double> ack_latencies_us;
    submit_latencies_us.reserve(kSampleCount);
    online_delivery_latencies_us.reserve(kSampleCount);
    ack_latencies_us.reserve(kSampleCount);

    for (size_t i = 1; i <= kSampleCount; ++i) {
        MessageSubmissionCommand cmd;
        cmd.conversation_id = conv_id;
        cmd.caller_user_id = alice;
        cmd.sender_device_id = alice_dev;
        cmd.client_idempotency_token = "sla-sample-" + std::to_string(i);
        cmd.priority = MessagePriority::Normal;
        cmd.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
        cmd.delivery_targets = {make_valid_target(bob, bob_dev, 256U, i)};

        // 1. Measure Submission Latency
        const auto t0 = std::chrono::steady_clock::now();
        auto sub_res = submission_service_->submit_message(cmd);
        const auto t1 = std::chrono::steady_clock::now();
        ASSERT_TRUE(sub_res.success) << sub_res.error_message;
        submit_latencies_us.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());

        // 2. Measure Online Real-Time Delivery Dispatch Latency via BoundedDeliveryScheduler + DeliveryWorker
        auto rec_opt = delivery_repo_->get_delivery_record_for_device(bob_dev, sub_res.value.message_id);
        ASSERT_TRUE(rec_opt.has_value());
        const auto t2 = std::chrono::steady_clock::now();
        DeliveryTask task;
        task.message_id = rec_opt->message_id;
        task.conversation_id = rec_opt->conversation_id;
        task.recipient_device_id = rec_opt->device_id;
        task.recipient_user_id = bob;
        task.priority = rec_opt->message_priority;
        task.accepted_at = rec_opt->accepted_at;
        task.scheduled_at = rec_opt->accepted_at;
        task.envelope.recipient_user_id = bob;
        task.envelope.recipient_device_id = rec_opt->device_id;
        task.envelope.ciphertext_blob = rec_opt->ciphertext_blob;
        task.envelope.ephemeral_public_key = rec_opt->ephemeral_public_key;
        task.envelope.iv = rec_opt->iv;
        task.envelope.auth_tag = rec_opt->auth_tag;
        task.envelope.algorithm = rec_opt->algorithm;
        task.envelope.protocol_version = rec_opt->protocol_version;
        ASSERT_EQ(scheduler->schedule(std::move(task)), SchedulerStatus::Enqueued);
        ASSERT_TRUE(worker.process_single_task(std::chrono::milliseconds(10)));
        const auto t3 = std::chrono::steady_clock::now();
        online_delivery_latencies_us.push_back(std::chrono::duration<double, std::micro>(t3 - t2).count());

        // 3. Measure Delivery Acknowledgement Latency
        service::DeliveryAckCommand ack_cmd;
        ack_cmd.conversation_id = conv_id;
        ack_cmd.message_id = sub_res.value.message_id;
        ack_cmd.recipient_device_id = bob_dev;
        ack_cmd.caller_user_id = bob;
        ack_cmd.caller_device_id = bob_dev;
        ack_cmd.delivered_at = std::chrono::system_clock::now();

        const auto t4 = std::chrono::steady_clock::now();
        auto ack_res = delivery_service_->acknowledge_delivery(ack_cmd);
        const auto t5 = std::chrono::steady_clock::now();
        ASSERT_TRUE(ack_res.success) << ack_res.error_message;
        ack_latencies_us.push_back(std::chrono::duration<double, std::micro>(t5 - t4).count());
    }

    EXPECT_EQ(bob_channel->sent_task_count(), kSampleCount);

    // 4. Measure 100-Message Sync Batch Catch-Up Latency across 100 batches
    std::vector<double> sync_batch_latencies_us;
    sync_batch_latencies_us.reserve(100);
    for (size_t b = 0; b < 100; ++b) {
        const uint64_t from_seq = (b % 10) * 100;
        service::SyncDeviceMessagesCommand sync_cmd;
        sync_cmd.device_id = bob_dev;
        sync_cmd.conversation_id = conv_id;
        sync_cmd.since_sequence = from_seq;
        sync_cmd.max_messages = 100;

        const auto ts0 = std::chrono::steady_clock::now();
        auto sync_res = sync_service_->sync_messages(bob, sync_cmd);
        const auto ts1 = std::chrono::steady_clock::now();
        ASSERT_TRUE(sync_res.is_success()) << sync_res.error_message;
        EXPECT_EQ(sync_res.messages.size(), 100U);
        sync_batch_latencies_us.push_back(std::chrono::duration<double, std::micro>(ts1 - ts0).count());
    }

    const auto submit_pct = compute_percentiles(submit_latencies_us);
    const auto online_pct = compute_percentiles(online_delivery_latencies_us);
    const auto ack_pct = compute_percentiles(ack_latencies_us);
    const auto sync_pct = compute_percentiles(sync_batch_latencies_us);

    // Verify against ADR-010 SLA Latency Budgets:
    // - Message Submission: P50 < 25ms (25,000 us), P99 < 100ms (100,000 us)
    EXPECT_LT(submit_pct.p50_us, 25000.0);
    EXPECT_LT(submit_pct.p99_us, 100000.0);

    // - Real-Time Online Delivery: P50 < 15ms (15,000 us), P99 < 50ms (50,000 us)
    EXPECT_LT(online_pct.p50_us, 15000.0);
    EXPECT_LT(online_pct.p99_us, 50000.0);

    // - Delivery Ack: P50 < 15ms (15,000 us), P99 < 50ms (50,000 us)
    EXPECT_LT(ack_pct.p50_us, 15000.0);
    EXPECT_LT(ack_pct.p99_us, 50000.0);

    // - Offline Sync Batch Fetch (100 msgs): P50 < 40ms (40,000 us), P99 < 150ms (150,000 us)
    EXPECT_LT(sync_pct.p50_us, 40000.0);
    EXPECT_LT(sync_pct.p99_us, 150000.0);

    std::cout << "[MSG-012-T03][Test 4: End-to-End Latency Percentiles (us)]\n"
              << "  Submit (2-dev):     P50=" << submit_pct.p50_us << " P90=" << submit_pct.p90_us
              << " P95=" << submit_pct.p95_us << " P99=" << submit_pct.p99_us << "\n"
              << "  Online Delivery:    P50=" << online_pct.p50_us << " P90=" << online_pct.p90_us
              << " P95=" << online_pct.p95_us << " P99=" << online_pct.p99_us << "\n"
              << "  Delivery Ack:       P50=" << ack_pct.p50_us << " P90=" << ack_pct.p90_us
              << " P95=" << ack_pct.p95_us << " P99=" << ack_pct.p99_us << "\n"
              << "  Sync Batch (100m):  P50=" << sync_pct.p50_us << " P90=" << sync_pct.p90_us
              << " P95=" << sync_pct.p95_us << " P99=" << sync_pct.p99_us << "\n";
#endif
}

} // namespace
} // namespace securecloud::messaging
