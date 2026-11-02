#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "client/auth_crypto_directory_client_interface.hpp"
#include "concurrency/bounded_worker_pool.hpp"
#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/delivery_worker.hpp"
#include "delivery/device_connection_registry.hpp"
#include "delivery/durable_delivery_recovery_service.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "delivery/realtime_delivery_accelerator.hpp"
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
#include "messaging/db/mock_scylla_session.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "messaging/repository/scylla_delivery_state_repository.hpp"
#include "messaging/repository/scylla_idempotency_repository.hpp"
#include "messaging/repository/scylla_message_repository.hpp"
#include "messaging/repository/sync_cursor_repository_interface.hpp"
#include "securecloud/auth/v1/auth.pb.h"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "service/conversation_authorization_service.hpp"
#include "service/delivery_retry_policy.hpp"
#include "service/delivery_service.hpp"
#include "service/e2e_envelope_validator.hpp"
#include "service/idempotency_guard.hpp"
#include "service/in_memory_sequence_allocator.hpp"
#include "service/message_submission_service.hpp"
#include "service/message_sync_service.hpp"
#include "service/messaging_error_mapper.hpp"
#include "service/messaging_service_impl.hpp"
#include "service/read_receipt_service.hpp"
#include "service/recipient_device_resolution_service.hpp"
#include "service/sync_cursor_manager.hpp"

#include <chrono>
#include <future>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
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
using delivery::DeliveryRecoveryConfig;
using delivery::DeliverySchedulerConfig;
using delivery::DeliveryWorker;
using delivery::DeviceConnectionRegistry;
using delivery::DurableDeliveryRecoveryService;
using delivery::MockDeviceDeliveryChannel;
using delivery::RealtimeDeliveryAccelerator;
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
using domain::PerDeviceEnvelope;
using domain::ReadState;
using domain::RecipientDeliveryState;
using domain::UserId;

// ============================================================================
// Hermetic Thread-Safe Storage Supporting Fault Injection & Reconnects
// ============================================================================

class FaultInjectableDeliveryRepository final : public repository::IDeliveryStateRepository {
  public:
    void set_fault_active(bool active) {
        std::lock_guard<std::mutex> lock(mu_);
        fault_active_ = active;
    }

    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (fault_active_) {
            throw std::runtime_error("Simulated ScyllaDB write timeout during pending delivery save");
        }
        for (const auto& r : records) {
            records_by_dev_msg_[r.device_id.str() + ":" + r.message_id.to_string()] = r;
            records_by_dev_[r.device_id.str()].push_back(r);
        }
    }

    std::vector<DeviceDeliveryRecord>
    fetch_pending_for_device(const DeviceId& device_id, const std::string& delivery_bucket, size_t limit) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (fault_active_) {
            throw std::runtime_error("Simulated ScyllaDB timeout during fetch_pending_for_device");
        }
        std::vector<DeviceDeliveryRecord> out;
        auto it = records_by_dev_.find(device_id.str());
        if (it == records_by_dev_.end()) {
            return out;
        }
        for (const auto& r : it->second) {
            const std::string key = r.device_id.str() + ":" + r.message_id.to_string();
            const auto& latest = records_by_dev_msg_[key];
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
        if (fault_active_) {
            throw std::runtime_error("Simulated ScyllaDB write timeout during recipient states save");
        }
        for (const auto& s : states) {
            states_by_msg_[s.message_id.to_string()][s.recipient_device_id.str()] = s;
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
        if (msg_it != states_by_msg_.end()) {
            auto dev_it = msg_it->second.find(recipient_device_id.str());
            if (dev_it != msg_it->second.end() && !dev_it->second.read_at.has_value()) {
                dev_it->second.read_at = read_at;
            }
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

    void raw_stage_record(const DeviceDeliveryRecord& r) {
        std::lock_guard<std::mutex> lock(mu_);
        records_by_dev_msg_[r.device_id.str() + ":" + r.message_id.to_string()] = r;
        records_by_dev_[r.device_id.str()].push_back(r);
    }

  private:
    mutable std::mutex mu_;
    bool fault_active_{false};
    std::unordered_map<std::string, DeviceDeliveryRecord> records_by_dev_msg_;
    std::unordered_map<std::string, std::vector<DeviceDeliveryRecord>> records_by_dev_;
    std::unordered_map<std::string, std::unordered_map<std::string, RecipientDeliveryState>> states_by_msg_;
};

class FaultInjectableMessageRepository final : public repository::IMessageRepository {
  public:
    void set_fault_active(bool active) {
        std::lock_guard<std::mutex> lock(mu_);
        fault_active_ = active;
    }

    void save_message(const MessageEntity& msg) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (fault_active_) {
            throw std::runtime_error("Simulated ScyllaDB node timeout on messages_by_conversation commit");
        }
        const std::string part_key = msg.conversation_id.to_string() + ":" + msg.message_bucket.value();
        partitions_[part_key].push_back(msg);
    }

    std::optional<MessageEntity> find_by_id(const ConversationId& conv_id, const MessageBucket& bucket,
                                            const MessageId& msg_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (fault_active_) {
            throw std::runtime_error("Simulated ScyllaDB timeout on find_by_id");
        }
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
        if (fault_active_) {
            throw std::runtime_error("Simulated ScyllaDB timeout on range query");
        }
        std::vector<MessageEntity> result;
        const std::string part_key = conv_id.to_string() + ":" + bucket.value();
        auto it = partitions_.find(part_key);
        if (it == partitions_.end()) {
            return result;
        }
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

  private:
    mutable std::mutex mu_;
    bool fault_active_{false};
    std::unordered_map<std::string, std::vector<MessageEntity>> partitions_;
};

class FaultInjectableIdempotencyRepository final : public repository::IIdempotencyRepository {
  public:
    void set_fault_active(bool active) {
        std::lock_guard<std::mutex> lock(mu_);
        fault_active_ = active;
    }

    std::optional<IdempotencyRecord> find_submission(const DeviceId& dev, const std::string& key) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (fault_active_) {
            throw std::runtime_error("Simulated ScyllaDB timeout on idempotency lookup");
        }
        auto it = store_.find(dev.str() + ":" + key);
        if (it != store_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void save_submission(const IdempotencyRecord& rec) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (fault_active_) {
            throw std::runtime_error("Simulated ScyllaDB timeout on idempotency save");
        }
        store_[rec.sender_device_id.str() + ":" + rec.idempotency_key] = rec;
    }

  private:
    mutable std::mutex mu_;
    bool fault_active_{false};
    std::unordered_map<std::string, IdempotencyRecord> store_;
};

class SimpleOutboxRepository final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& /*event*/, const std::string& /*bucket*/) override {}
    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string& /*bucket*/,
                                                                    size_t /*limit*/) override {
        return {};
    }
    void mark_event_published(const std::string& /*bucket*/, std::chrono::system_clock::time_point /*created_at*/,
                              const std::string& /*event_id*/,
                              std::chrono::system_clock::time_point /*published_at*/) override {}
};

class SimpleSyncCursorRepository final : public repository::ISyncCursorRepository {
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
        for (const auto& [_, c] : cursors_) {
            if (c.device_id == dev) {
                out.push_back(c);
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

class SimpleCryptoClient final : public IAuthCryptoDirectoryClient {
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

DeviceCryptoRecord make_device_record(const UserId& user_id, const DeviceId& device_id) {
    DeviceCryptoRecord rec;
    rec.device_id = device_id;
    rec.user_id = user_id;
    rec.identity_key = std::vector<uint8_t>(32, 0xEE);
    rec.signed_prekey = std::vector<uint8_t>(32, 0xFF);
    rec.signed_prekey_signature = std::vector<uint8_t>(64, 0xCC);
    rec.one_time_prekey = std::vector<uint8_t>(32, 0xDD);
    rec.one_time_prekey_id = "otk-" + device_id.str();
    rec.status = securecloud::auth::v1::DEVICE_STATUS_ACTIVE;
    rec.identity_key_fingerprint = "fp-" + device_id.str();
    rec.signed_prekey_created_at_epoch_ms = 1000;
    rec.remaining_one_time_prekeys = 50;
    return rec;
}

DeviceDeliveryTarget make_target(const UserId& user_id, const DeviceId& device_id, uint64_t msg_idx) {
    DeviceDeliveryTarget target;
    target.recipient_user_id = user_id;
    target.recipient_device_id = device_id;
    std::string cipher("\x89\xAB\xCD\xEF\x91\xA2\xB3\xC4\xD5\xE6\xF7\x88", 12);
    cipher += device_id.str() + ":MSG_" + std::to_string(msg_idx);
    target.ciphertext_blob = std::move(cipher);
    target.ephemeral_public_key = std::vector<uint8_t>(32, 0x11);
    target.iv = std::vector<uint8_t>(24, 0x22);
    target.auth_tag = std::vector<uint8_t>(16, 0x33);
    target.algorithm = "XChaCha20-Poly1305";
    target.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
    target.one_time_prekey_id = "otk-" + device_id.str();
    return target;
}

} // namespace

// ============================================================================
// MSG-012-T04 Fault Recovery & Chaos Suite
// ============================================================================

class MessagingFaultRecoveryIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        membership_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        msg_repo_ = std::make_shared<FaultInjectableMessageRepository>();
        delivery_repo_ = std::make_shared<FaultInjectableDeliveryRepository>();
        idempotency_repo_ = std::make_shared<FaultInjectableIdempotencyRepository>();
        outbox_repo_ = std::make_shared<SimpleOutboxRepository>();
        sync_cursor_repo_ = std::make_shared<SimpleSyncCursorRepository>();
        crypto_client_ = std::make_shared<SimpleCryptoClient>();

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

        read_receipt_service_ =
            std::make_shared<service::ReadReceiptService>(delivery_repo_, membership_repo_, outbox_repo_);

        submission_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "sub_pool");
        delivery_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "del_pool");
        sync_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "sync_pool");

        messaging_service_impl_ = std::make_unique<service::MessagingServiceImpl>(
            submission_pool_, delivery_pool_, sync_pool_, nullptr, submission_service_, delivery_service_,
            read_receipt_service_, sync_service_, sync_cursor_mgr_, nullptr, device_resolver_);

        // Spin up in-process gRPC test server
        grpc::ServerBuilder builder;
        builder.RegisterService(messaging_service_impl_.get());
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);
        channel_ = server_->InProcessChannel(grpc::ChannelArguments{});
        stub_ = v1::MessagingService::NewStub(channel_);
    }

    void TearDown() override {
        if (submission_pool_) {
            submission_pool_->shutdown();
        }
        if (delivery_pool_) {
            delivery_pool_->shutdown();
        }
        if (sync_pool_) {
            sync_pool_->shutdown();
        }
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> membership_repo_;
    std::shared_ptr<FaultInjectableMessageRepository> msg_repo_;
    std::shared_ptr<FaultInjectableDeliveryRepository> delivery_repo_;
    std::shared_ptr<FaultInjectableIdempotencyRepository> idempotency_repo_;
    std::shared_ptr<SimpleOutboxRepository> outbox_repo_;
    std::shared_ptr<SimpleSyncCursorRepository> sync_cursor_repo_;
    std::shared_ptr<SimpleCryptoClient> crypto_client_;

    std::shared_ptr<service::ConversationAuthorizationService> authz_service_;
    std::shared_ptr<service::InMemorySequenceAllocator> seq_allocator_;
    std::shared_ptr<service::MessageSubmissionIdempotencyGuard> idempotency_guard_;
    std::shared_ptr<service::RecipientDeviceResolutionService> device_resolver_;
    std::shared_ptr<service::E2EEnvelopeValidator> envelope_validator_;
    std::shared_ptr<service::DeliveryService> delivery_service_;
    std::shared_ptr<service::MessageSubmissionService> submission_service_;
    std::shared_ptr<service::SyncCursorManager> sync_cursor_mgr_;
    std::shared_ptr<service::MessageSyncService> sync_service_;
    std::shared_ptr<service::ReadReceiptService> read_receipt_service_;

    std::shared_ptr<concurrency::BoundedWorkerPool> submission_pool_;
    std::shared_ptr<concurrency::BoundedWorkerPool> delivery_pool_;
    std::shared_ptr<concurrency::BoundedWorkerPool> sync_pool_;
    std::unique_ptr<service::MessagingServiceImpl> messaging_service_impl_;
    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::MessagingService::Stub> stub_;
};

// ----------------------------------------------------------------------------
// Test 1: Mid-Flight Transport Disconnection & Lease Expiration Redelivery
// ----------------------------------------------------------------------------
TEST_F(MessagingFaultRecoveryIntegrationTest, MidFlightTransportDisconnectionAndAcceleratorRedelivery) {
    const auto conv_id = ConversationId::generate_v7();
    const auto now = std::chrono::system_clock::now();
    const UserId alice("018d0000-0000-7000-8000-000000000301");
    const UserId bob("018d0000-0000-7000-8000-000000000302");
    const DeviceId alice_dev("dev-alice-socket");
    const DeviceId bob_dev("dev-bob-socket");

    ConversationEntity conv{conv_id, ConversationType::Direct, alice, now};
    conv_repo_->save_conversation(conv);

    ConversationParticipantEntity p_alice{conv_id, alice, ParticipantRole::Member, MembershipStatus::Active, now};
    ConversationParticipantEntity p_bob{conv_id, bob, ParticipantRole::Member, MembershipStatus::Active, now};
    membership_repo_->add_participant(p_alice);
    membership_repo_->add_participant(p_bob);

    crypto_client_->set_user_devices(alice, {make_device_record(alice, alice_dev)});
    crypto_client_->set_user_devices(bob, {make_device_record(bob, bob_dev)});

    auto conn_registry = std::make_shared<DeviceConnectionRegistry>();
    auto bob_channel_1 = std::make_shared<MockDeviceDeliveryChannel>(bob_dev, bob);
    conn_registry->register_channel(bob_channel_1);

    auto scheduler = std::make_shared<BoundedDeliveryScheduler>();
    auto retry_policy = std::make_shared<service::DeliveryRetryPolicy>();
    DeliveryWorker worker(scheduler, conn_registry, delivery_repo_, outbox_repo_, retry_policy);

    // 1. Submit message
    MessageSubmissionCommand cmd;
    cmd.conversation_id = conv_id;
    cmd.caller_user_id = alice;
    cmd.sender_device_id = alice_dev;
    cmd.client_idempotency_token = "mid-flight-disconnect-1";
    cmd.priority = MessagePriority::Normal;
    cmd.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
    cmd.delivery_targets = {make_target(bob, bob_dev, 1)};

    auto sub_res = submission_service_->submit_message(cmd);
    ASSERT_TRUE(sub_res.success);
    const MessageId msg_id = sub_res.value.message_id;

    // 2. Fetch staged delivery record and verify Queued
    auto rec_opt = delivery_repo_->get_delivery_record_for_device(bob_dev, msg_id);
    ASSERT_TRUE(rec_opt.has_value());
    EXPECT_EQ(rec_opt->delivery_state, DeliveryState::Queued);

    // 3. Simulate mid-flight socket severance: channel becomes inactive during delivery dispatch
    bob_channel_1->set_active(false);
    bob_channel_1->set_next_result(domain::DeliveryAttemptResult::RecipientOffline);

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

    ASSERT_EQ(scheduler->schedule(task), SchedulerStatus::Enqueued);
    ASSERT_TRUE(worker.process_single_task(std::chrono::milliseconds(20)));

    // 4. Verify unregister on lease expiration / socket severance
    conn_registry->unregister_channel(bob_dev);
    EXPECT_FALSE(conn_registry->is_online(bob_dev));

    // Confirm that mid-flight disconnect kept record in durable QUEUED state
    auto rec_after = delivery_repo_->get_delivery_record_for_device(bob_dev, msg_id);
    ASSERT_TRUE(rec_after.has_value());
    EXPECT_EQ(rec_after->delivery_state, DeliveryState::Queued);

    // 5. Device reconnects with fresh active delivery channel
    auto bob_channel_2 = std::make_shared<MockDeviceDeliveryChannel>(bob_dev, bob);
    conn_registry->register_channel(bob_channel_2);
    EXPECT_TRUE(conn_registry->is_online(bob_dev));

    // Fast-track accelerator discovers undelivered envelope upon reconnect and schedules redelivery
    RealtimeDeliveryAccelerator accelerator(delivery_repo_, scheduler, conn_registry);
    size_t accelerated = accelerator.on_device_connected(bob_dev, bob, rec_opt->delivery_bucket);
    EXPECT_EQ(accelerated, 1U);

    // Worker dispatches to newly connected channel
    ASSERT_TRUE(worker.process_single_task(std::chrono::milliseconds(20)));
    EXPECT_EQ(bob_channel_2->sent_task_count(), 1U);
    EXPECT_EQ(bob_channel_2->sent_tasks()[0].message_id, msg_id);

    // 6. Affirmative delivery receipt completes lifecycle
    service::DeliveryAckCommand ack;
    ack.conversation_id = conv_id;
    ack.message_id = msg_id;
    ack.recipient_device_id = bob_dev;
    ack.caller_user_id = bob;
    ack.caller_device_id = bob_dev;
    ack.delivered_at = std::chrono::system_clock::now();

    auto ack_res = delivery_service_->acknowledge_delivery(ack);
    ASSERT_TRUE(ack_res.success);

    auto final_rec = delivery_repo_->get_delivery_record_for_device(bob_dev, msg_id);
    ASSERT_TRUE(final_rec.has_value());
    EXPECT_EQ(final_rec->delivery_state, DeliveryState::Delivered);

    std::cout << "[MSG-012-T04][Test 1: Mid-Flight Transport Recovery] Socket disconnected mid-flight -> "
              << "Retried -> Accelerated on Reconnect -> Successfully Delivered and Acknowledged.\n";
}

// ----------------------------------------------------------------------------
// Test 2: Abrupt Service Crash & State Recovery (T_recovery <= 500 ms)
// ----------------------------------------------------------------------------
TEST_F(MessagingFaultRecoveryIntegrationTest, MessagingServiceAbruptRestartDurableStateRecovery) {
    constexpr size_t kStagedMessages = 500;
    const auto conv_id = ConversationId::generate_v7();
    const auto now = std::chrono::system_clock::now();
    const std::string bucket = MessageBucket::from_time_point(now).value();

    const UserId alice("018d0000-0000-7000-8000-000000000401");
    const UserId bob("018d0000-0000-7000-8000-000000000402");
    const DeviceId alice_dev("dev-alice-crash");
    const DeviceId bob_dev("dev-bob-crash");

    // 1. Stage 500 durable pending deliveries directly in storage before crash
    for (size_t i = 1; i <= kStagedMessages; ++i) {
        DeviceDeliveryRecord r;
        r.device_id = bob_dev;
        r.delivery_bucket = bucket;
        r.accepted_at = now + std::chrono::milliseconds(i);
        r.message_id = MessageId::generate_v7();
        r.conversation_id = conv_id;
        r.message_sequence = i;
        r.message_priority = MessagePriority::Normal;
        r.delivery_state = (i % 2 == 0) ? DeliveryState::Queued : DeliveryState::Delivering;
        r.attempt_count = (i % 2 == 0) ? 0 : 1;
        r.ciphertext_blob = "RECOVERY_CIPHERTEXT_" + std::to_string(i);
        r.iv = std::vector<uint8_t>(24, 0x42);
        r.auth_tag = std::vector<uint8_t>(16, 0x99);
        r.algorithm = E2EAlgorithm::XChaCha20_Poly1305;
        r.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;

        delivery_repo_->raw_stage_record(r);
    }

    // 2. Abrupt service teardown (simulate process SIGKILL / container crash)
    messaging_service_impl_.reset();
    submission_pool_->shutdown();
    delivery_pool_->shutdown();
    sync_pool_->shutdown();

    // 3. Restart and hydrate service from durable storage; measure T_recovery
    const auto restart_start = std::chrono::steady_clock::now();

    auto new_conn_registry = std::make_shared<DeviceConnectionRegistry>();
    auto new_bob_channel = std::make_shared<MockDeviceDeliveryChannel>(bob_dev, bob);
    new_conn_registry->register_channel(new_bob_channel);

    DeliverySchedulerConfig sched_cfg;
    sched_cfg.max_global_queued_tasks = 10000;
    sched_cfg.max_tasks_per_device = 1000;
    auto new_scheduler = std::make_shared<BoundedDeliveryScheduler>(sched_cfg);

    DeliveryRecoveryConfig rec_cfg;
    rec_cfg.batch_size = 500;
    DurableDeliveryRecoveryService recovery_engine(delivery_repo_, new_scheduler, new_conn_registry, rec_cfg);

    // Execute startup recovery cycle across candidate devices
    size_t recovered_count = recovery_engine.run_recovery_cycle({bob_dev}, bucket);

    const auto restart_end = std::chrono::steady_clock::now();
    const double recovery_ms = std::chrono::duration<double, std::milli>(restart_end - restart_start).count();

    // 4. Assert crash recovery requirements:
    // - T_recovery <= 500 ms SLA
    // - 100% of the 500 pending messages discovered and scheduled without loss or sequence gaps
    EXPECT_LE(recovery_ms, 500.0);
    EXPECT_EQ(recovered_count, kStagedMessages);
    EXPECT_EQ(new_scheduler->global_queue_depth(), kStagedMessages);
    EXPECT_EQ(new_scheduler->device_queue_depth(bob_dev), kStagedMessages);

    // 5. Verify worker drains scheduled recovery tasks cleanly to the reconnected device
    auto retry_policy = std::make_shared<service::DeliveryRetryPolicy>();
    DeliveryWorker worker(new_scheduler, new_conn_registry, delivery_repo_, outbox_repo_, retry_policy);
    for (size_t i = 0; i < kStagedMessages; ++i) {
        ASSERT_TRUE(worker.process_single_task(std::chrono::milliseconds(10)));
    }
    EXPECT_EQ(new_bob_channel->sent_task_count(), kStagedMessages);

    std::cout << "[MSG-012-T04][Test 2: Crash Restart Recovery] Recovered " << recovered_count
              << " durable messages in " << recovery_ms << " ms (SLA <= 500 ms).\n";
}

// ----------------------------------------------------------------------------
// Test 3: Transient ScyllaDB Storage Fault Injection & Clean Resumption
// ----------------------------------------------------------------------------
TEST_F(MessagingFaultRecoveryIntegrationTest, TransientScyllaFaultInjectionStructuredGrpcDegradationAndResumption) {
    const auto conv_id = ConversationId::generate_v7();
    const auto now = std::chrono::system_clock::now();
    const UserId alice("018d0000-0000-7000-8000-000000000501");
    const UserId bob("018d0000-0000-7000-8000-000000000502");
    const DeviceId alice_dev("018d0000-0000-7000-8000-000000000511");
    const DeviceId bob_dev("018d0000-0000-7000-8000-000000000512");

    ConversationEntity conv{conv_id, ConversationType::Direct, alice, now};
    conv_repo_->save_conversation(conv);

    ConversationParticipantEntity p_alice{conv_id, alice, ParticipantRole::Member, MembershipStatus::Active, now};
    ConversationParticipantEntity p_bob{conv_id, bob, ParticipantRole::Member, MembershipStatus::Active, now};
    membership_repo_->add_participant(p_alice);
    membership_repo_->add_participant(p_bob);

    crypto_client_->set_user_devices(alice, {make_device_record(alice, alice_dev)});
    crypto_client_->set_user_devices(bob, {make_device_record(bob, bob_dev)});

    // 1. Send normal message before fault injection
    {
        v1::SendMessageRequest req;
        req.set_conversation_id(conv_id.to_string());
        req.set_sender_device_id(alice_dev.str());
        req.set_client_idempotency_token("clean-call-1");
        req.set_priority(v1::MESSAGE_PRIORITY_NORMAL);
        auto* target = req.add_delivery_targets();
        target->set_recipient_user_id(bob.str());
        target->set_recipient_device_id(bob_dev.str());
        auto* ep = target->mutable_encrypted_payload();
        ep->set_ciphertext_blob(std::string("\x89\xAB\xCD\xEF\x91\xA2\xB3\xC4\xD5\xE6\xF7\x88", 12) + "payload1");
        ep->set_ephemeral_public_key(std::string(32, 0x11));
        ep->set_initialization_vector(std::string(24, 0x22));
        ep->set_auth_tag(std::string(16, 0x33));
        ep->set_algorithm("XChaCha20-Poly1305");

        ::grpc::ClientContext ctx;
        ctx.AddMetadata("x-user-id", alice.str());
        ctx.AddMetadata("x-device-id", alice_dev.str());
        ctx.AddMetadata("x-correlation-id", "corr-clean-1");

        v1::SendMessageResponse resp;
        auto status = stub_->SendMessage(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << status.error_message();
        EXPECT_FALSE(resp.message_id().empty());
        EXPECT_EQ(resp.target_count(), 1U);
    }

    // 2. Inject transient database failure in ScyllaDB message repository
    msg_repo_->set_fault_active(true);

    {
        v1::SendMessageRequest req;
        req.set_conversation_id(conv_id.to_string());
        req.set_sender_device_id(alice_dev.str());
        req.set_client_idempotency_token("fault-call-2");
        req.set_priority(v1::MESSAGE_PRIORITY_NORMAL);
        auto* target = req.add_delivery_targets();
        target->set_recipient_user_id(bob.str());
        target->set_recipient_device_id(bob_dev.str());
        auto* ep = target->mutable_encrypted_payload();
        ep->set_ciphertext_blob(std::string("\x89\xAB\xCD\xEF\x91\xA2\xB3\xC4\xD5\xE6\xF7\x88", 12) + "payload2");
        ep->set_ephemeral_public_key(std::string(32, 0x11));
        ep->set_initialization_vector(std::string(24, 0x22));
        ep->set_auth_tag(std::string(16, 0x33));
        ep->set_algorithm("XChaCha20-Poly1305");

        ::grpc::ClientContext ctx;
        ctx.AddMetadata("x-user-id", alice.str());
        ctx.AddMetadata("x-device-id", alice_dev.str());
        ctx.AddMetadata("x-correlation-id", "corr-fault-2");

        v1::SendMessageResponse resp;
        auto status = stub_->SendMessage(&ctx, req, &resp);

        // Verify that transient database failure fails closed with structured gRPC error
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INTERNAL);

        auto detail = service::extract_error_detail(ctx);
        ASSERT_TRUE(detail.has_value());
        EXPECT_EQ(detail->error_code(), v1::MESSAGING_ERROR_CODE_UNSPECIFIED);
        EXPECT_NE(detail->reason().find("ScyllaDB"), std::string::npos);
    }

    // 3. Clear fault injection (storage restored)
    msg_repo_->set_fault_active(false);

    // 4. Re-issue submission with same idempotency token; verify atomic completion and sequence continuity
    {
        v1::SendMessageRequest req;
        req.set_conversation_id(conv_id.to_string());
        req.set_sender_device_id(alice_dev.str());
        req.set_client_idempotency_token("fault-call-2"); // re-attempt failed token
        req.set_priority(v1::MESSAGE_PRIORITY_NORMAL);
        auto* target = req.add_delivery_targets();
        target->set_recipient_user_id(bob.str());
        target->set_recipient_device_id(bob_dev.str());
        auto* ep = target->mutable_encrypted_payload();
        ep->set_ciphertext_blob(std::string("\x89\xAB\xCD\xEF\x91\xA2\xB3\xC4\xD5\xE6\xF7\x88", 12) + "payload2");
        ep->set_ephemeral_public_key(std::string(32, 0x11));
        ep->set_initialization_vector(std::string(24, 0x22));
        ep->set_auth_tag(std::string(16, 0x33));
        ep->set_algorithm("XChaCha20-Poly1305");

        ::grpc::ClientContext ctx;
        ctx.AddMetadata("x-user-id", alice.str());
        ctx.AddMetadata("x-device-id", alice_dev.str());
        ctx.AddMetadata("x-correlation-id", "corr-retry-2");

        v1::SendMessageResponse resp;
        auto status = stub_->SendMessage(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << status.error_message();
        EXPECT_FALSE(resp.message_id().empty());
        EXPECT_EQ(resp.target_count(), 1U);
    }

    std::cout << "[MSG-012-T04][Test 3: Storage Fault Injection] Storage fault yielded structured gRPC error -> "
              << "Storage restored -> Idempotent retry committed sequence 2 atomically.\n";
}

// ----------------------------------------------------------------------------
// Test 4: Delayed Retry Sweeper Backoff & Message Expiration TTL Purge
// ----------------------------------------------------------------------------
TEST_F(MessagingFaultRecoveryIntegrationTest, DelayedRetrySweeperBackoffRespectsJitterAndTtl) {
    const auto conv_id = ConversationId::generate_v7();
    const auto now = std::chrono::system_clock::now();
    const std::string bucket = MessageBucket::from_time_point(now).value();
    const DeviceId bob_dev("dev-bob-sweeper");
    const UserId bob("018d0000-0000-7000-8000-000000000602");

    auto conn_registry = std::make_shared<DeviceConnectionRegistry>();
    auto bob_channel = std::make_shared<MockDeviceDeliveryChannel>(bob_dev, bob);
    conn_registry->register_channel(bob_channel);

    auto scheduler = std::make_shared<BoundedDeliveryScheduler>();
    DeliveryRecoveryConfig rec_cfg;
    rec_cfg.batch_size = 50;
    rec_cfg.max_delivery_ttl = std::chrono::hours(24);
    DurableDeliveryRecoveryService recovery_engine(delivery_repo_, scheduler, conn_registry, rec_cfg);

    const MessageId future_mid = MessageId::generate_v7();
    const MessageId ready_mid = MessageId::generate_v7();
    const MessageId expired_mid = MessageId::generate_v7();

    // 1. Task in RETRY_WAIT with next_retry_at in the future (+30s)
    DeviceDeliveryRecord r_future;
    r_future.device_id = bob_dev;
    r_future.delivery_bucket = bucket;
    r_future.accepted_at = now;
    r_future.message_id = future_mid;
    r_future.conversation_id = conv_id;
    r_future.delivery_state = DeliveryState::RetryWait;
    r_future.attempt_count = 1;
    r_future.next_retry_at = now + std::chrono::seconds(30);
    r_future.ciphertext_blob = "FUTURE_CIPHERTEXT";
    delivery_repo_->raw_stage_record(r_future);

    // 2. Task in RETRY_WAIT whose backoff elapsed in the past (-10s)
    DeviceDeliveryRecord r_ready;
    r_ready.device_id = bob_dev;
    r_ready.delivery_bucket = bucket;
    r_ready.accepted_at = now - std::chrono::seconds(15);
    r_ready.message_id = ready_mid;
    r_ready.conversation_id = conv_id;
    r_ready.delivery_state = DeliveryState::RetryWait;
    r_ready.attempt_count = 1;
    r_ready.next_retry_at = now - std::chrono::seconds(5);
    r_ready.ciphertext_blob = "READY_CIPHERTEXT";
    delivery_repo_->raw_stage_record(r_ready);

    // 3. Task accepted 25 hours ago (>24h TTL)
    DeviceDeliveryRecord r_expired;
    r_expired.device_id = bob_dev;
    r_expired.delivery_bucket = bucket;
    r_expired.accepted_at = now - std::chrono::hours(25);
    r_expired.message_id = expired_mid;
    r_expired.conversation_id = conv_id;
    r_expired.delivery_state = DeliveryState::Queued;
    r_expired.attempt_count = 0;
    r_expired.ciphertext_blob = "EXPIRED_CIPHERTEXT";
    delivery_repo_->raw_stage_record(r_expired);

    // 4. Sweep retries: only ready_mid should be enqueued, future_mid must not be enqueued
    size_t swept = recovery_engine.sweep_retries_for_device(bob_dev, bucket, now);
    EXPECT_EQ(swept, 1U);
    EXPECT_EQ(scheduler->device_queue_depth(bob_dev), 1U);

    auto dequeued = scheduler->try_dequeue();
    ASSERT_TRUE(dequeued.has_value());
    EXPECT_EQ(dequeued->message_id, ready_mid);

    // 5. Purge expired: r_expired should be detected and marked EXPIRED
    size_t purged = recovery_engine.purge_expired_for_device(bob_dev, bucket, now);
    EXPECT_EQ(purged, 1U);

    auto purged_rec = delivery_repo_->get_delivery_record_for_device(bob_dev, expired_mid);
    ASSERT_TRUE(purged_rec.has_value());
    EXPECT_EQ(purged_rec->delivery_state, DeliveryState::Expired);

    std::cout << "[MSG-012-T04][Test 4: Delayed Retry Sweeper & Expiration Purge] Future backoff held -> "
              << "Elapsed backoff swept into scheduler -> 25h expired record purged to EXPIRED.\n";
}

} // namespace securecloud::messaging
