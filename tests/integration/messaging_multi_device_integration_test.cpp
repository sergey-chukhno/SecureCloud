#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "client/auth_crypto_directory_client_interface.hpp"
#include "concurrency/bounded_worker_pool.hpp"
#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/connection_lifecycle_manager.hpp"
#include "delivery/device_connection_registry.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "delivery/realtime_delivery_accelerator.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/envelope_types.hpp"
#include "domain/idempotency_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/message_entity.hpp"
#include "domain/message_types.hpp"
#include "domain/outbox_event.hpp"
#include "domain/read_receipt_types.hpp"
#include "domain/submission_types.hpp"
#include "domain/sync_types.hpp"
#include "gateway_config.hpp"
#include "grpc/messaging_client_interface.hpp"
#include "grpc/messaging_service_client.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/proxy/messaging_proxy_handler.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/retry_policy.hpp"
#include "http/routing/router.hpp"
#include "messaging/repository/conversation_repository_interface.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/idempotency_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "messaging/repository/sync_cursor_repository_interface.hpp"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "service/conversation_authorization_service.hpp"
#include "service/conversation_service.hpp"
#include "service/delivery_service.hpp"
#include "service/e2e_envelope_validator.hpp"
#include "service/idempotency_guard.hpp"
#include "service/in_memory_sequence_allocator.hpp"
#include "service/message_submission_service.hpp"
#include "service/message_sync_service.hpp"
#include "service/messaging_service_impl.hpp"
#include "service/presence_coordinator.hpp"
#include "service/read_receipt_service.hpp"
#include "service/recipient_device_resolution_service.hpp"
#include "service/sync_cursor_manager.hpp"

#include <chrono>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging {
namespace {

using client::CryptoDirectoryError;
using client::CryptoDirectoryErrorKind;
using client::DeviceCryptoRecord;
using client::IAuthCryptoDirectoryClient;
using delivery::MockDeviceDeliveryChannel;
using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryState;
using domain::DeviceDeliveryRecord;
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
using domain::ParticipantRole;
using domain::ReadState;
using domain::RecipientDeliveryState;
using domain::UserId;

// ============================================================================
// Thread-Safe In-Memory Repositories
// ============================================================================

class ThreadSafeMessageRepository final : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& message) override {
        std::lock_guard<std::mutex> lock(mu_);
        messages_.push_back(message);
    }

    std::optional<MessageEntity> find_by_id(const ConversationId& conv_id, const MessageBucket& bucket,
                                            const MessageId& msg_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& m : messages_) {
            if (m.conversation_id == conv_id && m.message_bucket == bucket && m.message_id == msg_id) {
                return m;
            }
        }
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId& conv_id,
                                                               const MessageBucket& bucket, uint64_t from_seq,
                                                               uint64_t to_seq, size_t limit) override {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<MessageEntity> out;
        for (const auto& m : messages_) {
            if (m.conversation_id == conv_id && m.message_bucket == bucket && m.message_sequence >= from_seq &&
                m.message_sequence <= to_seq) {
                out.push_back(m);
                if (out.size() >= limit) {
                    break;
                }
            }
        }
        return out;
    }

    uint64_t get_last_sequence(const ConversationId& conv_id, const MessageBucket& bucket) override {
        std::lock_guard<std::mutex> lock(mu_);
        uint64_t max_seq = 0;
        for (const auto& m : messages_) {
            if (m.conversation_id == conv_id && m.message_bucket == bucket && m.message_sequence > max_seq) {
                max_seq = m.message_sequence;
            }
        }
        return max_seq;
    }

  private:
    mutable std::mutex mu_;
    std::vector<MessageEntity> messages_;
};

class ThreadSafeDeliveryStateRepository final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& r : records) {
            pending_[{r.device_id.str(), r.message_id.to_string()}] = r;
        }
    }

    std::vector<DeviceDeliveryRecord>
    fetch_pending_for_device(const DeviceId& device_id, const std::string& delivery_bucket, size_t limit) override {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<DeviceDeliveryRecord> out;
        for (const auto& [key, rec] : pending_) {
            if (rec.device_id == device_id && (delivery_bucket.empty() || rec.delivery_bucket == delivery_bucket)) {
                if (rec.delivery_state == DeliveryState::Pending || rec.delivery_state == DeliveryState::Queued ||
                    rec.delivery_state == DeliveryState::Delivering) {
                    out.push_back(rec);
                    if (out.size() >= limit) {
                        break;
                    }
                }
            }
        }
        return out;
    }

    void update_device_delivery_status(const DeviceId& device_id, const std::string&,
                                       const std::chrono::system_clock::time_point&, const MessageId& message_id,
                                       DeliveryState state, int32_t attempt_count,
                                       std::optional<std::chrono::system_clock::time_point> next_retry) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = pending_.find({device_id.str(), message_id.to_string()});
        if (it != pending_.end()) {
            it->second.delivery_state = state;
            it->second.attempt_count = attempt_count;
            it->second.next_retry_at = next_retry;
        }
    }

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& st : states) {
            states_[st.message_id].push_back(st);
        }
    }

    void record_delivery_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point& delivered_at) override {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& st : states_[message_id]) {
            if (st.recipient_device_id == recipient_device_id) {
                st.delivery_state = DeliveryState::Delivered;
                st.delivered_at = delivered_at;
            }
        }
        auto it = pending_.find({recipient_device_id.str(), message_id.to_string()});
        if (it != pending_.end()) {
            it->second.delivery_state = DeliveryState::Delivered;
        }
    }

    void record_read_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                         const std::chrono::system_clock::time_point& read_at) override {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& st : states_[message_id]) {
            if (st.recipient_device_id == recipient_device_id) {
                st.read_at = read_at;
            }
        }
    }

    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = states_.find(message_id);
        if (it != states_.end()) {
            return it->second;
        }
        return {};
    }

    std::optional<DeviceDeliveryRecord> get_delivery_record_for_device(const DeviceId& device_id,
                                                                       const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = pending_.find({device_id.str(), message_id.to_string()});
        if (it != pending_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::optional<MessageDeliverySummary> get_message_delivery_summary(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = states_.find(message_id);
        if (it == states_.end() || it->second.empty()) {
            return std::nullopt;
        }

        MessageDeliverySummary summary;
        summary.message_id = message_id;
        std::map<UserId, LogicalRecipientReadStatus> read_map;

        for (const auto& st : it->second) {
            domain::DeviceDeliveryStatus ds;
            ds.device_id = st.recipient_device_id;
            ds.recipient_user_id = st.recipient_user_id;
            ds.delivery_state = st.delivery_state;
            ds.delivered_at = st.delivered_at;

            summary.total_targets++;
            if (st.delivery_state == DeliveryState::Delivered) {
                summary.delivered_targets++;
            } else if (st.delivery_state == DeliveryState::Expired) {
                summary.expired_targets++;
            } else {
                summary.pending_targets++;
            }

            auto& u_status = read_map[st.recipient_user_id];
            u_status.user_id = st.recipient_user_id;
            if (st.read_at.has_value()) {
                u_status.read_state = ReadState::Read;
                u_status.read_at = st.read_at;
                u_status.reader_device_id = st.recipient_device_id;
            }
            summary.device_statuses.push_back(std::move(ds));
        }

        for (auto& [_, rrs] : read_map) {
            summary.recipient_read_statuses.push_back(std::move(rrs));
        }
        return summary;
    }

  private:
    mutable std::mutex mu_;
    std::map<std::pair<std::string, std::string>, DeviceDeliveryRecord> pending_;
    std::unordered_map<MessageId, std::vector<RecipientDeliveryState>> states_;
};

class ThreadSafeOutboxRepository final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string&) override {
        std::lock_guard<std::mutex> lock(mu_);
        events_.push_back(event);
    }
    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }
    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

  private:
    std::mutex mu_;
    std::vector<ConversationOutboxEvent> events_;
};

class ThreadSafeIdempotencyRepository final : public repository::IIdempotencyRepository {
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
    std::mutex mu_;
    std::unordered_map<std::string, IdempotencyRecord> records_;
};

class ThreadSafeSyncCursorRepository final : public repository::ISyncCursorRepository {
  public:
    std::optional<DeviceSyncCursor> get_sync_cursor(const DeviceId& device_id,
                                                    const ConversationId& conversation_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = cursors_.find({device_id.str(), conversation_id.to_string()});
        if (it != cursors_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::vector<DeviceSyncCursor> list_sync_cursors_by_device(const DeviceId& device_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<DeviceSyncCursor> out;
        for (const auto& [k, v] : cursors_) {
            if (k.first == device_id.str()) {
                out.push_back(v);
            }
        }
        return out;
    }

    void upsert_sync_cursor(const DeviceSyncCursor& cursor) override {
        std::lock_guard<std::mutex> lock(mu_);
        cursors_[{cursor.device_id.str(), cursor.conversation_id.to_string()}] = cursor;
    }

  private:
    std::mutex mu_;
    std::map<std::pair<std::string, std::string>, DeviceSyncCursor> cursors_;
};

class ThreadSafeAuthDirectoryClient final : public IAuthCryptoDirectoryClient {
  public:
    void set_device(const UserId& user_id, const DeviceId& device_id,
                    securecloud::auth::v1::DeviceStatus status = securecloud::auth::v1::DEVICE_STATUS_ACTIVE) {
        std::lock_guard<std::mutex> lock(mu_);
        DeviceCryptoRecord rec{
            .device_id = device_id,
            .user_id = user_id,
            .identity_key = std::vector<uint8_t>(32, 0xAA),
            .signed_prekey = std::vector<uint8_t>(32, 0xBB),
            .signed_prekey_signature = std::vector<uint8_t>(64, 0xCC),
            .one_time_prekey = std::vector<uint8_t>(32, 0xDD),
            .one_time_prekey_id = "otk-001",
            .status = status,
            .identity_key_fingerprint = "fp-" + device_id.str(),
            .signed_prekey_created_at_epoch_ms = 1000,
            .remaining_one_time_prekeys = 50,
        };
        auto& vec = user_devices_[user_id];
        bool updated = false;
        for (auto& existing : vec) {
            if (existing.device_id == device_id) {
                existing = rec;
                updated = true;
                break;
            }
        }
        if (!updated) {
            vec.push_back(rec);
        }
        device_map_[device_id] = rec;
    }

    client::Result<std::vector<DeviceCryptoRecord>, CryptoDirectoryError>
    get_user_device_crypto_records(const UserId& user_id, std::chrono::milliseconds) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = user_devices_.find(user_id);
        if (it != user_devices_.end()) {
            return it->second;
        }
        return std::vector<DeviceCryptoRecord>{};
    }

    client::Result<DeviceCryptoRecord, CryptoDirectoryError>
    get_device_crypto_identity(const DeviceId& device_id, std::chrono::milliseconds) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = device_map_.find(device_id);
        if (it != device_map_.end()) {
            return it->second;
        }
        return CryptoDirectoryError{
            .kind = CryptoDirectoryErrorKind::NotFound,
            .message = "Device not found",
            .grpc_code = ::grpc::StatusCode::NOT_FOUND,
        };
    }

  private:
    std::mutex mu_;
    std::unordered_map<UserId, std::vector<DeviceCryptoRecord>> user_devices_;
    std::unordered_map<DeviceId, DeviceCryptoRecord> device_map_;
};

// ============================================================================
// Multi-Device E2E Integration Test Suite (MSG-011-T06)
// ============================================================================

class MessagingMultiDeviceIntegrationTest : public ::testing::Test {
  protected:
    static std::string make_binary_cipher(uint8_t tag_val) {
        std::string s;
        s.reserve(64);
        for (size_t i = 0; i < 32; ++i) {
            uint8_t c1 = static_cast<uint8_t>(0xC2 + ((tag_val + i) % 2));
            uint8_t c2 = static_cast<uint8_t>(0x80 + ((tag_val + i * 3) % 64));
            s.push_back(static_cast<char>(c1));
            s.push_back(static_cast<char>(c2));
        }
        return s;
    }

    static void add_target_to_request(v1::SendMessageRequest& req, const UserId& user_id, const DeviceId& device_id,
                                      uint8_t tag_val) {
        auto* t = req.add_delivery_targets();
        t->set_recipient_user_id(user_id.str());
        t->set_recipient_device_id(device_id.str());
        auto* ep = t->mutable_encrypted_payload();
        ep->set_ciphertext_blob(make_binary_cipher(tag_val));
        ep->set_ephemeral_public_key(std::string(32, static_cast<char>(tag_val)));
        ep->set_initialization_vector(std::string(24, static_cast<char>(tag_val)));
        ep->set_auth_tag(std::string(16, static_cast<char>(tag_val)));
        ep->set_algorithm("XChaCha20-Poly1305");
    }

    void SetUp() override {
        alice_user_ = UserId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        alice_dev_1_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d360a1"); // Alice Phone
        alice_dev_2_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d360a2"); // Alice Laptop

        bob_user_ = UserId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
        bob_dev_1_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d360b1"); // Bob Phone
        bob_dev_2_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d360b2"); // Bob Tablet

        conv_id_ = ConversationId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36100").value();

        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        member_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        message_repo_ = std::make_shared<ThreadSafeMessageRepository>();
        delivery_repo_ = std::make_shared<ThreadSafeDeliveryStateRepository>();
        outbox_repo_ = std::make_shared<ThreadSafeOutboxRepository>();
        idem_repo_ = std::make_shared<ThreadSafeIdempotencyRepository>();
        cursor_repo_ = std::make_shared<ThreadSafeSyncCursorRepository>();
        auth_dir_client_ = std::make_shared<ThreadSafeAuthDirectoryClient>();

        auto now = std::chrono::system_clock::now();
        conv_repo_->save_conversation(ConversationEntity{
            .conversation_id = conv_id_,
            .type = ConversationType::Direct,
            .created_by_user_id = alice_user_,
            .created_at = now,
        });
        member_repo_->add_participant(ConversationParticipantEntity{
            .conversation_id = conv_id_,
            .user_id = alice_user_,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = now,
        });
        member_repo_->add_participant(ConversationParticipantEntity{
            .conversation_id = conv_id_,
            .user_id = bob_user_,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = now,
        });

        auth_service_ = std::make_shared<service::ConversationAuthorizationService>(*conv_repo_, *member_repo_);
        conv_service_ = std::make_shared<service::ConversationService>(*conv_repo_, *member_repo_, *auth_service_);
        seq_allocator_ = std::make_shared<service::InMemorySequenceAllocator>();
        idem_guard_ = std::make_shared<service::MessageSubmissionIdempotencyGuard>(idem_repo_);
        resolution_service_ = std::make_shared<service::RecipientDeviceResolutionService>(auth_dir_client_);
        envelope_validator_ = std::make_shared<service::E2EEnvelopeValidator>(resolution_service_);

        submission_service_ = std::make_shared<service::MessageSubmissionService>(
            auth_service_, seq_allocator_, idem_guard_, message_repo_, delivery_repo_, outbox_repo_,
            envelope_validator_, resolution_service_);

        delivery_service_ =
            std::make_shared<service::DeliveryService>(delivery_repo_, outbox_repo_, [this](const DeviceId& dev_id) {
                auto st_bob = resolution_service_->get_device_status(bob_user_, dev_id);
                if (st_bob.has_value()) {
                    return *st_bob == securecloud::auth::v1::DEVICE_STATUS_ACTIVE;
                }
                auto st_alice = resolution_service_->get_device_status(alice_user_, dev_id);
                if (st_alice.has_value()) {
                    return *st_alice == securecloud::auth::v1::DEVICE_STATUS_ACTIVE;
                }
                return true;
            });

        read_receipt_service_ = std::make_shared<service::ReadReceiptService>(
            delivery_repo_, member_repo_, outbox_repo_, [](const DeviceId&) { return true; });

        cursor_manager_ = std::make_shared<service::SyncCursorManager>(cursor_repo_, message_repo_);
        sync_service_ = std::make_shared<service::MessageSyncService>(message_repo_, cursor_manager_, auth_service_,
                                                                      delivery_repo_);
        presence_coordinator_ = std::make_shared<service::PresenceCoordinator>();

        connection_registry_ = std::make_shared<delivery::DeviceConnectionRegistry>();
        lifecycle_manager_ = std::make_shared<delivery::ConnectionLifecycleManager>(
            connection_registry_, presence_coordinator_, std::chrono::milliseconds(50), std::chrono::seconds(60));
        scheduler_ = std::make_shared<delivery::BoundedDeliveryScheduler>();
        accelerator_ =
            std::make_shared<delivery::RealtimeDeliveryAccelerator>(delivery_repo_, scheduler_, connection_registry_,
                                                                    delivery::RealtimeDeliveryAcceleratorConfig{
                                                                        .max_fast_track_batch = 50,
                                                                        .max_delivery_ttl = std::chrono::hours(24),
                                                                    });
        accelerator_->attach_to_lifecycle_manager(*lifecycle_manager_);

        service_impl_ = std::make_unique<service::MessagingServiceImpl>(
            nullptr, nullptr, nullptr, conv_service_, submission_service_, delivery_service_, read_receipt_service_,
            sync_service_, cursor_manager_, presence_coordinator_, resolution_service_);

        grpc::ServerBuilder builder;
        builder.RegisterService(service_impl_.get());
        server_ = builder.BuildAndStart();
        channel_ = server_->InProcessChannel(grpc::ChannelArguments{});
        stub_ = v1::MessagingService::NewStub(channel_);
        messaging_client_ = std::make_shared<gateway::grpc::MessagingServiceClient>(channel_);

        deadline_mgr_ = std::make_shared<gateway::http::DeadlineManager>();
        retry_policy_ = std::make_shared<gateway::http::RetryPolicy>();
        bulkhead_mgr_ = std::make_shared<gateway::http::BulkheadManager>();
        circuit_breaker_ =
            std::make_shared<gateway::http::CircuitBreaker>("messaging", gateway::GatewayCircuitBreakerConfig{
                                                                             .enabled = true,
                                                                             .failure_threshold = 5,
                                                                             .recovery_timeout_ms = 1000,
                                                                             .half_open_probe_count = 1,
                                                                         });
        gateway_handler_ = std::make_unique<gateway::http::MessagingProxyHandler>(
            messaging_client_, deadline_mgr_, retry_policy_, bulkhead_mgr_, circuit_breaker_);
    }

    void TearDown() override {
        lifecycle_manager_->stop();
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    static void add_caller_metadata(grpc::ClientContext& ctx, const UserId& user, const DeviceId& device) {
        ctx.AddMetadata("x-user-id", user.str());
        ctx.AddMetadata("x-device-id", device.str());
        ctx.AddMetadata("x-correlation-id", "corr-msg-011-integ");
    }

    UserId alice_user_;
    DeviceId alice_dev_1_;
    DeviceId alice_dev_2_;
    UserId bob_user_;
    DeviceId bob_dev_1_;
    DeviceId bob_dev_2_;
    ConversationId conv_id_;

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> member_repo_;
    std::shared_ptr<ThreadSafeMessageRepository> message_repo_;
    std::shared_ptr<ThreadSafeDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<ThreadSafeOutboxRepository> outbox_repo_;
    std::shared_ptr<ThreadSafeIdempotencyRepository> idem_repo_;
    std::shared_ptr<ThreadSafeSyncCursorRepository> cursor_repo_;
    std::shared_ptr<ThreadSafeAuthDirectoryClient> auth_dir_client_;

    std::shared_ptr<service::ConversationAuthorizationService> auth_service_;
    std::shared_ptr<service::ConversationService> conv_service_;
    std::shared_ptr<service::InMemorySequenceAllocator> seq_allocator_;
    std::shared_ptr<service::MessageSubmissionIdempotencyGuard> idem_guard_;
    std::shared_ptr<service::RecipientDeviceResolutionService> resolution_service_;
    std::shared_ptr<service::E2EEnvelopeValidator> envelope_validator_;
    std::shared_ptr<service::MessageSubmissionService> submission_service_;
    std::shared_ptr<service::DeliveryService> delivery_service_;
    std::shared_ptr<service::ReadReceiptService> read_receipt_service_;
    std::shared_ptr<service::SyncCursorManager> cursor_manager_;
    std::shared_ptr<service::MessageSyncService> sync_service_;
    std::shared_ptr<service::PresenceCoordinator> presence_coordinator_;

    std::shared_ptr<delivery::DeviceConnectionRegistry> connection_registry_;
    std::shared_ptr<delivery::ConnectionLifecycleManager> lifecycle_manager_;
    std::shared_ptr<delivery::BoundedDeliveryScheduler> scheduler_;
    std::shared_ptr<delivery::RealtimeDeliveryAccelerator> accelerator_;

    std::unique_ptr<service::MessagingServiceImpl> service_impl_;
    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::MessagingService::Stub> stub_;
    std::shared_ptr<gateway::grpc::MessagingServiceClient> messaging_client_;
    std::shared_ptr<gateway::http::DeadlineManager> deadline_mgr_;
    std::shared_ptr<gateway::http::RetryPolicy> retry_policy_;
    std::shared_ptr<gateway::http::BulkheadManager> bulkhead_mgr_;
    std::shared_ptr<gateway::http::CircuitBreaker> circuit_breaker_;
    std::unique_ptr<gateway::http::MessagingProxyHandler> gateway_handler_;
};

// ============================================================================
// Test 1: Multi-Device Fan-Out & Self-Fanout (Sent History Sync)
// ============================================================================

TEST_F(MessagingMultiDeviceIntegrationTest, Test01_MultiDeviceFanOutAndSelfFanout) {
    auth_dir_client_->set_device(alice_user_, alice_dev_1_);
    auth_dir_client_->set_device(alice_user_, alice_dev_2_);
    auth_dir_client_->set_device(bob_user_, bob_dev_1_);
    auth_dir_client_->set_device(bob_user_, bob_dev_2_);

    // 1a. Omitting Alice's companion device A2 is rejected under strict completeness
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_1_);
        v1::SendMessageRequest req;
        req.set_conversation_id(conv_id_.to_string());
        req.set_sender_device_id(alice_dev_1_.str());
        req.set_client_idempotency_token("idem-omit-companion-001");
        add_target_to_request(req, bob_user_, bob_dev_1_, 0x21);
        add_target_to_request(req, bob_user_, bob_dev_2_, 0x22);

        v1::SendMessageResponse resp;
        auto status = stub_->SendMessage(&ctx, req, &resp);
        EXPECT_FALSE(status.ok()) << "Omitting sender companion device A2 must be rejected";
    }

    // 1b. Full fan-out including companion device A2 + recipient devices B1, B2 succeeds
    std::string msg_id;
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_1_);
        v1::SendMessageRequest req;
        req.set_conversation_id(conv_id_.to_string());
        req.set_sender_device_id(alice_dev_1_.str());
        req.set_client_idempotency_token("idem-full-fanout-001");
        add_target_to_request(req, alice_user_, alice_dev_2_, 0x12);
        add_target_to_request(req, bob_user_, bob_dev_1_, 0x21);
        add_target_to_request(req, bob_user_, bob_dev_2_, 0x22);

        v1::SendMessageResponse resp;
        auto status = stub_->SendMessage(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << status.error_message();
        EXPECT_EQ(resp.target_count(), 3u);
        msg_id = resp.message_id();
    }

    // 1c. A2, B1, and B2 independently sync and receive ONLY their own encrypted payload, then ACK
    const std::vector<std::tuple<UserId, DeviceId, uint8_t>> targets = {
        {alice_user_, alice_dev_2_, 0x12},
        {bob_user_, bob_dev_1_, 0x21},
        {bob_user_, bob_dev_2_, 0x22},
    };

    for (const auto& [uid, did, tag] : targets) {
        grpc::ClientContext sync_ctx;
        add_caller_metadata(sync_ctx, uid, did);
        v1::SyncDeviceMessagesRequest sync_req;
        sync_req.set_device_id(did.str());
        sync_req.set_conversation_id(conv_id_.to_string());
        sync_req.set_since_sequence(0);
        v1::SyncDeviceMessagesResponse sync_resp;
        ASSERT_TRUE(stub_->SyncDeviceMessages(&sync_ctx, sync_req, &sync_resp).ok());
        ASSERT_EQ(sync_resp.messages_size(), 1);
        ASSERT_EQ(sync_resp.messages(0).delivery_targets_size(), 1);
        EXPECT_EQ(sync_resp.messages(0).delivery_targets(0).recipient_device_id(), did.str());
        EXPECT_EQ(sync_resp.messages(0).delivery_targets(0).encrypted_payload().ciphertext_blob(),
                  make_binary_cipher(tag));

        grpc::ClientContext ack_ctx;
        add_caller_metadata(ack_ctx, uid, did);
        v1::AcknowledgeDeliveryRequest ack_req;
        ack_req.set_message_id(msg_id);
        ack_req.set_recipient_device_id(did.str());
        ack_req.set_delivered_at_unix_ms(1760000001000LL);
        v1::AcknowledgeDeliveryResponse ack_resp;
        ASSERT_TRUE(stub_->AcknowledgeDelivery(&ack_ctx, ack_req, &ack_resp).ok());
    }

    // 1d. B1 records a read receipt; verify delivery summary via Gateway HTTP route
    {
        grpc::ClientContext read_ctx;
        add_caller_metadata(read_ctx, bob_user_, bob_dev_1_);
        v1::SendReadReceiptRequest read_req;
        read_req.set_conversation_id(conv_id_.to_string());
        read_req.set_message_id(msg_id);
        read_req.set_reader_device_id(bob_dev_1_.str());
        read_req.set_read_at_unix_ms(1760000002000LL);
        v1::SendReadReceiptResponse read_resp;
        ASSERT_TRUE(stub_->SendReadReceipt(&read_ctx, read_req, &read_resp).ok());
    }

    {
        httplib::Request http_req;
        http_req.method = "GET";
        http_req.path = "/v1/conversations/" + conv_id_.to_string() + "/messages/" + msg_id + "/delivery-status";
        http_req.path_params["conversationId"] = conv_id_.to_string();
        http_req.path_params["messageId"] = msg_id;

        httplib::Response http_res;
        gateway::http::AuthenticatedContext auth_ctx(
            alice_user_.str(), alice_dev_1_.str(), "sess-01",
            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
            {"messaging:read", "messaging:write"}, 1800000000000LL);
        gateway_handler_->handle_get_delivery_status(http_req, http_res, auth_ctx);

        ASSERT_EQ(http_res.status, 200);
        auto body = nlohmann::json::parse(http_res.body);
        EXPECT_EQ(body["summary"]["total_targets"], 3);
        EXPECT_EQ(body["summary"]["delivered_targets"], 3);
        EXPECT_EQ(body["summary"]["pending_targets"], 0);
        ASSERT_EQ(body["device_statuses"].size(), 3u);
        for (const auto& ds : body["device_statuses"]) {
            EXPECT_EQ(ds["delivery_state"], "DELIVERED");
        }
        ASSERT_FALSE(body["recipient_read_statuses"].empty());
        bool found_bob_read = false;
        for (const auto& rs : body["recipient_read_statuses"]) {
            if (rs["user_id"] == bob_user_.str()) {
                EXPECT_TRUE(rs["is_read"].get<bool>());
                EXPECT_EQ(rs["reader_device_id"], bob_dev_1_.str());
                found_bob_read = true;
            }
        }
        EXPECT_TRUE(found_bob_read);
    }
}

// ============================================================================
// Test 2: Anti-Impersonation Perimeter Rejection
// ============================================================================

TEST_F(MessagingMultiDeviceIntegrationTest, Test02_AntiImpersonationPerimeterRejection) {
    auth_dir_client_->set_device(alice_user_, alice_dev_1_);
    auth_dir_client_->set_device(alice_user_, alice_dev_2_);
    auth_dir_client_->set_device(bob_user_, bob_dev_1_);
    auth_dir_client_->set_device(bob_user_, bob_dev_2_);

    // Submit a message
    std::string msg_id;
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_1_);
        v1::SendMessageRequest req;
        req.set_conversation_id(conv_id_.to_string());
        req.set_sender_device_id(alice_dev_1_.str());
        req.set_client_idempotency_token("idem-impersonation-001");
        add_target_to_request(req, alice_user_, alice_dev_2_, 0x12);
        add_target_to_request(req, bob_user_, bob_dev_1_, 0x21);
        add_target_to_request(req, bob_user_, bob_dev_2_, 0x22);
        v1::SendMessageResponse resp;
        ASSERT_TRUE(stub_->SendMessage(&ctx, req, &resp).ok());
        msg_id = resp.message_id();
    }

    // 2a. Authenticated device A1 attempts to ACK delivery for companion device A2 -> Rejected
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_1_);
        v1::AcknowledgeDeliveryRequest req;
        req.set_message_id(msg_id);
        req.set_recipient_device_id(alice_dev_2_.str());
        v1::AcknowledgeDeliveryResponse resp;
        auto status = stub_->AcknowledgeDelivery(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
    }

    // 2b. Authenticated device B1 attempts to sync messages for companion device B2 -> Rejected
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, bob_user_, bob_dev_1_);
        v1::SyncDeviceMessagesRequest req;
        req.set_device_id(bob_dev_2_.str());
        req.set_conversation_id(conv_id_.to_string());
        v1::SyncDeviceMessagesResponse resp;
        auto status = stub_->SyncDeviceMessages(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
    }
}

// ============================================================================
// Test 3: Device Revocation Quarantine
// ============================================================================

TEST_F(MessagingMultiDeviceIntegrationTest, Test03_DeviceRevocationQuarantine) {
    auth_dir_client_->set_device(alice_user_, alice_dev_1_);
    auth_dir_client_->set_device(alice_user_, alice_dev_2_);
    auth_dir_client_->set_device(bob_user_, bob_dev_1_);
    auth_dir_client_->set_device(bob_user_, bob_dev_2_);

    // Revoke Bob's B2 in Auth directory and invalidate cache
    auth_dir_client_->set_device(bob_user_, bob_dev_2_, securecloud::auth::v1::DEVICE_STATUS_REVOKED);
    resolution_service_->invalidate_device(bob_dev_2_);
    scheduler_->purge_device_tasks(bob_dev_2_);

    // 3a. Future submission targeting revoked B2 is rejected with DEVICE_REVOKED (PERMISSION_DENIED)
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_1_);
        v1::SendMessageRequest req;
        req.set_conversation_id(conv_id_.to_string());
        req.set_sender_device_id(alice_dev_1_.str());
        req.set_client_idempotency_token("idem-revoked-b2-001");
        add_target_to_request(req, alice_user_, alice_dev_2_, 0x12);
        add_target_to_request(req, bob_user_, bob_dev_1_, 0x21);
        add_target_to_request(req, bob_user_, bob_dev_2_, 0x22);
        v1::SendMessageResponse resp;
        auto status = stub_->SendMessage(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    }

    // 3b. Submission targeting active devices {A2, B1} succeeds
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_1_);
        v1::SendMessageRequest req;
        req.set_conversation_id(conv_id_.to_string());
        req.set_sender_device_id(alice_dev_1_.str());
        req.set_client_idempotency_token("idem-active-only-002");
        add_target_to_request(req, alice_user_, alice_dev_2_, 0x12);
        add_target_to_request(req, bob_user_, bob_dev_1_, 0x21);
        v1::SendMessageResponse resp;
        auto status = stub_->SendMessage(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << status.error_message();
        EXPECT_EQ(resp.target_count(), 2u);
    }

    // 3c. Revoked B2 attempts SyncDeviceMessages -> Rejected
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, bob_user_, bob_dev_2_);
        v1::SyncDeviceMessagesRequest req;
        req.set_device_id(bob_dev_2_.str());
        req.set_conversation_id(conv_id_.to_string());
        v1::SyncDeviceMessagesResponse resp;
        auto status = stub_->SyncDeviceMessages(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    }
}

// ============================================================================
// Test 4: Newly Enrolled Device Boundary (Zero-Retroactive-Synthesis)
// ============================================================================

TEST_F(MessagingMultiDeviceIntegrationTest, Test04_NewlyEnrolledDeviceBoundaryZeroRetroactiveSynthesis) {
    // Initially Bob only has B1 enrolled
    auth_dir_client_->set_device(alice_user_, alice_dev_1_);
    auth_dir_client_->set_device(bob_user_, bob_dev_1_);

    // M1 and M2 sent before B2 is enrolled
    for (int i = 1; i <= 2; ++i) {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_1_);
        v1::SendMessageRequest req;
        req.set_conversation_id(conv_id_.to_string());
        req.set_sender_device_id(alice_dev_1_.str());
        req.set_client_idempotency_token("idem-pre-enroll-" + std::to_string(i));
        add_target_to_request(req, bob_user_, bob_dev_1_, static_cast<uint8_t>(0x30 + i));
        v1::SendMessageResponse resp;
        ASSERT_TRUE(stub_->SendMessage(&ctx, req, &resp).ok());
    }

    // Bob enrolls B2; invalidate cache so resolution service discovers B2
    auth_dir_client_->set_device(bob_user_, bob_dev_2_);
    resolution_service_->invalidate_user_cache(bob_user_);

    // M3 sent targeting both B1 and B2
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_1_);
        v1::SendMessageRequest req;
        req.set_conversation_id(conv_id_.to_string());
        req.set_sender_device_id(alice_dev_1_.str());
        req.set_client_idempotency_token("idem-post-enroll-3");
        add_target_to_request(req, bob_user_, bob_dev_1_, 0x41);
        add_target_to_request(req, bob_user_, bob_dev_2_, 0x42);
        v1::SendMessageResponse resp;
        ASSERT_TRUE(stub_->SendMessage(&ctx, req, &resp).ok());
    }

    // B2 syncs from sequence 0: receives M1, M2 metadata without payload, and M3 full envelope
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, bob_user_, bob_dev_2_);
        v1::SyncDeviceMessagesRequest req;
        req.set_device_id(bob_dev_2_.str());
        req.set_conversation_id(conv_id_.to_string());
        req.set_since_sequence(0);
        v1::SyncDeviceMessagesResponse resp;
        ASSERT_TRUE(stub_->SyncDeviceMessages(&ctx, req, &resp).ok());
        ASSERT_EQ(resp.messages_size(), 3);

        EXPECT_EQ(resp.messages(0).delivery_targets_size(), 0);
        EXPECT_EQ(resp.messages(1).delivery_targets_size(), 0);
        ASSERT_EQ(resp.messages(2).delivery_targets_size(), 1);
        EXPECT_EQ(resp.messages(2).delivery_targets(0).recipient_device_id(), bob_dev_2_.str());
        EXPECT_EQ(resp.messages(2).delivery_targets(0).encrypted_payload().ciphertext_blob(), make_binary_cipher(0x42));
    }
}

// ============================================================================
// Test 5: Concurrent Real-Time Dispatch Isolation
// ============================================================================

TEST_F(MessagingMultiDeviceIntegrationTest, Test05_ConcurrentRealtimeDispatchIsolation) {
    auth_dir_client_->set_device(alice_user_, alice_dev_1_);
    auth_dir_client_->set_device(bob_user_, bob_dev_1_);
    auth_dir_client_->set_device(bob_user_, bob_dev_2_);

    // B1 connects online; B2 is offline
    auto ch_b1 = std::make_shared<delivery::MockDeviceDeliveryChannel>(bob_dev_1_, bob_user_);
    (void)lifecycle_manager_->establish_connection(ch_b1);

    // Alice sends M1 targeting B1 and B2
    std::string msg_id;
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_1_);
        v1::SendMessageRequest req;
        req.set_conversation_id(conv_id_.to_string());
        req.set_sender_device_id(alice_dev_1_.str());
        req.set_client_idempotency_token("idem-rt-isolation-1");
        add_target_to_request(req, bob_user_, bob_dev_1_, 0x51);
        add_target_to_request(req, bob_user_, bob_dev_2_, 0x52);
        v1::SendMessageResponse resp;
        ASSERT_TRUE(stub_->SendMessage(&ctx, req, &resp).ok());
        msg_id = resp.message_id();
    }

    // B1 acknowledges delivery immediately
    {
        grpc::ClientContext ack_ctx;
        add_caller_metadata(ack_ctx, bob_user_, bob_dev_1_);
        v1::AcknowledgeDeliveryRequest ack_req;
        ack_req.set_message_id(msg_id);
        ack_req.set_recipient_device_id(bob_dev_1_.str());
        v1::AcknowledgeDeliveryResponse ack_resp;
        ASSERT_TRUE(stub_->AcknowledgeDelivery(&ack_ctx, ack_req, &ack_resp).ok());
    }

    EXPECT_EQ(scheduler_->device_queue_depth(bob_dev_1_), 0u);
    EXPECT_EQ(scheduler_->device_queue_depth(bob_dev_2_), 0u);

    // Now B2 connects online -> RealtimeDeliveryAccelerator fast-tracks M1 to B2 without re-dispatching to B1!
    auto ch_b2 = std::make_shared<delivery::MockDeviceDeliveryChannel>(bob_dev_2_, bob_user_);
    (void)lifecycle_manager_->establish_connection(ch_b2);

    EXPECT_EQ(scheduler_->device_queue_depth(bob_dev_1_), 0u) << "B1 must not receive duplicate fast-track dispatch";
    EXPECT_EQ(scheduler_->device_queue_depth(bob_dev_2_), 1u) << "B2 must receive accelerated delivery on reconnect";

    auto task_b2 = scheduler_->try_dequeue();
    ASSERT_TRUE(task_b2.has_value());
    EXPECT_EQ(task_b2->recipient_device_id, bob_dev_2_);
    EXPECT_EQ(task_b2->message_id.to_string(), msg_id);
}

} // namespace
} // namespace securecloud::messaging
