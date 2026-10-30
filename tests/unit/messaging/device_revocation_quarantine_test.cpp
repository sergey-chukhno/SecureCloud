#include "client/auth_crypto_directory_client_interface.hpp"
#include "delivery/bounded_delivery_scheduler.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/envelope_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/message_entity.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "repository/message_repository_interface.hpp"
#include "repository/sync_cursor_repository_interface.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/delivery_service.hpp"
#include "service/message_sync_service.hpp"
#include "service/messaging_service_impl.hpp"
#include "service/recipient_device_resolution_service.hpp"
#include "service/sync_cursor_manager.hpp"

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"

#include <chrono>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace securecloud::messaging::service {
namespace {

using client::CryptoDirectoryError;
using client::CryptoDirectoryErrorKind;
using client::DeviceCryptoRecord;
using client::IAuthCryptoDirectoryClient;
using client::Result;
using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryState;
using domain::DeliveryTask;
using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::DeviceSyncCursor;
using domain::E2EAlgorithm;
using domain::E2EProtocolVersion;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::MessagePriority;
using domain::ParticipantRole;
using domain::PerDeviceEnvelope;
using domain::RecipientDeliveryState;
using domain::UserId;

// ============================================================================
// Mocks
// ============================================================================

class MockAuthDirectoryClient final : public IAuthCryptoDirectoryClient {
  public:
    void set_device(const UserId& user_id, const DeviceId& device_id, securecloud::auth::v1::DeviceStatus status) {
        std::lock_guard<std::mutex> lock(mutex_);
        DeviceCryptoRecord rec{
            .device_id = device_id,
            .user_id = user_id,
            .identity_key = std::vector<uint8_t>(32, 0x01),
            .signed_prekey = std::vector<uint8_t>(32, 0x02),
            .signed_prekey_signature = std::vector<uint8_t>(64, 0x03),
            .one_time_prekey = std::vector<uint8_t>(32, 0x04),
            .one_time_prekey_id = "otk-1",
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

    Result<std::vector<DeviceCryptoRecord>, CryptoDirectoryError>
    get_user_device_crypto_records(const UserId& user_id, std::chrono::milliseconds) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = user_devices_.find(user_id);
        if (it != user_devices_.end()) {
            return it->second;
        }
        return std::vector<DeviceCryptoRecord>{};
    }

    Result<DeviceCryptoRecord, CryptoDirectoryError> get_device_crypto_identity(const DeviceId& device_id,
                                                                                std::chrono::milliseconds) override {
        std::lock_guard<std::mutex> lock(mutex_);
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
    std::mutex mutex_;
    std::unordered_map<UserId, std::vector<DeviceCryptoRecord>> user_devices_;
    std::unordered_map<DeviceId, DeviceCryptoRecord> device_map_;
};

class MockDeliveryRepo final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>&) override {}
    std::vector<DeviceDeliveryRecord> fetch_pending_for_device(const DeviceId&, const std::string&, size_t) override {
        return {};
    }
    void update_device_delivery_status(const DeviceId&, const std::string&,
                                       const std::chrono::system_clock::time_point&, const MessageId&, DeliveryState,
                                       int32_t, std::optional<std::chrono::system_clock::time_point>) override {}
    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        states_ = states;
    }
    void record_delivery_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {
    }
    void record_read_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {}
    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId&) override { return states_; }

  private:
    std::vector<RecipientDeliveryState> states_;
};

class MockOutboxRepo final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const domain::ConversationOutboxEvent&, const std::string&) override {}
    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }
    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}
};

class MockMessageRepo final : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity&) override {}
    std::optional<MessageEntity> find_by_id(const ConversationId&, const MessageBucket&, const MessageId&) override {
        return std::nullopt;
    }
    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId&, const MessageBucket&, uint64_t,
                                                               uint64_t, size_t) override {
        return {};
    }
    uint64_t get_last_sequence(const ConversationId&, const MessageBucket&) override { return 0; }
};

class MockCursorRepo final : public repository::ISyncCursorRepository {
  public:
    std::optional<DeviceSyncCursor> get_sync_cursor(const DeviceId&, const ConversationId&) override {
        return std::nullopt;
    }
    std::vector<DeviceSyncCursor> list_sync_cursors_by_device(const DeviceId&) override { return {}; }
    void upsert_sync_cursor(const DeviceSyncCursor&) override {}
};

// ============================================================================
// Tests (MSG-011-T03)
// ============================================================================

TEST(DeviceRevocationQuarantineTest, SubmissionTargetingRevokedDeviceIsRejectedFailClosed) {
    auto auth_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice("018f1234-5678-7000-8000-000000000001");
    UserId bob("018f1234-5678-7000-8000-000000000002");
    DeviceId alice_phone("018f1234-5678-7000-8000-0000000000a1");
    DeviceId bob_phone("018f1234-5678-7000-8000-0000000000b1");
    DeviceId bob_revoked_tablet("018f1234-5678-7000-8000-0000000000b2");

    auth_client->set_device(alice, alice_phone, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    auth_client->set_device(bob, bob_phone, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    auth_client->set_device(bob, bob_revoked_tablet, securecloud::auth::v1::DEVICE_STATUS_REVOKED);

    RecipientDeviceResolutionService resolution_svc(auth_client);

    PerDeviceEnvelope env_b1{
        .recipient_user_id = bob,
        .recipient_device_id = bob_phone,
        .ciphertext_blob = "CT_B1",
    };
    PerDeviceEnvelope env_b2_revoked{
        .recipient_user_id = bob,
        .recipient_device_id = bob_revoked_tablet,
        .ciphertext_blob = "CT_B2",
    };

    auto res =
        resolution_svc.validate_submission_targets({alice, bob}, {env_b1, env_b2_revoked}, alice_phone, alice, true);
    EXPECT_FALSE(res.is_valid);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED);
}

TEST(DeviceRevocationQuarantineTest, SchedulerPurgesQueuedTasksForRevokedDeviceWithoutAffectingActiveDevices) {
    delivery::BoundedDeliveryScheduler scheduler;
    DeviceId active_dev("018f1234-5678-7000-8000-0000000000b1");
    DeviceId revoked_dev("018f1234-5678-7000-8000-0000000000b2");
    ConversationId conv_id = ConversationId::generate_v7();

    for (uint64_t seq = 1; seq <= 3; ++seq) {
        (void)seq;
        DeliveryTask t_revoked;
        t_revoked.recipient_device_id = revoked_dev;
        t_revoked.conversation_id = conv_id;
        t_revoked.message_id = MessageId::generate_v7();
        t_revoked.priority = MessagePriority::Normal;
        EXPECT_EQ(scheduler.schedule(t_revoked), delivery::SchedulerStatus::Enqueued);

        DeliveryTask t_active;
        t_active.recipient_device_id = active_dev;
        t_active.conversation_id = conv_id;
        t_active.message_id = MessageId::generate_v7();
        t_active.priority = MessagePriority::Normal;
        EXPECT_EQ(scheduler.schedule(t_active), delivery::SchedulerStatus::Enqueued);
    }

    EXPECT_EQ(scheduler.device_queue_depth(revoked_dev), 3u);
    EXPECT_EQ(scheduler.device_queue_depth(active_dev), 3u);
    EXPECT_EQ(scheduler.global_queue_depth(), 6u);

    size_t purged = scheduler.purge_device_tasks(revoked_dev);
    EXPECT_EQ(purged, 3u);
    EXPECT_EQ(scheduler.device_queue_depth(revoked_dev), 0u);
    EXPECT_EQ(scheduler.device_queue_depth(active_dev), 3u);
    EXPECT_EQ(scheduler.global_queue_depth(), 3u);
}

TEST(DeviceRevocationQuarantineTest, RevokedDeviceBlockedFromGetMessagesSyncAndAcknowledgeDelivery) {
    auto auth_client = std::make_shared<MockAuthDirectoryClient>();
    UserId bob("018f1234-5678-7000-8000-000000000002");
    DeviceId bob_revoked("018f1234-5678-7000-8000-0000000000b2");
    ConversationId conv_id = ConversationId::generate_v7();
    MessageId msg_id = MessageId::generate_v7();

    // Initially active, then invalidated and revoked
    auth_client->set_device(bob, bob_revoked, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    auto resolution_svc = std::make_shared<RecipientDeviceResolutionService>(auth_client);
    EXPECT_EQ(resolution_svc->get_device_status(bob, bob_revoked), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    // Revoke in Auth and invalidate cache
    auth_client->set_device(bob, bob_revoked, securecloud::auth::v1::DEVICE_STATUS_REVOKED);
    resolution_svc->invalidate_device(bob_revoked);
    EXPECT_EQ(resolution_svc->get_device_status(bob, bob_revoked), securecloud::auth::v1::DEVICE_STATUS_REVOKED);

    auto conv_repo = std::make_shared<repository::InMemoryConversationRepository>();
    auto member_repo = std::make_shared<repository::InMemoryMembershipRepository>();
    auto msg_repo = std::make_shared<MockMessageRepo>();
    auto cursor_repo = std::make_shared<MockCursorRepo>();
    auto delivery_repo = std::make_shared<MockDeliveryRepo>();
    auto outbox_repo = std::make_shared<MockOutboxRepo>();

    auto auth_svc = std::make_shared<ConversationAuthorizationService>(*conv_repo, *member_repo);
    auto cursor_mgr = std::make_shared<SyncCursorManager>(cursor_repo, msg_repo);
    auto sync_svc = std::make_shared<MessageSyncService>(msg_repo, cursor_mgr, auth_svc, delivery_repo);
    auto delivery_svc =
        std::make_shared<DeliveryService>(delivery_repo, outbox_repo, [resolution_svc, bob](const DeviceId& dev) {
            auto st = resolution_svc->get_device_status(bob, dev);
            return !st.has_value() || *st == securecloud::auth::v1::DEVICE_STATUS_ACTIVE;
        });

    MessagingServiceImpl service(nullptr, nullptr, nullptr, nullptr, nullptr, delivery_svc, nullptr, sync_svc,
                                 cursor_mgr, nullptr, resolution_svc);

    grpc::ServerBuilder builder;
    builder.RegisterService(&service);
    auto server = builder.BuildAndStart();
    auto stub = v1::MessagingService::NewStub(server->InProcessChannel(grpc::ChannelArguments{}));

    // 1. Revoked device attempts GetMessages -> Rejected
    {
        grpc::ClientContext ctx;
        ctx.AddMetadata("x-user-id", bob.str());
        ctx.AddMetadata("x-device-id", bob_revoked.str());
        v1::GetMessagesRequest req;
        req.set_conversation_id(conv_id.to_string());
        req.set_recipient_device_id(bob_revoked.str());
        v1::GetMessagesResponse resp;
        auto status = stub->GetMessages(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    }

    // 2. Revoked device attempts SyncDeviceMessages -> Rejected
    {
        grpc::ClientContext ctx;
        ctx.AddMetadata("x-user-id", bob.str());
        ctx.AddMetadata("x-device-id", bob_revoked.str());
        v1::SyncDeviceMessagesRequest req;
        req.set_device_id(bob_revoked.str());
        req.set_conversation_id(conv_id.to_string());
        v1::SyncDeviceMessagesResponse resp;
        auto status = stub->SyncDeviceMessages(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    }

    // 3. Revoked device attempts AcknowledgeDelivery -> Rejected
    {
        grpc::ClientContext ctx;
        ctx.AddMetadata("x-user-id", bob.str());
        ctx.AddMetadata("x-device-id", bob_revoked.str());
        v1::AcknowledgeDeliveryRequest req;
        req.set_message_id(msg_id.to_string());
        req.set_recipient_device_id(bob_revoked.str());
        v1::AcknowledgeDeliveryResponse resp;
        auto status = stub->AcknowledgeDelivery(&ctx, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    }

    server->Shutdown();
}

} // namespace
} // namespace securecloud::messaging::service
