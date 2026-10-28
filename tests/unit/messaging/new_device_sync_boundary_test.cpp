#include "concurrency/bounded_worker_pool.hpp"
#include "db/mock_scylla_session.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/envelope_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/message_entity.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/scylla_delivery_state_repository.hpp"
#include "repository/message_repository_interface.hpp"
#include "repository/sync_cursor_repository_interface.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/message_sync_service.hpp"
#include "service/messaging_service_impl.hpp"
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

using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryState;
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
using domain::RecipientDeliveryState;
using domain::UserId;

// ============================================================================
// In-Memory Repositories for Multi-Device Sync Boundary Verification
// ============================================================================

class InMemoryMessageRepo final : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& message) override {
        std::lock_guard<std::mutex> lock(mutex_);
        messages_.push_back(message);
    }

    std::optional<MessageEntity> find_by_id(const ConversationId& conv_id, const MessageBucket& bucket,
                                            const MessageId& msg_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
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
        std::lock_guard<std::mutex> lock(mutex_);
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
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t max_seq = 0;
        for (const auto& m : messages_) {
            if (m.conversation_id == conv_id && m.message_bucket == bucket) {
                if (m.message_sequence > max_seq) {
                    max_seq = m.message_sequence;
                }
            }
        }
        return max_seq;
    }

  private:
    mutable std::mutex mutex_;
    std::vector<MessageEntity> messages_;
};

class InMemorySyncCursorRepo final : public repository::ISyncCursorRepository {
  public:
    std::optional<DeviceSyncCursor> get_sync_cursor(const DeviceId& device_id,
                                                    const ConversationId& conversation_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cursors_.find({device_id.str(), conversation_id.to_string()});
        if (it != cursors_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::vector<DeviceSyncCursor> list_sync_cursors_by_device(const DeviceId& device_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DeviceSyncCursor> out;
        for (const auto& [key, val] : cursors_) {
            if (key.first == device_id.str()) {
                out.push_back(val);
            }
        }
        return out;
    }

    void upsert_sync_cursor(const DeviceSyncCursor& cursor) override {
        std::lock_guard<std::mutex> lock(mutex_);
        cursors_[{cursor.device_id.str(), cursor.conversation_id.to_string()}] = cursor;
    }

  private:
    mutable std::mutex mutex_;
    std::map<std::pair<std::string, std::string>, DeviceSyncCursor> cursors_;
};

class InMemoryMultiDeviceDeliveryRepo final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& r : records) {
            records_[{r.device_id.str(), r.message_id.to_string()}] = r;
        }
    }

    std::vector<DeviceDeliveryRecord> fetch_pending_for_device(const DeviceId& device_id, const std::string& bucket,
                                                               size_t limit) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DeviceDeliveryRecord> out;
        for (const auto& [key, r] : records_) {
            if (r.device_id == device_id && r.delivery_bucket == bucket) {
                out.push_back(r);
                if (out.size() >= limit) {
                    break;
                }
            }
        }
        return out;
    }

    void update_device_delivery_status(const DeviceId& device_id, const std::string&,
                                       const std::chrono::system_clock::time_point&, const MessageId& message_id,
                                       DeliveryState state, int32_t attempt_count,
                                       std::optional<std::chrono::system_clock::time_point> next_retry) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = records_.find({device_id.str(), message_id.to_string()});
        if (it != records_.end()) {
            it->second.delivery_state = state;
            it->second.attempt_count = attempt_count;
            it->second.next_retry_at = next_retry;
        }
    }

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& st : states) {
            states_[st.message_id].push_back(st);
        }
    }

    void record_delivery_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point& delivered_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& st : states_[message_id]) {
            if (st.recipient_device_id == recipient_device_id) {
                st.delivery_state = DeliveryState::Delivered;
                st.delivered_at = delivered_at;
            }
        }
        auto it = records_.find({recipient_device_id.str(), message_id.to_string()});
        if (it != records_.end()) {
            it->second.delivery_state = DeliveryState::Delivered;
        }
    }

    void record_read_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                         const std::chrono::system_clock::time_point& read_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& st : states_[message_id]) {
            if (st.recipient_device_id == recipient_device_id) {
                st.delivery_state = DeliveryState::Read;
                st.read_at = read_at;
            }
        }
    }

    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = states_.find(message_id);
        if (it != states_.end()) {
            return it->second;
        }
        return {};
    }

    std::optional<DeviceDeliveryRecord> get_delivery_record_for_device(const DeviceId& device_id,
                                                                       const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = records_.find({device_id.str(), message_id.to_string()});
        if (it != records_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

  private:
    mutable std::mutex mutex_;
    std::map<std::pair<std::string, std::string>, DeviceDeliveryRecord> records_;
    std::unordered_map<MessageId, std::vector<RecipientDeliveryState>> states_;
};

// ============================================================================
// Test Fixture
// ============================================================================

class NewDeviceSyncBoundaryTest : public ::testing::Test {
  protected:
    void SetUp() override {
        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        member_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        message_repo_ = std::make_shared<InMemoryMessageRepo>();
        cursor_repo_ = std::make_shared<InMemorySyncCursorRepo>();
        delivery_repo_ = std::make_shared<InMemoryMultiDeviceDeliveryRepo>();

        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *member_repo_);
        cursor_manager_ = std::make_shared<SyncCursorManager>(cursor_repo_, message_repo_);
        sync_service_ =
            std::make_shared<MessageSyncService>(message_repo_, cursor_manager_, auth_service_, delivery_repo_);

        conv_id_ = ConversationId::from_string("018f1234-5678-7000-8000-000000000001").value();
        alice_user_ = UserId("018f1234-5678-7000-8000-000000000010");
        bob_user_ = UserId("018f1234-5678-7000-8000-000000000020");

        bob_sender_dev_ = DeviceId("018f1234-5678-7000-8000-000000000201");
        alice_dev_1_ = DeviceId("018f1234-5678-7000-8000-000000000101"); // Enrolled at t=0
        alice_dev_2_ = DeviceId("018f1234-5678-7000-8000-000000000102"); // Newly enrolled after M1, M2

        auto now = std::chrono::system_clock::now();
        ConversationEntity conv{
            .conversation_id = conv_id_,
            .type = ConversationType::Direct,
            .created_by_user_id = bob_user_,
            .created_at = now,
        };
        conv_repo_->save_conversation(conv);

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
            .role = ParticipantRole::Admin,
            .status = MembershipStatus::Active,
            .joined_at = now,
        });

        messaging_service_ = std::make_unique<MessagingServiceImpl>(nullptr, nullptr, nullptr, nullptr, nullptr,
                                                                    nullptr, nullptr, sync_service_, cursor_manager_);

        grpc::ServerBuilder builder;
        builder.RegisterService(messaging_service_.get());
        server_ = builder.BuildAndStart();
        channel_ = server_->InProcessChannel(grpc::ChannelArguments{});
        stub_ = v1::MessagingService::NewStub(channel_);
    }

    void TearDown() override {
        if (server_) {
            server_->Shutdown();
        }
    }

    MessageId seed_message_with_targets(uint64_t seq, const std::vector<std::pair<DeviceId, std::string>>& targets) {
        auto now = std::chrono::system_clock::now();
        auto bucket = MessageBucket::from_time_point(now);
        auto msg_id =
            MessageId::from_string("018f1234-5678-7000-8000-00000000090" + std::to_string(seq)).value();

        MessageEntity entity;
        entity.conversation_id = conv_id_;
        entity.message_bucket = bucket;
        entity.message_sequence = seq;
        entity.message_id = msg_id;
        entity.sender_user_id = bob_user_;
        entity.sender_device_id = bob_sender_dev_;
        entity.priority = MessagePriority::Normal;
        entity.accepted_at = now;
        entity.envelope.ciphertext = targets.empty() ? "" : targets.front().second;
        entity.envelope.envelope_version = 1;
        message_repo_->save_message(entity);

        std::vector<DeviceDeliveryRecord> records;
        std::vector<RecipientDeliveryState> states;
        for (const auto& [dev_id, ciphertext] : targets) {
            DeviceDeliveryRecord rec;
            rec.device_id = dev_id;
            rec.delivery_bucket = bucket.value();
            rec.accepted_at = now;
            rec.message_id = msg_id;
            rec.conversation_id = conv_id_;
            rec.message_sequence = seq;
            rec.message_priority = MessagePriority::Normal;
            rec.delivery_state = DeliveryState::Queued;
            rec.ciphertext_blob = ciphertext;
            rec.ephemeral_public_key = std::vector<uint8_t>(32, static_cast<uint8_t>(seq));
            rec.iv = std::vector<uint8_t>(12, static_cast<uint8_t>(seq + 10));
            rec.auth_tag = std::vector<uint8_t>(16, static_cast<uint8_t>(seq + 20));
            rec.algorithm = E2EAlgorithm::XChaCha20_Poly1305;
            rec.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
            records.push_back(rec);

            RecipientDeliveryState st;
            st.message_id = msg_id;
            st.recipient_device_id = dev_id;
            st.recipient_user_id = alice_user_;
            st.delivery_state = DeliveryState::Queued;
            states.push_back(st);
        }
        delivery_repo_->save_pending_deliveries(records);
        delivery_repo_->save_recipient_delivery_states(states);
        return msg_id;
    }

    static void add_caller_metadata(grpc::ClientContext& ctx, const UserId& user, const DeviceId& device) {
        ctx.AddMetadata("x-user-id", user.str());
        ctx.AddMetadata("x-device-id", device.str());
        ctx.AddMetadata("x-correlation-id", "corr-msg-011-t04");
    }

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> member_repo_;
    std::shared_ptr<InMemoryMessageRepo> message_repo_;
    std::shared_ptr<InMemorySyncCursorRepo> cursor_repo_;
    std::shared_ptr<InMemoryMultiDeviceDeliveryRepo> delivery_repo_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<SyncCursorManager> cursor_manager_;
    std::shared_ptr<MessageSyncService> sync_service_;
    std::unique_ptr<MessagingServiceImpl> messaging_service_;
    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::MessagingService::Stub> stub_;

    ConversationId conv_id_;
    UserId alice_user_;
    UserId bob_user_;
    DeviceId bob_sender_dev_;
    DeviceId alice_dev_1_;
    DeviceId alice_dev_2_;
};

// ============================================================================
// Tests (MSG-011-T04)
// ============================================================================

TEST_F(NewDeviceSyncBoundaryTest, PreEnrollmentMessagesOmitPayloadWhilePostEnrollmentMessagesIncludeDeviceEnvelope) {
    // 1. Messages M1 and M2 are sent when Alice only has alice_dev_1_ enrolled
    auto m1_id = seed_message_with_targets(1, {{alice_dev_1_, "CIPHERTEXT_M1_FOR_A1"}});
    auto m2_id = seed_message_with_targets(2, {{alice_dev_1_, "CIPHERTEXT_M2_FOR_A1"}});

    // 2. Alice enrolls alice_dev_2_. Message M3 is sent to both alice_dev_1_ and alice_dev_2_
    auto m3_id = seed_message_with_targets(
        3, {{alice_dev_1_, "CIPHERTEXT_M3_FOR_A1"}, {alice_dev_2_, "CIPHERTEXT_M3_FOR_A2"}});

    // 3. Newly enrolled alice_dev_2_ calls SyncDeviceMessages from sequence 0
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_2_);

        v1::SyncDeviceMessagesRequest req;
        req.set_device_id(alice_dev_2_.str());
        req.set_conversation_id(conv_id_.to_string());
        req.set_since_sequence(0);
        req.set_max_messages(10);

        v1::SyncDeviceMessagesResponse resp;
        auto status = stub_->SyncDeviceMessages(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << status.error_message();
        ASSERT_EQ(resp.messages_size(), 3);

        // M1 and M2: Pre-enrollment history -> Metadata present, zero delivery targets, zero A1 ciphertext leakage
        const auto& env1 = resp.messages(0);
        EXPECT_EQ(env1.message_id(), m1_id.to_string());
        EXPECT_EQ(env1.sender_user_id(), bob_user_.str());
        EXPECT_EQ(env1.delivery_targets_size(), 0)
            << "Pre-enrollment message M1 must not synthesize or leak companion device envelopes";

        const auto& env2 = resp.messages(1);
        EXPECT_EQ(env2.message_id(), m2_id.to_string());
        EXPECT_EQ(env2.delivery_targets_size(), 0)
            << "Pre-enrollment message M2 must not synthesize or leak companion device envelopes";

        // M3: Post-enrollment message -> Exact envelope targeted to alice_dev_2_
        const auto& env3 = resp.messages(2);
        EXPECT_EQ(env3.message_id(), m3_id.to_string());
        ASSERT_EQ(env3.delivery_targets_size(), 1);
        const auto& target3 = env3.delivery_targets(0);
        EXPECT_EQ(target3.recipient_device_id(), alice_dev_2_.str());
        EXPECT_EQ(target3.state(), v1::DELIVERY_STATE_QUEUED);
        EXPECT_EQ(target3.encrypted_payload().ciphertext_blob(), "CIPHERTEXT_M3_FOR_A2");
        EXPECT_EQ(target3.encrypted_payload().algorithm(), "XChaCha20-Poly1305");
        EXPECT_EQ(target3.encrypted_payload().ephemeral_public_key().size(), 32u);
        EXPECT_EQ(target3.encrypted_payload().initialization_vector().size(), 12u);
        EXPECT_EQ(target3.encrypted_payload().auth_tag().size(), 16u);
    }

    // 4. Existing alice_dev_1_ calls SyncDeviceMessages from sequence 0 -> Receives full envelopes for M1, M2, and M3
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_1_);

        v1::SyncDeviceMessagesRequest req;
        req.set_device_id(alice_dev_1_.str());
        req.set_conversation_id(conv_id_.to_string());
        req.set_since_sequence(0);
        req.set_max_messages(10);

        v1::SyncDeviceMessagesResponse resp;
        auto status = stub_->SyncDeviceMessages(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << status.error_message();
        ASSERT_EQ(resp.messages_size(), 3);

        ASSERT_EQ(resp.messages(0).delivery_targets_size(), 1);
        EXPECT_EQ(resp.messages(0).delivery_targets(0).recipient_device_id(), alice_dev_1_.str());
        EXPECT_EQ(resp.messages(0).delivery_targets(0).encrypted_payload().ciphertext_blob(), "CIPHERTEXT_M1_FOR_A1");

        ASSERT_EQ(resp.messages(1).delivery_targets_size(), 1);
        EXPECT_EQ(resp.messages(1).delivery_targets(0).recipient_device_id(), alice_dev_1_.str());
        EXPECT_EQ(resp.messages(1).delivery_targets(0).encrypted_payload().ciphertext_blob(), "CIPHERTEXT_M2_FOR_A1");

        ASSERT_EQ(resp.messages(2).delivery_targets_size(), 1);
        EXPECT_EQ(resp.messages(2).delivery_targets(0).recipient_device_id(), alice_dev_1_.str());
        EXPECT_EQ(resp.messages(2).delivery_targets(0).encrypted_payload().ciphertext_blob(), "CIPHERTEXT_M3_FOR_A1");
    }
}

TEST_F(NewDeviceSyncBoundaryTest, GetMessagesPopulatesGenuinePerDeviceEnvelopeAndRespectsPreEnrollmentBoundary) {
    seed_message_with_targets(1, {{alice_dev_1_, "CIPHERTEXT_M1_FOR_A1"}});
    seed_message_with_targets(
        2, {{alice_dev_1_, "CIPHERTEXT_M2_FOR_A1"}, {alice_dev_2_, "CIPHERTEXT_M2_FOR_A2"}});

    // GetMessages as alice_dev_2_
    grpc::ClientContext ctx;
    add_caller_metadata(ctx, alice_user_, alice_dev_2_);

    v1::GetMessagesRequest req;
    req.set_conversation_id(conv_id_.to_string());
    req.set_recipient_device_id(alice_dev_2_.str());
    req.set_since_sequence(0);
    req.set_max_results(10);

    v1::GetMessagesResponse resp;
    auto status = stub_->GetMessages(&ctx, req, &resp);
    ASSERT_TRUE(status.ok()) << status.error_message();
    ASSERT_EQ(resp.messages_size(), 2);

    // M1 has no target for alice_dev_2_
    EXPECT_EQ(resp.messages(0).delivery_targets_size(), 0);

    // M2 has genuine target for alice_dev_2_
    ASSERT_EQ(resp.messages(1).delivery_targets_size(), 1);
    EXPECT_EQ(resp.messages(1).delivery_targets(0).recipient_device_id(), alice_dev_2_.str());
    EXPECT_EQ(resp.messages(1).delivery_targets(0).encrypted_payload().ciphertext_blob(), "CIPHERTEXT_M2_FOR_A2");
}

TEST_F(NewDeviceSyncBoundaryTest, CompanionDevicesMaintainIndependentSyncWatermarks) {
    seed_message_with_targets(
        1, {{alice_dev_1_, "CT_1_A1"}, {alice_dev_2_, "CT_1_A2"}});
    seed_message_with_targets(
        2, {{alice_dev_1_, "CT_2_A1"}, {alice_dev_2_, "CT_2_A2"}});
    seed_message_with_targets(
        3, {{alice_dev_1_, "CT_3_A1"}, {alice_dev_2_, "CT_3_A2"}});

    // Advance alice_dev_1_ cursor to sequence 3
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_1_);
        v1::UpdateSyncCursorRequest req;
        req.mutable_cursor()->set_device_id(alice_dev_1_.str());
        req.mutable_cursor()->set_conversation_id(conv_id_.to_string());
        req.mutable_cursor()->set_last_delivered_sequence(3);
        v1::UpdateSyncCursorResponse resp;
        ASSERT_TRUE(stub_->UpdateSyncCursor(&ctx, req, &resp).ok());
    }

    // Advance alice_dev_2_ cursor to sequence 1
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_2_);
        v1::UpdateSyncCursorRequest req;
        req.mutable_cursor()->set_device_id(alice_dev_2_.str());
        req.mutable_cursor()->set_conversation_id(conv_id_.to_string());
        req.mutable_cursor()->set_last_delivered_sequence(1);
        v1::UpdateSyncCursorResponse resp;
        ASSERT_TRUE(stub_->UpdateSyncCursor(&ctx, req, &resp).ok());
    }

    // Verify alice_dev_2_ cursor was not overwritten by alice_dev_1_ and syncs M2, M3
    {
        grpc::ClientContext ctx;
        add_caller_metadata(ctx, alice_user_, alice_dev_2_);
        v1::SyncDeviceMessagesRequest req;
        req.set_device_id(alice_dev_2_.str());
        req.set_conversation_id(conv_id_.to_string());
        req.set_since_sequence(0); // Falls back to stored cursor (1)
        req.set_max_messages(10);

        v1::SyncDeviceMessagesResponse resp;
        ASSERT_TRUE(stub_->SyncDeviceMessages(&ctx, req, &resp).ok());
        ASSERT_EQ(resp.messages_size(), 2);
        EXPECT_EQ(resp.messages(0).delivery_targets(0).encrypted_payload().ciphertext_blob(), "CT_2_A2");
        EXPECT_EQ(resp.messages(1).delivery_targets(0).encrypted_payload().ciphertext_blob(), "CT_3_A2");
    }
}

TEST_F(NewDeviceSyncBoundaryTest, ScyllaDeliveryStateRepositoryFetchesDeviceRecordByDeviceAndMessage) {
    auto mock_session = std::make_shared<db::MockScyllaSession>();
    repository::ScyllaDeliveryStateRepository repo(mock_session);

    auto msg_id = MessageId::from_string("018f1234-5678-7000-8000-000000000999").value();
    std::string ct = "SCYLLA_CIPHERTEXT_A2";
    std::vector<uint8_t> ct_vec(ct.begin(), ct.end());
    std::vector<uint8_t> epk_vec(32, 0xAA);
    std::vector<uint8_t> iv_vec(12, 0xBB);
    std::vector<uint8_t> tag_vec(16, 0xCC);

    db::ScyllaRow row(
        {"device_id", "delivery_bucket", "accepted_at", "message_id", "conversation_id", "message_sequence",
         "message_priority", "delivery_state", "attempt_count", "next_retry_at", "ciphertext_blob",
         "ephemeral_public_key", "iv", "auth_tag", "algorithm", "protocol_version", "one_time_prekey_id"},
        {db::ScyllaValue(alice_dev_2_.str()), db::ScyllaValue("2026-10"), db::ScyllaValue(1700000000000LL),
         db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(conv_id_.to_string()),
         db::ScyllaValue(static_cast<int64_t>(42)), db::ScyllaValue("NORMAL"), db::ScyllaValue("QUEUED"),
         db::ScyllaValue(0), db::ScyllaValue(), db::ScyllaValue(ct_vec), db::ScyllaValue(epk_vec),
         db::ScyllaValue(iv_vec), db::ScyllaValue(tag_vec), db::ScyllaValue("XChaCha20-Poly1305"),
         db::ScyllaValue(1), db::ScyllaValue()});

    mock_session->set_prepared_result(db::PreparedStatementId("deliv_repo_get_device_record"),
                                      db::ScyllaQueryResult({row}));

    auto rec = repo.get_delivery_record_for_device(alice_dev_2_, msg_id);
    ASSERT_TRUE(rec.has_value());
    EXPECT_EQ(rec->device_id, alice_dev_2_);
    EXPECT_EQ(rec->message_id, msg_id);
    EXPECT_EQ(rec->ciphertext_blob, "SCYLLA_CIPHERTEXT_A2");
    EXPECT_EQ(rec->ephemeral_public_key.size(), 32u);
    EXPECT_EQ(rec->iv.size(), 12u);
    EXPECT_EQ(rec->auth_tag.size(), 16u);
}

} // namespace
} // namespace securecloud::messaging::service
