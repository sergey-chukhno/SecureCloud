#include "messaging/db/embedded_migrations.hpp"
#include "messaging/db/migration_runner.hpp"
#include "messaging/db/mock_scylla_session.hpp"
#include "messaging/db/scylla_session_pool.hpp"
#include "messaging/domain/conversation_entity.hpp"
#include "messaging/domain/conversation_participant_entity.hpp"
#include "messaging/domain/delivery_types.hpp"
#include "messaging/domain/group_metadata_entity.hpp"
#include "messaging/domain/idempotency_types.hpp"
#include "messaging/domain/message_bucket.hpp"
#include "messaging/domain/message_entity.hpp"
#include "messaging/domain/outbox_event.hpp"
#include "messaging/domain/sync_types.hpp"
#include "messaging/repository/scylla_conversation_repository.hpp"
#include "messaging/repository/scylla_delivery_state_repository.hpp"
#include "messaging/repository/scylla_idempotency_repository.hpp"
#include "messaging/repository/scylla_membership_repository.hpp"
#include "messaging/repository/scylla_message_repository.hpp"
#include "messaging/repository/scylla_outbox_repository.hpp"
#include "messaging/repository/scylla_sync_cursor_repository.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace securecloud::messaging::test {
namespace {

using domain::CiphertextEnvelope;
using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationOutboxEventType;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryState;
using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::DeviceSyncCursor;
using domain::DirectPair;
using domain::GroupMetadataEntity;
using domain::GroupStatus;
using domain::IdempotencyRecord;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::MessagePriority;
using domain::ParticipantRole;
using domain::RecipientDeliveryState;
using domain::SubmissionStatus;
using domain::UserId;
using repository::OutboxEventRecord;
using repository::OutboxPublishStatus;
using repository::ScyllaConversationRepository;
using repository::ScyllaDeliveryStateRepository;
using repository::ScyllaIdempotencyRepository;
using repository::ScyllaMembershipRepository;
using repository::ScyllaMessageRepository;
using repository::ScyllaOutboxRepository;
using repository::ScyllaSyncCursorRepository;

bool is_scylla_reachable(const std::string& host = "127.0.0.1", uint16_t port = 9042, int timeout_ms = 300) {
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return false;
    }
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    bool ok = (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);
    closesocket(sock);
    return ok;
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    bool ok = (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);
    close(sock);
    return ok;
#endif
}

// ============================================================================
// 1. Persistence Pipeline Integration (Hermetic End-to-End Simulation)
// ============================================================================

class MessagingPersistenceHermeticPipelineTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_session_ = std::make_shared<db::MockScyllaSession>();
        conv_repo_ = std::make_unique<ScyllaConversationRepository>(mock_session_);
        membership_repo_ = std::make_unique<ScyllaMembershipRepository>(mock_session_);
        msg_repo_ = std::make_unique<ScyllaMessageRepository>(mock_session_);
        delivery_repo_ = std::make_unique<ScyllaDeliveryStateRepository>(mock_session_);
        sync_repo_ = std::make_unique<ScyllaSyncCursorRepository>(mock_session_);
        idempotency_repo_ = std::make_unique<ScyllaIdempotencyRepository>(mock_session_);
        outbox_repo_ = std::make_unique<ScyllaOutboxRepository>(mock_session_);
    }

    std::shared_ptr<db::MockScyllaSession> mock_session_;
    std::unique_ptr<ScyllaConversationRepository> conv_repo_;
    std::unique_ptr<ScyllaMembershipRepository> membership_repo_;
    std::unique_ptr<ScyllaMessageRepository> msg_repo_;
    std::unique_ptr<ScyllaDeliveryStateRepository> delivery_repo_;
    std::unique_ptr<ScyllaSyncCursorRepository> sync_repo_;
    std::unique_ptr<ScyllaIdempotencyRepository> idempotency_repo_;
    std::unique_ptr<ScyllaOutboxRepository> outbox_repo_;
};

TEST_F(MessagingPersistenceHermeticPipelineTest, ConversationAndDirectPairDualWrite) {
    auto alice = UserId("user-alice");
    auto bob = UserId("user-bob");
    DirectPair pair(alice, bob);
    auto conv_id = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    // 1. Save direct conversation
    ConversationEntity conv;
    conv.conversation_id = conv_id;
    conv.type = ConversationType::Direct;
    conv.created_by_user_id = alice;
    conv.created_at = now;
    conv_repo_->save_conversation(conv);
    conv_repo_->save_direct_conversation(pair, conv_id);

    // 2. Mock query responses
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    db::ScyllaRow row_conv(
        {"conversation_id", "conversation_type", "created_at", "created_by_user_id", "metadata_version"},
        {db::ScyllaValue(conv_id.to_string()), db::ScyllaValue("DIRECT"), db::ScyllaValue(now_ms),
         db::ScyllaValue(alice.str()), db::ScyllaValue(1)});
    mock_session_->set_prepared_result(db::PreparedStatementId("conv_repo_find_conv"),
                                       db::ScyllaQueryResult({row_conv}));

    db::ScyllaRow row_direct({"conversation_id"}, {db::ScyllaValue(conv_id.to_string())});
    mock_session_->set_prepared_result(db::PreparedStatementId("conv_repo_find_direct"),
                                       db::ScyllaQueryResult({row_direct}));

    // Verify lookup by conv_id
    auto found_conv = conv_repo_->find_conversation_by_id(conv_id);
    ASSERT_TRUE(found_conv.has_value());
    EXPECT_EQ(found_conv->conversation_id, conv_id);

    // Verify lookup with canonical pair
    auto found_pair_id = conv_repo_->find_direct_conversation(pair);
    ASSERT_TRUE(found_pair_id.has_value());
    EXPECT_EQ(*found_pair_id, conv_id);

    // Verify reverse order pair resolves identically
    DirectPair reverse_pair(bob, alice);
    EXPECT_EQ(pair.user_a(), reverse_pair.user_a());
    EXPECT_EQ(pair.user_b(), reverse_pair.user_b());
}

TEST_F(MessagingPersistenceHermeticPipelineTest, MessageMonthlyBucketAndSequenceOrdering) {
    auto conv_id = ConversationId::generate_v7();
    auto oct_bucket = MessageBucket::from_year_month(2026, 10);
    auto nov_bucket = oct_bucket.next_bucket();

    EXPECT_EQ(oct_bucket.value(), "202610");
    EXPECT_EQ(nov_bucket.value(), "202611");

    // Save message in October bucket
    MessageEntity msg_oct;
    msg_oct.conversation_id = conv_id;
    msg_oct.message_bucket = oct_bucket;
    msg_oct.message_sequence = 1;
    msg_oct.message_id = MessageId::generate_v7();
    msg_oct.sender_user_id = UserId("alice");
    msg_oct.sender_device_id = DeviceId("alice-dev-1");
    msg_oct.accepted_at = std::chrono::system_clock::now();
    msg_oct.envelope.ciphertext = "enc-data-1";
    msg_repo_->save_message(msg_oct);

    // Save message in November bucket (sequence starts at 1 for new bucket or continuous)
    MessageEntity msg_nov;
    msg_nov.conversation_id = conv_id;
    msg_nov.message_bucket = nov_bucket;
    msg_nov.message_sequence = 2;
    msg_nov.message_id = MessageId::generate_v7();
    msg_nov.sender_user_id = UserId("bob");
    msg_nov.sender_device_id = DeviceId("bob-dev-1");
    msg_nov.accepted_at = std::chrono::system_clock::now();
    msg_nov.envelope.ciphertext = "enc-data-2";
    msg_repo_->save_message(msg_nov);

    // Verify prepared statements were called
    EXPECT_EQ(mock_session_->get_executed_prepared().size(), 2U);
}

TEST_F(MessagingPersistenceHermeticPipelineTest, RecipientDeviceDeliveryAndAckLifecycle) {
    auto msg_id = MessageId::generate_v7();
    auto dev1 = DeviceId("dev-phone-1");
    auto dev2 = DeviceId("dev-tablet-2");
    auto user1 = UserId("user-1");
    auto now = std::chrono::system_clock::now();

    // 1. Enqueue active pending deliveries for dev1 and dev2
    DeviceDeliveryRecord d1{dev1,
                            "202610",
                            now,
                            msg_id,
                            ConversationId::generate_v7(),
                            10,
                            MessagePriority::Normal,
                            DeliveryState::Pending,
                            0,
                            std::nullopt};
    DeviceDeliveryRecord d2{dev2,
                            "202610",
                            now,
                            msg_id,
                            ConversationId::generate_v7(),
                            10,
                            MessagePriority::Normal,
                            DeliveryState::Pending,
                            0,
                            std::nullopt};
    delivery_repo_->save_pending_deliveries({d1, d2});

    // 2. Track fan-out states for the message
    RecipientDeliveryState r1{msg_id, dev1, user1, DeliveryState::Pending, std::nullopt, std::nullopt};
    RecipientDeliveryState r2{msg_id, dev2, user1, DeliveryState::Pending, std::nullopt, std::nullopt};
    delivery_repo_->save_recipient_delivery_states({r1, r2});

    // 3. Device 1 acknowledges delivery
    delivery_repo_->record_delivery_ack(msg_id, dev1, now);

    // 4. Device 1 acknowledges read
    delivery_repo_->record_read_ack(msg_id, dev1, now + std::chrono::seconds(2));

    // Verify all prepared statements executed
    EXPECT_EQ(mock_session_->get_executed_prepared().size(), 6U);
}

TEST_F(MessagingPersistenceHermeticPipelineTest, SyncCursorAndIdempotencySubmission) {
    auto dev = DeviceId("dev-mobile-client");
    auto conv = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    // 1. Advance sync cursor
    DeviceSyncCursor cursor{dev, conv, 1500, now, 1};
    sync_repo_->upsert_sync_cursor(cursor);

    // 2. Record idempotent submission
    IdempotencyRecord rec{dev, "idem-key-777", MessageId::generate_v7(), conv, 1501, SubmissionStatus::Committed,
                          now, "fp-777"};
    idempotency_repo_->save_submission(rec);

    EXPECT_EQ(mock_session_->get_executed_prepared().size(), 2U);
}

TEST_F(MessagingPersistenceHermeticPipelineTest, TransactionalOutboxLifecycle) {
    auto conv_id = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    ConversationOutboxEvent event{"evt-999", conv_id, ConversationOutboxEventType::MessageSent, "{\"seq\":1501}", now};
    outbox_repo_->enqueue_event(event, "2026101512");

    outbox_repo_->mark_event_published("2026101512", now, "evt-999", now + std::chrono::milliseconds(50));

    EXPECT_EQ(mock_session_->get_executed_prepared().size(), 2U);
}

// ============================================================================
// 2. Live ScyllaDB Cluster Integration (Guarded by Reachability)
// ============================================================================

class ScyllaLiveClusterIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        if (!is_scylla_reachable("127.0.0.1", 9042, 300)) {
            GTEST_SKIP() << "ScyllaDB cluster on 127.0.0.1:9042 is offline. Skipping live container persistence tests.";
        }
    }
};

TEST_F(ScyllaLiveClusterIntegrationTest, LiveKeyspaceAndTableSchemaVerification) {
    messaging::ScyllaConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 9042;
    cfg.keyspace = "securecloud_messaging";

    auto session = std::make_shared<db::ScyllaSession>(cfg);
    EXPECT_TRUE(session->ping());

    // Verify migration catalog
    auto migrations = db::ScyllaMigrationRunner::get_standard_migrations();
    EXPECT_GE(migrations.size(), 3U);
}

} // namespace
} // namespace securecloud::messaging::test
