#include "messaging/domain/conversation_types.hpp"
#include "messaging/domain/message_bucket.hpp"
#include "messaging/domain/message_entity.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/service/conversation_authorization_service.hpp"
#include "messaging/service/message_sync_service.hpp"
#include "messaging/service/sync_cursor_manager.hpp"

#include <algorithm>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <vector>

namespace securecloud::messaging::service::test {
namespace {

using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeviceId;
using domain::DeviceSyncCursor;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::ParticipantRole;
using domain::UserId;

/// In-memory mock for ISyncCursorRepository
class MockSyncCursorRepo : public repository::ISyncCursorRepository {
  public:
    std::optional<DeviceSyncCursor> get_sync_cursor(const DeviceId& device_id,
                                                    const ConversationId& conversation_id) override {
        auto key = std::make_pair(device_id.str(), conversation_id.to_string());
        auto it = store_.find(key);
        if (it != store_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::vector<DeviceSyncCursor> list_sync_cursors_by_device(const DeviceId& device_id) override {
        std::vector<DeviceSyncCursor> results;
        for (const auto& [key, cursor] : store_) {
            if (key.first == device_id.str()) {
                results.push_back(cursor);
            }
        }
        return results;
    }

    void upsert_sync_cursor(const DeviceSyncCursor& cursor) override {
        auto key = std::make_pair(cursor.device_id.str(), cursor.conversation_id.to_string());
        store_[key] = cursor;
    }

  private:
    std::map<std::pair<std::string, std::string>, DeviceSyncCursor> store_;
};

/// In-memory mock for IMessageRepository supporting chronological range queries
class MockMessageRepo : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override {
        messages_[msg.conversation_id.to_string()].push_back(msg);
        auto& msgs = messages_[msg.conversation_id.to_string()];
        std::sort(msgs.begin(), msgs.end(), [](const MessageEntity& a, const MessageEntity& b) {
            return a.message_sequence < b.message_sequence;
        });
    }

    std::optional<MessageEntity> find_by_id(const ConversationId& conv, const MessageBucket& bucket,
                                            const MessageId& id) override {
        (void)bucket;
        auto it = messages_.find(conv.to_string());
        if (it == messages_.end()) {
            return std::nullopt;
        }
        for (const auto& msg : it->second) {
            if (msg.message_id == id) {
                return msg;
            }
        }
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId& conv, const MessageBucket& bucket,
                                                               uint64_t from, uint64_t to, size_t limit) override {
        (void)bucket;
        std::vector<MessageEntity> results;
        auto it = messages_.find(conv.to_string());
        if (it == messages_.end()) {
            return results;
        }

        for (const auto& msg : it->second) {
            if (msg.message_sequence >= from && msg.message_sequence <= to) {
                results.push_back(msg);
                if (results.size() >= limit) {
                    break;
                }
            }
        }
        return results;
    }

    uint64_t get_last_sequence(const ConversationId& conversation_id, const MessageBucket& message_bucket) override {
        (void)message_bucket;
        auto it = messages_.find(conversation_id.to_string());
        if (it == messages_.end() || it->second.empty()) {
            return 0;
        }
        return it->second.back().message_sequence;
    }

  private:
    std::map<std::string, std::vector<MessageEntity>> messages_;
};

domain::MessageEntity create_test_message(const ConversationId& conv_id, uint64_t seq, const UserId& sender_user,
                                          const DeviceId& sender_dev) {
    domain::MessageEntity entity;
    entity.conversation_id = conv_id;
    entity.message_bucket = domain::MessageBucket::from_time_point(std::chrono::system_clock::now());
    entity.message_sequence = seq;
    entity.message_id = domain::MessageId::generate_v7();
    entity.sender_user_id = sender_user;
    entity.sender_device_id = sender_dev;
    entity.accepted_at = std::chrono::system_clock::now();
    return entity;
}

class MessageSyncServiceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        cursor_repo_ = std::make_shared<MockSyncCursorRepo>();
        message_repo_ = std::make_shared<MockMessageRepo>();
        cursor_manager_ = std::make_unique<SyncCursorManager>(cursor_repo_, message_repo_);

        conv_repo_ = std::make_unique<repository::InMemoryConversationRepository>();
        member_repo_ = std::make_unique<repository::InMemoryMembershipRepository>();
        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *member_repo_);

        sync_service_ = std::make_unique<MessageSyncService>(
            message_repo_, std::shared_ptr<SyncCursorManager>(cursor_manager_.get(), [](auto*) {}), auth_service_);

        alice_ = UserId("018e3a2b-4c5d-7e8f-9012-3456789abc01");
        bob_ = UserId("018e3a2b-4c5d-7e8f-9012-3456789abc02");
        eve_ = UserId("018e3a2b-4c5d-7e8f-9012-3456789abc03");

        alice_device_ = DeviceId("alice-device-1");
        conv_id_ = ConversationId::generate_v7();

        // Register conversation and membership for Alice and Bob
        ConversationEntity conv;
        conv.conversation_id = conv_id_;
        conv.type = ConversationType::Direct;
        conv_repo_->save_conversation(conv);

        ConversationParticipantEntity p_alice;
        p_alice.conversation_id = conv_id_;
        p_alice.user_id = alice_;
        p_alice.status = MembershipStatus::Active;
        p_alice.role = ParticipantRole::Member;
        member_repo_->add_participant(p_alice);

        ConversationParticipantEntity p_bob;
        p_bob.conversation_id = conv_id_;
        p_bob.user_id = bob_;
        p_bob.status = MembershipStatus::Active;
        p_bob.role = ParticipantRole::Member;
        member_repo_->add_participant(p_bob);
    }

    std::shared_ptr<MockSyncCursorRepo> cursor_repo_;
    std::shared_ptr<MockMessageRepo> message_repo_;
    std::unique_ptr<SyncCursorManager> cursor_manager_;

    std::unique_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::unique_ptr<repository::InMemoryMembershipRepository> member_repo_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;

    std::unique_ptr<MessageSyncService> sync_service_;

    UserId alice_;
    UserId bob_;
    UserId eve_;
    DeviceId alice_device_;
    ConversationId conv_id_;
};

TEST_F(MessageSyncServiceTest, ConstructorRejectsNullDependencies) {
    EXPECT_THROW(MessageSyncService(nullptr, std::shared_ptr<SyncCursorManager>(cursor_manager_.get(), [](auto*) {})),
                 std::invalid_argument);
    EXPECT_THROW(MessageSyncService(message_repo_, nullptr), std::invalid_argument);
}

TEST_F(MessageSyncServiceTest, ActiveParticipantSyncsMessagesSuccessfully) {
    // Populate 5 messages
    for (uint64_t i = 1; i <= 5; ++i) {
        message_repo_->save_message(create_test_message(conv_id_, i, bob_, DeviceId("bob-dev-1")));
    }

    SyncDeviceMessagesCommand cmd{
        .device_id = alice_device_, .conversation_id = conv_id_, .since_sequence = 0, .max_messages = 10};

    auto result = sync_service_->sync_messages(alice_, cmd);

    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.status, SyncMessagesStatus::Success);
    ASSERT_EQ(result.messages.size(), 5U);
    EXPECT_EQ(result.messages[0].message_sequence, 1U);
    EXPECT_EQ(result.messages[4].message_sequence, 5U);
    EXPECT_FALSE(result.has_more);
    EXPECT_EQ(result.latest_sequence, 5U);
    EXPECT_EQ(result.next_sequence, 6U);
}

TEST_F(MessageSyncServiceTest, NonParticipantSyncAttemptRejected) {
    SyncDeviceMessagesCommand cmd{
        .device_id = DeviceId("eve-device-1"), .conversation_id = conv_id_, .since_sequence = 0, .max_messages = 50};

    auto result = sync_service_->sync_messages(eve_, cmd);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, SyncMessagesStatus::NotAuthorized);
    EXPECT_TRUE(result.messages.empty());
}

TEST_F(MessageSyncServiceTest, ConversationNotFoundRejected) {
    auto unknown_conv = ConversationId::generate_v7();
    SyncDeviceMessagesCommand cmd{
        .device_id = alice_device_, .conversation_id = unknown_conv, .since_sequence = 0, .max_messages = 50};

    auto result = sync_service_->sync_messages(alice_, cmd);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, SyncMessagesStatus::ConversationNotFound);
}

TEST_F(MessageSyncServiceTest, PaginationBoundariesAndHasMore) {
    // Populate 10 messages (sequences 1 to 10)
    for (uint64_t i = 1; i <= 10; ++i) {
        message_repo_->save_message(create_test_message(conv_id_, i, bob_, DeviceId("bob-dev-1")));
    }

    // Batch 1: fetch 3 messages starting from sequence 0
    SyncDeviceMessagesCommand cmd1{
        .device_id = alice_device_, .conversation_id = conv_id_, .since_sequence = 0, .max_messages = 3};
    auto r1 = sync_service_->sync_messages(alice_, cmd1);
    ASSERT_TRUE(r1.is_success());
    ASSERT_EQ(r1.messages.size(), 3U);
    EXPECT_EQ(r1.messages[0].message_sequence, 1U);
    EXPECT_EQ(r1.messages[2].message_sequence, 3U);
    EXPECT_TRUE(r1.has_more);
    EXPECT_EQ(r1.next_sequence, 4U);
    EXPECT_EQ(r1.latest_sequence, 10U);

    // Batch 2: fetch 5 messages starting from sequence 3
    SyncDeviceMessagesCommand cmd2{
        .device_id = alice_device_, .conversation_id = conv_id_, .since_sequence = 3, .max_messages = 5};
    auto r2 = sync_service_->sync_messages(alice_, cmd2);
    ASSERT_TRUE(r2.is_success());
    ASSERT_EQ(r2.messages.size(), 5U);
    EXPECT_EQ(r2.messages[0].message_sequence, 4U);
    EXPECT_EQ(r2.messages[4].message_sequence, 8U);
    EXPECT_TRUE(r2.has_more);
    EXPECT_EQ(r2.next_sequence, 9U);

    // Batch 3: fetch remaining starting from sequence 8
    SyncDeviceMessagesCommand cmd3{
        .device_id = alice_device_, .conversation_id = conv_id_, .since_sequence = 8, .max_messages = 5};
    auto r3 = sync_service_->sync_messages(alice_, cmd3);
    ASSERT_TRUE(r3.is_success());
    ASSERT_EQ(r3.messages.size(), 2U);
    EXPECT_EQ(r3.messages[0].message_sequence, 9U);
    EXPECT_EQ(r3.messages[1].message_sequence, 10U);
    EXPECT_FALSE(r3.has_more);
    EXPECT_EQ(r3.next_sequence, 11U);
}

TEST_F(MessageSyncServiceTest, BatchClampingEnforced) {
    // Request with max_messages = 0 defaults to 50
    // Request with max_messages = 10000 clamps to 500
    EXPECT_EQ(clamp_sync_batch_size(0), 50U);
    EXPECT_EQ(clamp_sync_batch_size(10000), 500U);
}

TEST_F(MessageSyncServiceTest, CursorOutOfBoundsRejected) {
    for (uint64_t i = 1; i <= 10; ++i) {
        message_repo_->save_message(create_test_message(conv_id_, i, bob_, DeviceId("bob-dev-1")));
    }

    SyncDeviceMessagesCommand cmd{.device_id = alice_device_,
                                  .conversation_id = conv_id_,
                                  .since_sequence = 25, // Ceiling is 10
                                  .max_messages = 10};

    auto result = sync_service_->sync_messages(alice_, cmd);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, SyncMessagesStatus::CursorOutOfBounds);
}

TEST_F(MessageSyncServiceTest, EmptyConversationReturnsGracefully) {
    SyncDeviceMessagesCommand cmd{
        .device_id = alice_device_, .conversation_id = conv_id_, .since_sequence = 0, .max_messages = 10};

    auto result = sync_service_->sync_messages(alice_, cmd);

    ASSERT_TRUE(result.is_success());
    EXPECT_TRUE(result.messages.empty());
    EXPECT_FALSE(result.has_more);
    EXPECT_EQ(result.latest_sequence, 0U);
}

TEST_F(MessageSyncServiceTest, FallbackToStoredCursorWhenSinceSequenceIsZero) {
    // Populate 10 messages
    for (uint64_t i = 1; i <= 10; ++i) {
        message_repo_->save_message(create_test_message(conv_id_, i, bob_, DeviceId("bob-dev-1")));
    }

    // Advance stored cursor in repository to 6
    DeviceSyncCursor stored;
    stored.device_id = alice_device_;
    stored.conversation_id = conv_id_;
    stored.last_synced_sequence = 6;
    stored.sync_version = 2;
    stored.last_sync_at = std::chrono::system_clock::now();
    cursor_repo_->upsert_sync_cursor(stored);

    // Client requests with since_sequence = 0 (resume from persisted checkpoint)
    SyncDeviceMessagesCommand cmd{
        .device_id = alice_device_, .conversation_id = conv_id_, .since_sequence = 0, .max_messages = 10};

    auto result = sync_service_->sync_messages(alice_, cmd);

    ASSERT_TRUE(result.is_success());
    ASSERT_EQ(result.messages.size(), 4U); // 7, 8, 9, 10
    EXPECT_EQ(result.messages[0].message_sequence, 7U);
    EXPECT_EQ(result.messages[3].message_sequence, 10U);
    EXPECT_FALSE(result.has_more);
    EXPECT_EQ(result.next_sequence, 11U);
}

TEST_F(MessageSyncServiceTest, InvalidArgumentsRejected) {
    SyncDeviceMessagesCommand empty_dev{.device_id = DeviceId(""), .conversation_id = conv_id_};
    auto r1 = sync_service_->sync_messages(alice_, empty_dev);
    EXPECT_EQ(r1.status, SyncMessagesStatus::InvalidArguments);

    SyncDeviceMessagesCommand no_conv{.device_id = alice_device_, .conversation_id = std::nullopt};
    auto r2 = sync_service_->sync_messages(alice_, no_conv);
    EXPECT_EQ(r2.status, SyncMessagesStatus::InvalidArguments);
}

} // namespace
} // namespace securecloud::messaging::service::test
