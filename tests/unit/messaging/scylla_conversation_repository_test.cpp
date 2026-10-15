#include "messaging/db/mock_scylla_session.hpp"
#include "messaging/domain/conversation_entity.hpp"
#include "messaging/domain/conversation_participant_entity.hpp"
#include "messaging/domain/group_metadata_entity.hpp"
#include "messaging/repository/scylla_conversation_repository.hpp"
#include "messaging/repository/scylla_membership_repository.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::repository::test {
namespace {

using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DirectPair;
using domain::GroupMetadataEntity;
using domain::GroupStatus;
using domain::MembershipStatus;
using domain::ParticipantRole;
using domain::UserId;

// ============================================================================
// 1. ScyllaConversationRepository Tests
// ============================================================================

TEST(ScyllaConversationRepositoryTest, RejectsNullSessionInConstructor) {
    EXPECT_THROW(ScyllaConversationRepository(nullptr), std::invalid_argument);
}

TEST(ScyllaConversationRepositoryTest, SaveAndFindConversationById) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaConversationRepository repo(mock);

    auto conv_id = ConversationId::generate_v7();
    auto user_id = UserId("user-alice-123");
    auto now = std::chrono::system_clock::now();

    ConversationEntity conv;
    conv.conversation_id = conv_id;
    conv.type = ConversationType::Direct;
    conv.created_by_user_id = user_id;
    conv.created_at = now;
    conv.metadata_version = 2;

    // Save conversation
    repo.save_conversation(conv);
    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "conv_repo_save_conv");

    // Configure mock query response for find
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    db::ScyllaRow row({"conversation_id", "conversation_type", "created_at", "created_by_user_id", "metadata_version"},
                      {db::ScyllaValue(conv_id.to_string()), db::ScyllaValue("DIRECT"), db::ScyllaValue(now_ms),
                       db::ScyllaValue(user_id.str()), db::ScyllaValue(2)});
    mock->set_prepared_result(db::PreparedStatementId("conv_repo_find_conv"), db::ScyllaQueryResult({row}));

    auto found = repo.find_conversation_by_id(conv_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->conversation_id, conv_id);
    EXPECT_EQ(found->type, ConversationType::Direct);
    EXPECT_EQ(found->created_by_user_id, user_id);
    EXPECT_EQ(found->metadata_version, 2U);

    // Test not found returns nullopt
    mock->set_prepared_result(db::PreparedStatementId("conv_repo_find_conv"), db::ScyllaQueryResult{});
    auto not_found = repo.find_conversation_by_id(ConversationId::generate_v7());
    EXPECT_FALSE(not_found.has_value());
}

TEST(ScyllaConversationRepositoryTest, DirectPairSaveAndFind) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaConversationRepository repo(mock);

    DirectPair pair(UserId("alice"), UserId("bob"));
    auto conv_id = ConversationId::generate_v7();

    repo.save_direct_conversation(pair, conv_id);
    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "conv_repo_save_direct");

    // Configure mock response for direct pair query
    db::ScyllaRow row({"conversation_id"}, {db::ScyllaValue(conv_id.to_string())});
    mock->set_prepared_result(db::PreparedStatementId("conv_repo_find_direct"), db::ScyllaQueryResult({row}));

    auto found = repo.find_direct_conversation(pair);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found.value(), conv_id);

    // Direct pair inverted user order resolves canonically
    DirectPair inverted_pair(UserId("bob"), UserId("alice"));
    auto found_inverted = repo.find_direct_conversation(inverted_pair);
    ASSERT_TRUE(found_inverted.has_value());
    EXPECT_EQ(found_inverted.value(), conv_id);
}

TEST(ScyllaConversationRepositoryTest, GroupMetadataSaveAndFind) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaConversationRepository repo(mock);

    auto conv_id = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    GroupMetadataEntity meta;
    meta.conversation_id = conv_id;
    meta.title = "Security Engineering Guild";
    meta.status = GroupStatus::Active;
    meta.created_at = now;
    meta.updated_at = now;
    meta.metadata_version = 1;

    repo.save_group_metadata(meta);
    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "conv_repo_save_group_meta");

    // Configure mock find result
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    db::ScyllaRow row({"conversation_id", "group_name", "group_status", "created_by_user_id", "created_at",
                       "updated_at", "metadata_version"},
                      {db::ScyllaValue(conv_id.to_string()), db::ScyllaValue("Security Engineering Guild"),
                       db::ScyllaValue("ACTIVE"), db::ScyllaValue("user-1"), db::ScyllaValue(now_ms),
                       db::ScyllaValue(now_ms), db::ScyllaValue(1)});
    mock->set_prepared_result(db::PreparedStatementId("conv_repo_find_group_meta"), db::ScyllaQueryResult({row}));

    auto found = repo.find_group_metadata(conv_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->conversation_id, conv_id);
    EXPECT_EQ(found->title, "Security Engineering Guild");
    EXPECT_EQ(found->status, GroupStatus::Active);
    EXPECT_EQ(found->metadata_version, 1U);
}

// ============================================================================
// 2. ScyllaMembershipRepository Tests
// ============================================================================

TEST(ScyllaMembershipRepositoryTest, RejectsNullSessionInConstructor) {
    EXPECT_THROW(ScyllaMembershipRepository(nullptr), std::invalid_argument);
}

TEST(ScyllaMembershipRepositoryTest, AddUpdateAndFindParticipant) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaMembershipRepository repo(mock);

    auto conv_id = ConversationId::generate_v7();
    auto user_id = UserId("user-bob");
    auto joined_time = std::chrono::system_clock::now();

    ConversationParticipantEntity p;
    p.conversation_id = conv_id;
    p.user_id = user_id;
    p.role = ParticipantRole::Member;
    p.status = MembershipStatus::Active;
    p.joined_at = joined_time;
    p.membership_version = 1;

    repo.add_participant(p);
    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "member_repo_save_member");

    // Configure mock find result
    int64_t joined_ms = std::chrono::duration_cast<std::chrono::milliseconds>(joined_time.time_since_epoch()).count();
    db::ScyllaRow row(
        {"conversation_id", "user_id", "membership_status", "role", "joined_at", "left_at", "membership_version"},
        {db::ScyllaValue(conv_id.to_string()), db::ScyllaValue(user_id.str()), db::ScyllaValue("ACTIVE"),
         db::ScyllaValue("MEMBER"), db::ScyllaValue(joined_ms), db::ScyllaValue::null(), db::ScyllaValue(1)});
    mock->set_prepared_result(db::PreparedStatementId("member_repo_find_member"), db::ScyllaQueryResult({row}));

    auto found = repo.find_participant(conv_id, user_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->conversation_id, conv_id);
    EXPECT_EQ(found->user_id, user_id);
    EXPECT_EQ(found->role, ParticipantRole::Member);
    EXPECT_EQ(found->status, MembershipStatus::Active);
    EXPECT_FALSE(found->left_at.has_value());

    // Update participant to LEFT
    p.status = MembershipStatus::Left;
    p.left_at = std::chrono::system_clock::now();
    p.membership_version = 2;
    repo.update_participant(p);
    EXPECT_EQ(mock->get_executed_prepared().size(), 3U);
}

TEST(ScyllaMembershipRepositoryTest, ListParticipantsAndFilterActive) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaMembershipRepository repo(mock);

    auto conv_id = ConversationId::generate_v7();
    int64_t now_ms = 1700000000000LL;

    db::ScyllaRow r1(
        {"conversation_id", "user_id", "membership_status", "role", "joined_at", "left_at", "membership_version"},
        {db::ScyllaValue(conv_id.to_string()), db::ScyllaValue("user-1"), db::ScyllaValue("ACTIVE"),
         db::ScyllaValue("ADMIN"), db::ScyllaValue(now_ms), db::ScyllaValue::null(), db::ScyllaValue(1)});
    db::ScyllaRow r2(
        {"conversation_id", "user_id", "membership_status", "role", "joined_at", "left_at", "membership_version"},
        {db::ScyllaValue(conv_id.to_string()), db::ScyllaValue("user-2"), db::ScyllaValue("LEFT"),
         db::ScyllaValue("MEMBER"), db::ScyllaValue(now_ms), db::ScyllaValue(now_ms + 1000), db::ScyllaValue(2)});
    db::ScyllaRow r3(
        {"conversation_id", "user_id", "membership_status", "role", "joined_at", "left_at", "membership_version"},
        {db::ScyllaValue(conv_id.to_string()), db::ScyllaValue("user-3"), db::ScyllaValue("ACTIVE"),
         db::ScyllaValue("MEMBER"), db::ScyllaValue(now_ms), db::ScyllaValue::null(), db::ScyllaValue(1)});

    mock->set_prepared_result(db::PreparedStatementId("member_repo_list_members"), db::ScyllaQueryResult({r1, r2, r3}));

    auto all = repo.list_participants(conv_id);
    EXPECT_EQ(all.size(), 3U);

    auto active = repo.list_active_participants(conv_id);
    EXPECT_EQ(active.size(), 2U);
    EXPECT_EQ(active[0].user_id.str(), "user-1");
    EXPECT_EQ(active[1].user_id.str(), "user-3");
}

TEST(ScyllaMembershipRepositoryTest, TouchAndListUserConversationsWithPagination) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaMembershipRepository repo(mock);

    UserId user("user-charlie");
    auto conv1 = ConversationId::generate_v7();
    auto conv2 = ConversationId::generate_v7();
    auto conv3 = ConversationId::generate_v7();

    auto t1 = std::chrono::system_clock::now();
    auto t2 = t1 + std::chrono::seconds(10);
    auto t3 = t1 + std::chrono::seconds(20);

    repo.touch_user_conversation(user, conv1, ConversationType::Direct, MembershipStatus::Active, t1);
    EXPECT_EQ(mock->get_executed_prepared().size(), 1U);
    EXPECT_EQ(mock->get_executed_prepared()[0].first.value(), "member_repo_touch_user_conv");

    // Configure mock rows for list
    int64_t ms1 = std::chrono::duration_cast<std::chrono::milliseconds>(t1.time_since_epoch()).count();
    int64_t ms2 = std::chrono::duration_cast<std::chrono::milliseconds>(t2.time_since_epoch()).count();
    int64_t ms3 = std::chrono::duration_cast<std::chrono::milliseconds>(t3.time_since_epoch()).count();

    db::ScyllaRow r1({"conversation_id", "conversation_type", "membership_status", "last_activity_at"},
                     {db::ScyllaValue(conv1.to_string()), db::ScyllaValue("DIRECT"), db::ScyllaValue("ACTIVE"),
                      db::ScyllaValue(ms1)});
    db::ScyllaRow r2({"conversation_id", "conversation_type", "membership_status", "last_activity_at"},
                     {db::ScyllaValue(conv2.to_string()), db::ScyllaValue("GROUP"), db::ScyllaValue("ACTIVE"),
                      db::ScyllaValue(ms2)});
    db::ScyllaRow r3({"conversation_id", "conversation_type", "membership_status", "last_activity_at"},
                     {db::ScyllaValue(conv3.to_string()), db::ScyllaValue("DIRECT"), db::ScyllaValue("ACTIVE"),
                      db::ScyllaValue(ms3)});

    mock->set_prepared_result(db::PreparedStatementId("member_repo_list_user_convs"),
                              db::ScyllaQueryResult({r1, r2, r3}));

    // Page 1: limit 2
    auto page1 = repo.list_user_conversations(user, 2, std::nullopt);
    EXPECT_EQ(page1.items.size(), 2U);
    // Ordered descending by last_activity_at: conv3 (ms3), then conv2 (ms2)
    EXPECT_EQ(page1.items[0].conversation_id, conv3);
    EXPECT_EQ(page1.items[1].conversation_id, conv2);
    ASSERT_TRUE(page1.next_page_token.has_value());
    EXPECT_EQ(page1.next_page_token.value(), "2");

    // Page 2: with token "2"
    auto page2 = repo.list_user_conversations(user, 2, page1.next_page_token);
    EXPECT_EQ(page2.items.size(), 1U);
    EXPECT_EQ(page2.items[0].conversation_id, conv1);
    EXPECT_FALSE(page2.next_page_token.has_value());
}

} // namespace
} // namespace securecloud::messaging::repository::test
