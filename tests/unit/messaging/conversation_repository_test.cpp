#include "domain/conversation_entity.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/group_metadata_entity.hpp"
#include "repository/in_memory_conversation_repository.hpp"
#include "repository/in_memory_membership_repository.hpp"

#include <gtest/gtest.h>
#include <thread>
#include <vector>

namespace securecloud::messaging::repository {
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
// 1. Conversation Repository Tests
// ============================================================================

TEST(ConversationRepositoryTest, SaveAndFindConversationById) {
    InMemoryConversationRepository repo;

    auto conv_id = ConversationId::generate_v7();
    auto creator_id = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001").value();
    auto now = std::chrono::system_clock::now();

    // Not found initially
    EXPECT_FALSE(repo.find_conversation_by_id(conv_id).has_value());

    ConversationEntity entity{
        .conversation_id = conv_id,
        .type = ConversationType::Direct,
        .created_by_user_id = creator_id,
        .created_at = now,
        .metadata_version = 1,
    };

    repo.save_conversation(entity);

    auto retrieved = repo.find_conversation_by_id(conv_id);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->conversation_id, conv_id);
    EXPECT_EQ(retrieved->type, ConversationType::Direct);
    EXPECT_EQ(retrieved->created_by_user_id, creator_id);
}

TEST(ConversationRepositoryTest, DirectPairSaveAndLookup) {
    InMemoryConversationRepository repo;

    auto user_a = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001").value();
    auto user_b = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002").value();
    auto conv_id = ConversationId::generate_v7();

    DirectPair pair(user_a, user_b);

    EXPECT_FALSE(repo.find_direct_conversation(pair).has_value());

    repo.save_direct_conversation(pair, conv_id);

    // Lookup using identical pair
    auto found = repo.find_direct_conversation(pair);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(*found, conv_id);

    // Lookup using reversed pair (Bob, Alice) must yield same conv_id due to DirectPair symmetry
    DirectPair reversed_pair(user_b, user_a);
    auto found_reversed = repo.find_direct_conversation(reversed_pair);
    ASSERT_TRUE(found_reversed.has_value());
    EXPECT_EQ(*found_reversed, conv_id);
}

TEST(ConversationRepositoryTest, GroupMetadataSaveAndLookup) {
    InMemoryConversationRepository repo;

    auto conv_id = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    EXPECT_FALSE(repo.find_group_metadata(conv_id).has_value());

    GroupMetadataEntity meta{
        .conversation_id = conv_id,
        .title = "Core Architecture Team",
        .status = GroupStatus::Active,
        .created_at = now,
        .updated_at = now,
        .metadata_version = 1,
    };

    repo.save_group_metadata(meta);

    auto retrieved = repo.find_group_metadata(conv_id);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->title, "Core Architecture Team");
    EXPECT_EQ(retrieved->status, GroupStatus::Active);

    // Update status to Closed
    meta.status = GroupStatus::Closed;
    meta.metadata_version = 2;
    repo.save_group_metadata(meta);

    auto updated = repo.find_group_metadata(conv_id);
    ASSERT_TRUE(updated.has_value());
    EXPECT_EQ(updated->status, GroupStatus::Closed);
    EXPECT_EQ(updated->metadata_version, 2);
}

// ============================================================================
// 2. Membership Repository Tests
// ============================================================================

TEST(MembershipRepositoryTest, AddAndFindParticipant) {
    InMemoryMembershipRepository repo;

    auto conv_id = ConversationId::generate_v7();
    auto user_id = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001").value();
    auto now = std::chrono::system_clock::now();

    EXPECT_FALSE(repo.find_participant(conv_id, user_id).has_value());

    ConversationParticipantEntity participant{
        .conversation_id = conv_id,
        .user_id = user_id,
        .role = ParticipantRole::Admin,
        .status = MembershipStatus::Active,
        .joined_at = now,
        .left_at = std::nullopt,
        .membership_version = 1,
    };

    repo.add_participant(participant);

    auto found = repo.find_participant(conv_id, user_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->role, ParticipantRole::Admin);
    EXPECT_EQ(found->status, MembershipStatus::Active);
    EXPECT_FALSE(found->left_at.has_value());
}

TEST(MembershipRepositoryTest, UpdateParticipantAndListActiveOnly) {
    InMemoryMembershipRepository repo;

    auto conv_id = ConversationId::generate_v7();
    auto user_a = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001").value();
    auto user_b = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002").value();
    auto now = std::chrono::system_clock::now();

    repo.add_participant(ConversationParticipantEntity{
        .conversation_id = conv_id,
        .user_id = user_a,
        .role = ParticipantRole::Admin,
        .status = MembershipStatus::Active,
        .joined_at = now,
        .left_at = std::nullopt,
        .membership_version = 1,
    });

    repo.add_participant(ConversationParticipantEntity{
        .conversation_id = conv_id,
        .user_id = user_b,
        .role = ParticipantRole::Member,
        .status = MembershipStatus::Active,
        .joined_at = now,
        .left_at = std::nullopt,
        .membership_version = 1,
    });

    EXPECT_EQ(repo.list_participants(conv_id).size(), 2);
    EXPECT_EQ(repo.list_active_participants(conv_id).size(), 2);

    // User B leaves conversation
    ConversationParticipantEntity user_b_left{
        .conversation_id = conv_id,
        .user_id = user_b,
        .role = ParticipantRole::Member,
        .status = MembershipStatus::Left,
        .joined_at = now,
        .left_at = now,
        .membership_version = 2,
    };
    repo.update_participant(user_b_left);

    // Total participants remains 2 (history retained), active participants is now 1
    EXPECT_EQ(repo.list_participants(conv_id).size(), 2);
    auto active_list = repo.list_active_participants(conv_id);
    ASSERT_EQ(active_list.size(), 1);
    EXPECT_EQ(active_list[0].user_id, user_a);
}

TEST(MembershipRepositoryTest, UserInboxOrderingAndPagination) {
    InMemoryMembershipRepository repo;

    auto user_id = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001").value();

    auto conv1 = ConversationId::generate_v7();
    auto conv2 = ConversationId::generate_v7();
    auto conv3 = ConversationId::generate_v7();

    auto now = std::chrono::system_clock::now();
    auto t1 = now - std::chrono::minutes(30);
    auto t2 = now - std::chrono::minutes(10);
    auto t3 = now - std::chrono::minutes(1);

    repo.touch_user_conversation(user_id, conv1, ConversationType::Direct, MembershipStatus::Active, t1);
    repo.touch_user_conversation(user_id, conv2, ConversationType::Group, MembershipStatus::Active, t2);
    repo.touch_user_conversation(user_id, conv3, ConversationType::Direct, MembershipStatus::Active, t3);

    // First page, limit 2
    auto page1 = repo.list_user_conversations(user_id, 2, std::nullopt);
    ASSERT_EQ(page1.items.size(), 2);
    EXPECT_EQ(page1.items[0].conversation_id, conv3); // Most recent first (t3)
    EXPECT_EQ(page1.items[1].conversation_id, conv2); // Second most recent (t2)
    ASSERT_TRUE(page1.next_page_token.has_value());

    // Second page using token
    auto page2 = repo.list_user_conversations(user_id, 2, page1.next_page_token);
    ASSERT_EQ(page2.items.size(), 1);
    EXPECT_EQ(page2.items[0].conversation_id, conv1); // Oldest (t1)
    EXPECT_FALSE(page2.next_page_token.has_value());
}

// ============================================================================
// 3. Concurrency & Thread-Safety Tests
// ============================================================================

TEST(ConversationRepositoryTest, ConcurrentReadWriteThreadSafety) {
    InMemoryConversationRepository repo;
    auto creator_id = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001").value();

    constexpr int k_threads = 8;
    constexpr int k_iterations = 50;
    std::vector<std::thread> workers;
    workers.reserve(k_threads);

    for (int t = 0; t < k_threads; ++t) {
        workers.emplace_back([&repo, creator_id, t] {
            for (int i = 0; i < k_iterations; ++i) {
                auto conv_id = ConversationId::generate_v7();
                ConversationEntity entity{
                    .conversation_id = conv_id,
                    .type = (t % 2 == 0) ? ConversationType::Direct : ConversationType::Group,
                    .created_by_user_id = creator_id,
                    .created_at = std::chrono::system_clock::now(),
                    .metadata_version = 1,
                };
                repo.save_conversation(entity);
                auto found = repo.find_conversation_by_id(conv_id);
                EXPECT_TRUE(found.has_value());
            }
        });
    }

    for (auto& w : workers) {
        w.join();
    }
}

} // namespace
} // namespace securecloud::messaging::repository
