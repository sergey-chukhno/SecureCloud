#include "domain/conversation_entity.hpp"
#include "domain/conversation_lifecycle.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/group_metadata_entity.hpp"

#include <gtest/gtest.h>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace securecloud::messaging::domain {
namespace {

// ============================================================================
// 1. ConversationId Value Object Tests
// ============================================================================

TEST(ConversationDomainTest, ConversationIdNilAndGeneration) {
    ConversationId nil_id;
    EXPECT_TRUE(nil_id.is_nil());
    EXPECT_EQ(nil_id.to_string(), "00000000-0000-0000-0000-000000000000");

    auto id1 = ConversationId::generate_v7();
    EXPECT_FALSE(id1.is_nil());

    auto id2 = ConversationId::generate_v7();
    EXPECT_FALSE(id2.is_nil());
    EXPECT_NE(id1, id2);
}

TEST(ConversationDomainTest, ConversationIdStringRoundTripAndValidation) {
    auto generated = ConversationId::generate_v7();
    std::string str_repr = generated.to_string();

    auto parsed = ConversationId::from_string(str_repr);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, generated);
    EXPECT_EQ(parsed->to_string(), str_repr);

    // Invalid UUID format tests
    EXPECT_FALSE(ConversationId::from_string("").has_value());
    EXPECT_FALSE(ConversationId::from_string("not-a-valid-uuid").has_value());
    EXPECT_FALSE(ConversationId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d3600").has_value());   // 35 chars
    EXPECT_FALSE(ConversationId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d360000").has_value()); // 37 chars
    EXPECT_FALSE(ConversationId::from_string("0191ec4d_91b4_7b4d_b6a9_8e41e3d36000").has_value());  // underscores
    EXPECT_FALSE(ConversationId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d3600z").has_value());  // non-hex
}

TEST(ConversationDomainTest, ConversationIdOrderingAndHashing) {
    auto id1 = ConversationId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001").value();
    auto id2 = ConversationId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002").value();

    EXPECT_LT(id1, id2);
    EXPECT_LE(id1, id2);
    EXPECT_GT(id2, id1);
    EXPECT_GE(id2, id1);

    std::unordered_set<ConversationId> set;
    set.insert(id1);
    set.insert(id2);
    EXPECT_EQ(set.size(), 2);
    EXPECT_TRUE(set.contains(id1));
    EXPECT_TRUE(set.contains(id2));
}

// ============================================================================
// 2. UserId & DirectPair Value Object Tests
// ============================================================================

TEST(ConversationDomainTest, UserIdValidationAndOrdering) {
    EXPECT_TRUE(UserId::is_valid_format("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"));
    EXPECT_FALSE(UserId::is_valid_format("invalid-uuid"));
    EXPECT_FALSE(UserId::is_valid_format(""));

    auto user_a = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    auto user_b = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    ASSERT_TRUE(user_a.has_value());
    ASSERT_TRUE(user_b.has_value());

    EXPECT_LT(*user_a, *user_b);
    EXPECT_NE(*user_a, *user_b);

    std::unordered_map<UserId, std::string> map;
    map[*user_a] = "Alice";
    map[*user_b] = "Bob";
    EXPECT_EQ(map.at(*user_a), "Alice");
    EXPECT_EQ(map.at(*user_b), "Bob");
}

TEST(ConversationDomainTest, DirectPairSymmetryAndOrdering) {
    auto alice = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001").value();
    auto bob = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002").value();

    // Canonical pair ordering: smaller UserId is user_a
    DirectPair pair1(alice, bob);
    DirectPair pair2(bob, alice);

    EXPECT_EQ(pair1.user_a(), alice);
    EXPECT_EQ(pair1.user_b(), bob);
    EXPECT_EQ(pair2.user_a(), alice);
    EXPECT_EQ(pair2.user_b(), bob);

    // Equality: Alice + Bob is identical to Bob + Alice
    EXPECT_EQ(pair1, pair2);

    // Hash equality
    EXPECT_EQ(std::hash<DirectPair>{}(pair1), std::hash<DirectPair>{}(pair2));

    // Identical user pair is forbidden
    EXPECT_THROW(DirectPair(alice, alice), std::invalid_argument);
}

// ============================================================================
// 3. Conversation Entities Construction & Equality
// ============================================================================

TEST(ConversationDomainTest, ConversationEntityConstruction) {
    auto conv_id = ConversationId::generate_v7();
    auto creator_id = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001").value();
    auto now = std::chrono::system_clock::now();

    ConversationEntity entity{
        .conversation_id = conv_id,
        .type = ConversationType::Direct,
        .created_by_user_id = creator_id,
        .created_at = now,
        .metadata_version = 1,
    };

    EXPECT_EQ(entity.conversation_id, conv_id);
    EXPECT_EQ(entity.type, ConversationType::Direct);
    EXPECT_EQ(entity.created_by_user_id, creator_id);
    EXPECT_EQ(entity.metadata_version, 1);
}

TEST(ConversationDomainTest, GroupMetadataEntityConstruction) {
    auto conv_id = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    GroupMetadataEntity meta{
        .conversation_id = conv_id,
        .title = "Core Infrastructure Engineering",
        .status = GroupStatus::Active,
        .created_at = now,
        .updated_at = now,
        .metadata_version = 1,
    };

    EXPECT_EQ(meta.conversation_id, conv_id);
    EXPECT_EQ(meta.title, "Core Infrastructure Engineering");
    EXPECT_EQ(meta.status, GroupStatus::Active);
    EXPECT_EQ(meta.metadata_version, 1);
}

TEST(ConversationDomainTest, ConversationParticipantEntityConstruction) {
    auto conv_id = ConversationId::generate_v7();
    auto user_id = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001").value();
    auto now = std::chrono::system_clock::now();

    ConversationParticipantEntity participant{
        .conversation_id = conv_id,
        .user_id = user_id,
        .role = ParticipantRole::Admin,
        .status = MembershipStatus::Active,
        .joined_at = now,
        .left_at = std::nullopt,
        .membership_version = 1,
    };

    EXPECT_EQ(participant.conversation_id, conv_id);
    EXPECT_EQ(participant.user_id, user_id);
    EXPECT_EQ(participant.role, ParticipantRole::Admin);
    EXPECT_EQ(participant.status, MembershipStatus::Active);
    EXPECT_FALSE(participant.left_at.has_value());
    EXPECT_EQ(participant.membership_version, 1);
}

// ============================================================================
// 4. Lifecycle State Machine Transitions
// ============================================================================

TEST(ConversationDomainTest, GroupLifecycleTransitions) {
    // Active -> Closed: valid
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_group_transition(GroupStatus::Active, GroupStatus::Closed));

    // Active -> Active: idempotent valid
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_group_transition(GroupStatus::Active, GroupStatus::Active));

    // Closed -> Closed: idempotent valid
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_group_transition(GroupStatus::Closed, GroupStatus::Closed));

    // Closed -> Active: invalid (closed is terminal in MVP)
    EXPECT_FALSE(ConversationLifecycleManager::is_valid_group_transition(GroupStatus::Closed, GroupStatus::Active));
}

TEST(ConversationDomainTest, MembershipLifecycleTransitions) {
    // Active -> Left: valid
    EXPECT_TRUE(
        ConversationLifecycleManager::is_valid_membership_transition(MembershipStatus::Active, MembershipStatus::Left));

    // Active -> Removed: valid
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_membership_transition(MembershipStatus::Active,
                                                                             MembershipStatus::Removed));

    // Active -> Active: idempotent valid
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_membership_transition(MembershipStatus::Active,
                                                                             MembershipStatus::Active));

    // Left -> Active: valid (rejoin)
    EXPECT_TRUE(
        ConversationLifecycleManager::is_valid_membership_transition(MembershipStatus::Left, MembershipStatus::Active));

    // Removed -> Active: valid (readmission)
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_membership_transition(MembershipStatus::Removed,
                                                                             MembershipStatus::Active));

    // Left -> Removed: invalid (cannot remove non-active participant)
    EXPECT_FALSE(ConversationLifecycleManager::is_valid_membership_transition(MembershipStatus::Left,
                                                                              MembershipStatus::Removed));

    // Removed -> Left: invalid
    EXPECT_FALSE(ConversationLifecycleManager::is_valid_membership_transition(MembershipStatus::Removed,
                                                                              MembershipStatus::Left));
}

TEST(ConversationDomainTest, ParticipantCountAndTitleValidation) {
    // Direct participant count must be exactly 2
    EXPECT_FALSE(ConversationLifecycleManager::is_valid_direct_participant_count(0));
    EXPECT_FALSE(ConversationLifecycleManager::is_valid_direct_participant_count(1));
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_direct_participant_count(2));
    EXPECT_FALSE(ConversationLifecycleManager::is_valid_direct_participant_count(3));

    // Group initial participant count must be between 1 and 500
    EXPECT_FALSE(ConversationLifecycleManager::is_valid_group_initial_participant_count(0));
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_group_initial_participant_count(1));
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_group_initial_participant_count(50));
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_group_initial_participant_count(500));
    EXPECT_FALSE(ConversationLifecycleManager::is_valid_group_initial_participant_count(501));

    // Group title validation
    EXPECT_FALSE(ConversationLifecycleManager::is_valid_group_title(""));
    EXPECT_FALSE(ConversationLifecycleManager::is_valid_group_title("   "));
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_group_title("Project Falcon"));
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_group_title("A"));

    std::string long_title(255, 'x');
    EXPECT_TRUE(ConversationLifecycleManager::is_valid_group_title(long_title));

    std::string too_long_title(256, 'x');
    EXPECT_FALSE(ConversationLifecycleManager::is_valid_group_title(too_long_title));
}

} // namespace
} // namespace securecloud::messaging::domain
