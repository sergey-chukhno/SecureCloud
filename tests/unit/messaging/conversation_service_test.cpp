#include "domain/conversation_entity.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/group_metadata_entity.hpp"
#include "domain/outbox_event.hpp"
#include "repository/in_memory_conversation_repository.hpp"
#include "repository/in_memory_membership_repository.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/conversation_service.hpp"

#include <gtest/gtest.h>

namespace securecloud::messaging::service {
namespace {

using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationOutboxEventType;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DirectPair;
using domain::GroupMetadataEntity;
using domain::GroupStatus;
using domain::MembershipStatus;
using domain::ParticipantRole;
using domain::UserId;
using repository::InMemoryConversationRepository;
using repository::InMemoryMembershipRepository;

class ConversationServiceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        user_alice_ = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001").value();
        user_bob_ = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002").value();
        user_charlie_ = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003").value();
        user_dave_ = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36004").value();
    }

    UserId user_alice_;
    UserId user_bob_;
    UserId user_charlie_;
    UserId user_dave_;

    InMemoryConversationRepository conv_repo_;
    InMemoryMembershipRepository membership_repo_;
};

// ============================================================================
// 1. Direct Conversation Creation & Idempotency
// ============================================================================

TEST_F(ConversationServiceTest, CreateDirectConversationIdempotent) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);
    ConversationService service(conv_repo_, membership_repo_, auth);

    // Cannot create direct conversation with self
    auto self_res = service.create_direct_conversation(user_alice_, user_alice_);
    EXPECT_FALSE(self_res);
    EXPECT_EQ(self_res.error_code, v1::MESSAGING_ERROR_CODE_UNSPECIFIED);

    // Initial creation: Alice and Bob
    auto res1 = service.create_direct_conversation(user_alice_, user_bob_);
    ASSERT_TRUE(res1);
    EXPECT_EQ(res1.value.type, ConversationType::Direct);
    EXPECT_EQ(res1.value.created_by_user_id, user_alice_);
    auto conv_id = res1.value.conversation_id;

    // Verify participants added
    auto part_alice = membership_repo_.find_participant(conv_id, user_alice_);
    ASSERT_TRUE(part_alice);
    EXPECT_EQ(part_alice->role, ParticipantRole::Member);
    EXPECT_EQ(part_alice->status, MembershipStatus::Active);

    auto part_bob = membership_repo_.find_participant(conv_id, user_bob_);
    ASSERT_TRUE(part_bob);
    EXPECT_EQ(part_bob->role, ParticipantRole::Member);
    EXPECT_EQ(part_bob->status, MembershipStatus::Active);

    // Verify outbox event recorded
    auto outbox = service.get_outbox_events();
    EXPECT_EQ(outbox.size(), 1);
    EXPECT_EQ(outbox[0].event_type, ConversationOutboxEventType::ConversationCreated);
    EXPECT_EQ(outbox[0].conversation_id, conv_id);

    // Idempotent second call with same order
    auto res2 = service.create_direct_conversation(user_alice_, user_bob_);
    ASSERT_TRUE(res2);
    EXPECT_EQ(res2.value.conversation_id, conv_id);
    EXPECT_EQ(service.get_outbox_events().size(), 1); // No duplicate outbox event

    // Idempotent third call with inverted order (Bob creates with Alice)
    auto res3 = service.create_direct_conversation(user_bob_, user_alice_);
    ASSERT_TRUE(res3);
    EXPECT_EQ(res3.value.conversation_id, conv_id);
    EXPECT_EQ(service.get_outbox_events().size(), 1);
}

// ============================================================================
// 2. Group Conversation Creation
// ============================================================================

TEST_F(ConversationServiceTest, CreateGroupConversation) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);
    ConversationService service(conv_repo_, membership_repo_, auth);

    // Title validation
    EXPECT_FALSE(service.create_group_conversation(user_alice_, "", {user_bob_}));
    std::string long_title(300, 'A');
    EXPECT_FALSE(service.create_group_conversation(user_alice_, long_title, {user_bob_}));

    // Successful creation with Bob and Charlie (and redundant Alice in list)
    auto res = service.create_group_conversation(user_alice_, "Core Platform",
                                                 {user_bob_, user_charlie_, user_alice_, user_bob_});
    ASSERT_TRUE(res);
    auto conv_id = res.value.conversation_id;
    EXPECT_EQ(res.value.type, ConversationType::Group);

    // Group metadata verified
    auto meta = conv_repo_.find_group_metadata(conv_id);
    ASSERT_TRUE(meta);
    EXPECT_EQ(meta->title, "Core Platform");
    EXPECT_EQ(meta->status, GroupStatus::Active);

    // Alice is Admin
    auto part_alice = membership_repo_.find_participant(conv_id, user_alice_);
    ASSERT_TRUE(part_alice);
    EXPECT_EQ(part_alice->role, ParticipantRole::Admin);
    EXPECT_EQ(part_alice->status, MembershipStatus::Active);

    // Bob and Charlie are Members
    auto part_bob = membership_repo_.find_participant(conv_id, user_bob_);
    ASSERT_TRUE(part_bob);
    EXPECT_EQ(part_bob->role, ParticipantRole::Member);

    auto part_charlie = membership_repo_.find_participant(conv_id, user_charlie_);
    ASSERT_TRUE(part_charlie);
    EXPECT_EQ(part_charlie->role, ParticipantRole::Member);

    // Active participants count = 3
    EXPECT_EQ(membership_repo_.list_active_participants(conv_id).size(), 3);
}

// ============================================================================
// 3. Add Participant & Reactivation
// ============================================================================

TEST_F(ConversationServiceTest, AddParticipantAndReactivate) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);
    ConversationService service(conv_repo_, membership_repo_, auth);

    auto group = service.create_group_conversation(user_alice_, "Core Platform", {user_bob_});
    ASSERT_TRUE(group);
    auto conv_id = group.value.conversation_id;

    // Non-admin (Bob) cannot add participant
    auto res_member_add = service.add_participant(user_bob_, conv_id, user_charlie_);
    EXPECT_FALSE(res_member_add);

    // Admin (Alice) adds Charlie
    service.clear_outbox_events();
    auto res_admin_add = service.add_participant(user_alice_, conv_id, user_charlie_);
    EXPECT_TRUE(res_admin_add);

    auto part_charlie = membership_repo_.find_participant(conv_id, user_charlie_);
    ASSERT_TRUE(part_charlie);
    EXPECT_EQ(part_charlie->status, MembershipStatus::Active);
    EXPECT_EQ(part_charlie->role, ParticipantRole::Member);

    auto outbox = service.get_outbox_events();
    EXPECT_EQ(outbox.size(), 1);
    EXPECT_EQ(outbox[0].event_type, ConversationOutboxEventType::ParticipantJoined);

    // Idempotent addition of already active participant
    EXPECT_TRUE(service.add_participant(user_alice_, conv_id, user_charlie_));

    // Simulate Charlie leaving
    EXPECT_TRUE(service.leave_conversation(user_charlie_, conv_id));
    EXPECT_EQ(membership_repo_.find_participant(conv_id, user_charlie_)->status, MembershipStatus::Left);

    // Admin re-adds Charlie (Reactivation)
    auto res_reactivate = service.add_participant(user_alice_, conv_id, user_charlie_);
    EXPECT_TRUE(res_reactivate);
    auto part_reactivated = membership_repo_.find_participant(conv_id, user_charlie_);
    EXPECT_EQ(part_reactivated->status, MembershipStatus::Active);
    EXPECT_FALSE(part_reactivated->left_at.has_value());
    EXPECT_GT(part_reactivated->membership_version, 1);
}

// ============================================================================
// 4. Remove Participant
// ============================================================================

TEST_F(ConversationServiceTest, RemoveParticipant) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);
    ConversationService service(conv_repo_, membership_repo_, auth);

    auto group = service.create_group_conversation(user_alice_, "Core Platform", {user_bob_, user_charlie_});
    ASSERT_TRUE(group);
    auto conv_id = group.value.conversation_id;

    // Member cannot remove another member
    EXPECT_FALSE(service.remove_participant(user_bob_, conv_id, user_charlie_));

    // Admin removes Charlie
    service.clear_outbox_events();
    auto res_remove = service.remove_participant(user_alice_, conv_id, user_charlie_);
    EXPECT_TRUE(res_remove);

    auto part_charlie = membership_repo_.find_participant(conv_id, user_charlie_);
    ASSERT_TRUE(part_charlie);
    EXPECT_EQ(part_charlie->status, MembershipStatus::Removed);
    EXPECT_TRUE(part_charlie->left_at.has_value());

    auto outbox = service.get_outbox_events();
    EXPECT_EQ(outbox.size(), 1);
    EXPECT_EQ(outbox[0].event_type, ConversationOutboxEventType::ParticipantRemoved);
}

// ============================================================================
// 5. Leave Conversation & Auto-Close
// ============================================================================

TEST_F(ConversationServiceTest, LeaveConversationAndAutoClose) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);
    ConversationService service(conv_repo_, membership_repo_, auth);

    auto group = service.create_group_conversation(user_alice_, "Core Platform", {user_bob_});
    ASSERT_TRUE(group);
    auto conv_id = group.value.conversation_id;

    // Alice is sole Admin; cannot leave while Bob is active
    auto res_alice_leave = service.leave_conversation(user_alice_, conv_id);
    EXPECT_FALSE(res_alice_leave);

    // Bob leaves
    EXPECT_TRUE(service.leave_conversation(user_bob_, conv_id));
    EXPECT_EQ(membership_repo_.list_active_participants(conv_id).size(), 1);

    // Now Alice is alone in group; Alice can leave and group will auto-close
    service.clear_outbox_events();
    EXPECT_TRUE(service.leave_conversation(user_alice_, conv_id));
    EXPECT_EQ(membership_repo_.list_active_participants(conv_id).size(), 0);

    auto meta = conv_repo_.find_group_metadata(conv_id);
    ASSERT_TRUE(meta);
    EXPECT_EQ(meta->status, GroupStatus::Closed);

    auto outbox = service.get_outbox_events();
    ASSERT_GE(outbox.size(), 2);
    EXPECT_EQ(outbox[0].event_type, ConversationOutboxEventType::ParticipantLeft);
    EXPECT_EQ(outbox[1].event_type, ConversationOutboxEventType::ConversationClosed);
}

// ============================================================================
// 6. Update Group Metadata
// ============================================================================

TEST_F(ConversationServiceTest, UpdateGroupMetadata) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);
    ConversationService service(conv_repo_, membership_repo_, auth);

    auto group = service.create_group_conversation(user_alice_, "Core Platform", {user_bob_});
    ASSERT_TRUE(group);
    auto conv_id = group.value.conversation_id;

    // Member cannot update title
    EXPECT_FALSE(service.update_group_metadata(user_bob_, conv_id, "Hacked Title"));

    // Empty title rejected
    EXPECT_FALSE(service.update_group_metadata(user_alice_, conv_id, ""));

    // Admin updates title
    service.clear_outbox_events();
    auto res_update = service.update_group_metadata(user_alice_, conv_id, "New Engineering Title");
    ASSERT_TRUE(res_update);
    EXPECT_EQ(res_update.value.title, "New Engineering Title");
    EXPECT_GT(res_update.value.metadata_version, 1);

    auto outbox = service.get_outbox_events();
    EXPECT_EQ(outbox.size(), 1);
    EXPECT_EQ(outbox[0].event_type, ConversationOutboxEventType::GroupMetadataUpdated);
}

// ============================================================================
// 7. Get Conversation Details & List Inbox
// ============================================================================

TEST_F(ConversationServiceTest, GetConversationAndListUserInbox) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);
    ConversationService service(conv_repo_, membership_repo_, auth);

    auto group = service.create_group_conversation(user_alice_, "Core Platform", {user_bob_, user_charlie_});
    ASSERT_TRUE(group);
    auto conv_id = group.value.conversation_id;

    // Active member can fetch details
    auto details_res = service.get_conversation(user_alice_, conv_id);
    ASSERT_TRUE(details_res);
    EXPECT_EQ(details_res.value.conversation.conversation_id, conv_id);
    ASSERT_TRUE(details_res.value.group_metadata.has_value());
    EXPECT_EQ(details_res.value.group_metadata->title, "Core Platform");
    EXPECT_EQ(details_res.value.active_participants.size(), 3);

    // Non-member cannot fetch details
    EXPECT_FALSE(service.get_conversation(user_dave_, conv_id));

    // Alice lists her inbox
    auto inbox_res = service.list_user_conversations(user_alice_, 10, std::nullopt);
    ASSERT_TRUE(inbox_res);
    EXPECT_EQ(inbox_res.value.items.size(), 1);
    EXPECT_EQ(inbox_res.value.items[0].conversation_id, conv_id);
}

} // namespace
} // namespace securecloud::messaging::service
