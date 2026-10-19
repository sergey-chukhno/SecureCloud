#include "domain/conversation_entity.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/group_metadata_entity.hpp"
#include "repository/in_memory_conversation_repository.hpp"
#include "repository/in_memory_membership_repository.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/messaging_caller_context.hpp"

#include <gtest/gtest.h>

namespace securecloud::messaging::service {
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
using repository::InMemoryConversationRepository;
using repository::InMemoryMembershipRepository;

class ConversationAuthorizationServiceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        user_alice_ = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001").value();
        user_bob_ = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002").value();
        user_charlie_ = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003").value();
        user_dave_ = UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36004").value();

        conv_direct_id_ = ConversationId::generate_v7();
        conv_group_id_ = ConversationId::generate_v7();

        now_ = std::chrono::system_clock::now();

        // Setup Direct Conversation (Alice & Bob)
        ConversationEntity direct_conv{
            .conversation_id = conv_direct_id_,
            .type = ConversationType::Direct,
            .created_by_user_id = user_alice_,
            .created_at = now_,
            .metadata_version = 1,
        };
        conv_repo_.save_conversation(direct_conv);
        conv_repo_.save_direct_conversation(DirectPair(user_alice_, user_bob_), conv_direct_id_);

        membership_repo_.add_participant({
            .conversation_id = conv_direct_id_,
            .user_id = user_alice_,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = now_,
            .left_at = std::nullopt,
            .membership_version = 1,
        });
        membership_repo_.add_participant({
            .conversation_id = conv_direct_id_,
            .user_id = user_bob_,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = now_,
            .left_at = std::nullopt,
            .membership_version = 1,
        });

        // Setup Group Conversation (Alice as Admin, Bob as Member)
        ConversationEntity group_conv{
            .conversation_id = conv_group_id_,
            .type = ConversationType::Group,
            .created_by_user_id = user_alice_,
            .created_at = now_,
            .metadata_version = 1,
        };
        conv_repo_.save_conversation(group_conv);
        conv_repo_.save_group_metadata({
            .conversation_id = conv_group_id_,
            .title = "Engineering Core",
            .status = GroupStatus::Active,
            .created_at = now_,
            .updated_at = now_,
            .metadata_version = 1,
        });

        membership_repo_.add_participant({
            .conversation_id = conv_group_id_,
            .user_id = user_alice_,
            .role = ParticipantRole::Admin,
            .status = MembershipStatus::Active,
            .joined_at = now_,
            .left_at = std::nullopt,
            .membership_version = 1,
        });
        membership_repo_.add_participant({
            .conversation_id = conv_group_id_,
            .user_id = user_bob_,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = now_,
            .left_at = std::nullopt,
            .membership_version = 1,
        });
    }

    UserId user_alice_;
    UserId user_bob_;
    UserId user_charlie_;
    UserId user_dave_;

    ConversationId conv_direct_id_;
    ConversationId conv_group_id_;
    std::chrono::system_clock::time_point now_;

    InMemoryConversationRepository conv_repo_;
    InMemoryMembershipRepository membership_repo_;
};

// ============================================================================
// 1. can_view_conversation
// ============================================================================

TEST_F(ConversationAuthorizationServiceTest, CanViewConversation) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);

    // Non-existent conversation
    auto non_existent_id = ConversationId::generate_v7();
    auto res_not_found = auth.can_view_conversation(user_alice_, non_existent_id);
    EXPECT_FALSE(res_not_found);
    EXPECT_EQ(res_not_found.error_code, v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND);

    // Direct conversation: Active participants allowed
    EXPECT_TRUE(auth.can_view_conversation(user_alice_, conv_direct_id_));
    EXPECT_TRUE(auth.can_view_conversation(user_bob_, conv_direct_id_));

    // Direct conversation: Non-participant denied
    auto res_direct_outsider = auth.can_view_conversation(user_charlie_, conv_direct_id_);
    EXPECT_FALSE(res_direct_outsider);
    EXPECT_EQ(res_direct_outsider.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);

    // Group conversation: Active members allowed
    EXPECT_TRUE(auth.can_view_conversation(user_alice_, conv_group_id_));
    EXPECT_TRUE(auth.can_view_conversation(user_bob_, conv_group_id_));

    // Group conversation: Non-member denied
    auto res_group_outsider = auth.can_view_conversation(user_charlie_, conv_group_id_);
    EXPECT_FALSE(res_group_outsider);
    EXPECT_EQ(res_group_outsider.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);

    // Group conversation: Left member denied
    membership_repo_.update_participant({
        .conversation_id = conv_group_id_,
        .user_id = user_bob_,
        .role = ParticipantRole::Member,
        .status = MembershipStatus::Left,
        .joined_at = now_,
        .left_at = now_,
        .membership_version = 2,
    });
    auto res_left_member = auth.can_view_conversation(user_bob_, conv_group_id_);
    EXPECT_FALSE(res_left_member);
    EXPECT_EQ(res_left_member.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);
}

// ============================================================================
// 2. can_send_message
// ============================================================================

TEST_F(ConversationAuthorizationServiceTest, CanSendMessage) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);

    // Non-existent conversation
    auto non_existent_id = ConversationId::generate_v7();
    EXPECT_FALSE(auth.can_send_message(user_alice_, non_existent_id));

    // Direct conversation: Active participants allowed
    EXPECT_TRUE(auth.can_send_message(user_alice_, conv_direct_id_));
    EXPECT_TRUE(auth.can_send_message(user_bob_, conv_direct_id_));

    // Direct conversation: Non-participant denied
    auto res_outsider = auth.can_send_message(user_charlie_, conv_direct_id_);
    EXPECT_FALSE(res_outsider);
    EXPECT_EQ(res_outsider.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);

    // Group conversation: Active participants allowed
    EXPECT_TRUE(auth.can_send_message(user_alice_, conv_group_id_));
    EXPECT_TRUE(auth.can_send_message(user_bob_, conv_group_id_));

    // Group conversation: Closed group denies sending
    conv_repo_.save_group_metadata({
        .conversation_id = conv_group_id_,
        .title = "Engineering Core",
        .status = GroupStatus::Closed,
        .created_at = now_,
        .updated_at = now_,
        .metadata_version = 2,
    });
    auto res_closed = auth.can_send_message(user_alice_, conv_group_id_);
    EXPECT_FALSE(res_closed);
    EXPECT_EQ(res_closed.error_code, v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND);
}

// ============================================================================
// 3. can_add_participant
// ============================================================================

TEST_F(ConversationAuthorizationServiceTest, CanAddParticipant) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);

    // Direct conversation cannot add members
    auto res_direct = auth.can_add_participant(user_alice_, conv_direct_id_, user_charlie_);
    EXPECT_FALSE(res_direct);

    // Non-existent group
    auto non_existent_id = ConversationId::generate_v7();
    EXPECT_FALSE(auth.can_add_participant(user_alice_, non_existent_id, user_charlie_));

    // Regular Member cannot add participant
    auto res_member_denied = auth.can_add_participant(user_bob_, conv_group_id_, user_charlie_);
    EXPECT_FALSE(res_member_denied);

    // Non-participant cannot add participant
    auto res_outsider = auth.can_add_participant(user_dave_, conv_group_id_, user_charlie_);
    EXPECT_FALSE(res_outsider);

    // Admin can add new participant
    auto res_admin_ok = auth.can_add_participant(user_alice_, conv_group_id_, user_charlie_);
    EXPECT_TRUE(res_admin_ok);

    // Adding an already active member is rejected
    auto res_already_active = auth.can_add_participant(user_alice_, conv_group_id_, user_bob_);
    EXPECT_FALSE(res_already_active);

    // Closed group rejects adding participants
    conv_repo_.save_group_metadata({
        .conversation_id = conv_group_id_,
        .title = "Engineering Core",
        .status = GroupStatus::Closed,
        .created_at = now_,
        .updated_at = now_,
        .metadata_version = 2,
    });
    auto res_closed = auth.can_add_participant(user_alice_, conv_group_id_, user_charlie_);
    EXPECT_FALSE(res_closed);
}

// ============================================================================
// 4. can_remove_participant
// ============================================================================

TEST_F(ConversationAuthorizationServiceTest, CanRemoveParticipant) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);

    // Direct conversation cannot remove members
    EXPECT_FALSE(auth.can_remove_participant(user_alice_, conv_direct_id_, user_bob_));

    // Regular Member cannot remove others
    EXPECT_FALSE(auth.can_remove_participant(user_bob_, conv_group_id_, user_alice_));

    // Admin removing an active member is allowed
    EXPECT_TRUE(auth.can_remove_participant(user_alice_, conv_group_id_, user_bob_));

    // Admin removing a user who is not a participant is rejected
    auto res_not_member = auth.can_remove_participant(user_alice_, conv_group_id_, user_charlie_);
    EXPECT_FALSE(res_not_member);
    EXPECT_EQ(res_not_member.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);

    // Closed group rejects removing participants
    conv_repo_.save_group_metadata({
        .conversation_id = conv_group_id_,
        .title = "Engineering Core",
        .status = GroupStatus::Closed,
        .created_at = now_,
        .updated_at = now_,
        .metadata_version = 2,
    });
    EXPECT_FALSE(auth.can_remove_participant(user_alice_, conv_group_id_, user_bob_));
}

// ============================================================================
// 5. can_leave_conversation
// ============================================================================

TEST_F(ConversationAuthorizationServiceTest, CanLeaveConversation) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);

    // Direct conversation cannot be left
    EXPECT_FALSE(auth.can_leave_conversation(user_alice_, conv_direct_id_));

    // Non-participant cannot leave
    EXPECT_FALSE(auth.can_leave_conversation(user_charlie_, conv_group_id_));

    // Regular member can leave
    EXPECT_TRUE(auth.can_leave_conversation(user_bob_, conv_group_id_));

    // Sole Admin cannot leave while other active members remain
    auto res_sole_admin = auth.can_leave_conversation(user_alice_, conv_group_id_);
    EXPECT_FALSE(res_sole_admin);

    // If another Admin is added, the first Admin can leave
    membership_repo_.update_participant({
        .conversation_id = conv_group_id_,
        .user_id = user_bob_,
        .role = ParticipantRole::Admin,
        .status = MembershipStatus::Active,
        .joined_at = now_,
        .left_at = std::nullopt,
        .membership_version = 2,
    });
    EXPECT_TRUE(auth.can_leave_conversation(user_alice_, conv_group_id_));

    // If all other members left (Alice is alone in group), Alice can leave
    membership_repo_.update_participant({
        .conversation_id = conv_group_id_,
        .user_id = user_bob_,
        .role = ParticipantRole::Member,
        .status = MembershipStatus::Left,
        .joined_at = now_,
        .left_at = now_,
        .membership_version = 3,
    });
    EXPECT_TRUE(auth.can_leave_conversation(user_alice_, conv_group_id_));
}

// ============================================================================
// 6. can_update_metadata & can_close_conversation
// ============================================================================

TEST_F(ConversationAuthorizationServiceTest, MetadataAndClosePermissions) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);

    // Metadata: Direct conversation has no group metadata
    EXPECT_FALSE(auth.can_update_metadata(user_alice_, conv_direct_id_));
    EXPECT_FALSE(auth.can_close_conversation(user_alice_, conv_direct_id_));

    // Group: Admin can update metadata and close
    EXPECT_TRUE(auth.can_update_metadata(user_alice_, conv_group_id_));
    EXPECT_TRUE(auth.can_close_conversation(user_alice_, conv_group_id_));

    // Group: Regular Member cannot update metadata or close
    EXPECT_FALSE(auth.can_update_metadata(user_bob_, conv_group_id_));
    EXPECT_FALSE(auth.can_close_conversation(user_bob_, conv_group_id_));

    // Once closed, further updates or closing are denied
    conv_repo_.save_group_metadata({
        .conversation_id = conv_group_id_,
        .title = "Engineering Core",
        .status = GroupStatus::Closed,
        .created_at = now_,
        .updated_at = now_,
        .metadata_version = 2,
    });
    EXPECT_FALSE(auth.can_update_metadata(user_alice_, conv_group_id_));
    EXPECT_FALSE(auth.can_close_conversation(user_alice_, conv_group_id_));
}

// ============================================================================
// 7. MessagingCallerContext Overloads
// ============================================================================

TEST_F(ConversationAuthorizationServiceTest, CallerContextOverloads) {
    ConversationAuthorizationService auth(conv_repo_, membership_repo_);

    MessagingCallerContext valid_ctx{
        .base =
            {
                .user_id = user_alice_.str(),
                .device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099",
                .correlation_id = "corr-12345",
                .peer_identity = "gateway",
            },
        .idempotency_token = "token-1234567890123456",
    };

    EXPECT_TRUE(auth.can_view_conversation(valid_ctx, conv_group_id_));
    EXPECT_TRUE(auth.can_send_message(valid_ctx, conv_group_id_));
    EXPECT_TRUE(auth.can_add_participant(valid_ctx, conv_group_id_, user_charlie_));
    EXPECT_TRUE(auth.can_remove_participant(valid_ctx, conv_group_id_, user_bob_));
    EXPECT_TRUE(auth.can_update_metadata(valid_ctx, conv_group_id_));

    MessagingCallerContext invalid_ctx{
        .base =
            {
                .user_id = "not-a-valid-uuid",
                .device_id = "device-1",
                .correlation_id = "corr-1",
                .peer_identity = "gateway",
            },
        .idempotency_token = "",
    };

    EXPECT_FALSE(auth.can_view_conversation(invalid_ctx, conv_group_id_));
    EXPECT_FALSE(auth.can_send_message(invalid_ctx, conv_group_id_));
}

} // namespace
} // namespace securecloud::messaging::service
