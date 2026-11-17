#include "domain/conversation.hpp"
#include "domain/message.hpp"

#include <chrono>
#include <gtest/gtest.h>

namespace securecloud::client::domain::test {
namespace {

TEST(ConversationDomainTest, GroupParticipantRolesAndMembershipLifecycleSyncActiveList) {
    const ConversationId cid("conv-group-001");
    const UserId admin("user-admin");
    const UserId member1("user-bob");
    const UserId member2("user-charlie");

    Conversation conv(cid, ConversationType::Group, "Architecture Council", {admin, member1});
    EXPECT_EQ(conv.participants().size(), 2u);
    EXPECT_EQ(conv.participant_records().size(), 2u);
    EXPECT_EQ(conv.sender_key_epoch(), 1u);
    EXPECT_EQ(conv.group_status(), GroupStatus::Active);

    // Promote creator to Admin
    EXPECT_TRUE(conv.set_participant_role(admin, ParticipantRole::Admin));
    EXPECT_TRUE(conv.is_admin(admin));
    EXPECT_FALSE(conv.is_admin(member1));
    EXPECT_EQ(conv.role_of(member1), ParticipantRole::Member);

    // Add new participant with explicit role
    conv.add_participant(member2, ParticipantRole::Member);
    EXPECT_EQ(conv.participants().size(), 3u);
    EXPECT_TRUE(conv.has_participant(member2));

    // Remove member1 -> marked Removed in records and removed from active participants()
    conv.remove_participant(member1);
    EXPECT_FALSE(conv.has_participant(member1));
    EXPECT_EQ(conv.participants().size(), 2u);
    const auto rec1 = conv.find_participant(member1);
    ASSERT_TRUE(rec1.has_value());
    EXPECT_EQ(rec1->status, MembershipStatus::Removed);
    EXPECT_EQ(rec1->membership_version, 2u);
    EXPECT_FALSE(conv.role_of(member1).has_value());

    // Re-adding removed participant reactivates and bumps version
    conv.add_participant(member1, ParticipantRole::Admin);
    EXPECT_TRUE(conv.has_participant(member1));
    EXPECT_TRUE(conv.is_admin(member1));
    EXPECT_EQ(conv.find_participant(member1)->membership_version, 3u);

    // Increment sender key epoch
    EXPECT_EQ(conv.increment_sender_key_epoch(), 2u);
    EXPECT_EQ(conv.sender_key_epoch(), 2u);
}

TEST(ConversationDomainTest, JsonSerializationRoundTripPreservesRolesEpochAndTimestamps) {
    const ConversationId cid("conv-group-002");
    const auto created = std::chrono::system_clock::time_point(std::chrono::milliseconds(1760000000123LL));
    const auto last_act = std::chrono::system_clock::time_point(std::chrono::milliseconds(1760000300456LL));

    Conversation original(cid, ConversationType::Group, "Security Ops", {}, created, last_act, 4u, true);
    original.add_participant(UserId("alice"), ParticipantRole::Admin);
    original.add_participant(UserId("bob"), ParticipantRole::Member);
    original.set_participant_status(UserId("bob"), MembershipStatus::Left);
    original.set_group_status(GroupStatus::Closed);
    original.set_sender_key_epoch(7u);

    const std::string json_str = original.to_json();
    const auto decoded_opt = Conversation::from_json(json_str);
    ASSERT_TRUE(decoded_opt.has_value());

    const Conversation& decoded = *decoded_opt;
    EXPECT_EQ(decoded, original);
    EXPECT_EQ(decoded.conversation_id(), cid);
    EXPECT_EQ(decoded.type(), ConversationType::Group);
    EXPECT_EQ(decoded.title(), "Security Ops");
    EXPECT_EQ(decoded.unread_count(), 4u);
    EXPECT_TRUE(decoded.is_muted());
    EXPECT_EQ(decoded.group_status(), GroupStatus::Closed);
    EXPECT_EQ(decoded.sender_key_epoch(), 7u);
    EXPECT_TRUE(decoded.is_admin(UserId("alice")));
    EXPECT_FALSE(decoded.has_participant(UserId("bob")));
    ASSERT_TRUE(decoded.find_participant(UserId("bob")).has_value());
    EXPECT_EQ(decoded.find_participant(UserId("bob"))->status, MembershipStatus::Left);
    EXPECT_EQ(std::chrono::duration_cast<std::chrono::milliseconds>(decoded.created_at().time_since_epoch()).count(),
              1760000000123LL);
    EXPECT_EQ(
        std::chrono::duration_cast<std::chrono::milliseconds>(decoded.last_activity_at().time_since_epoch()).count(),
        1760000300456LL);
}

TEST(ConversationDomainTest, FromJsonRejectsMalformedOrInvalidInputs) {
    EXPECT_FALSE(Conversation::from_json("not-json").has_value());
    EXPECT_FALSE(Conversation::from_json("{}").has_value());
    EXPECT_FALSE(Conversation::from_json(R"({"conversation_id":""})").has_value());

    const std::string cid = "conv-group-003";
    EXPECT_FALSE(Conversation::from_json(R"({"conversation_id":")" + cid + R"(","type":"InvalidType"})").has_value());
    EXPECT_FALSE(
        Conversation::from_json(R"({"conversation_id":")" + cid + R"(","group_status":"CorruptStatus"})").has_value());
    EXPECT_FALSE(Conversation::from_json(R"({"conversation_id":")" + cid +
                                         R"(","participant_records":[{"user_id":"u1","role":"SuperUser"}]})")
                     .has_value());
}

TEST(MessageDomainTest, JsonSerializationRoundTripPreservesAllMetadataAndEpoch) {
    const MessageId mid("msg-001");
    const ConversationId cid("conv-group-004");
    const UserId sender_uid("alice");
    const DeviceId sender_did("alice-laptop");
    const auto sent_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1760000500789LL));

    Message original(mid, cid, sender_uid, sender_did, DeliveryState::Delivered, sent_at, "scg:v1:opaque-ref", 2,
                     "Alice", "idem-123", true, "report.pdf", 4096, "sha256:abcd");
    original.set_server_sequence_number(42u);
    original.set_sender_key_epoch(3u);

    EXPECT_EQ(original.client_message_id(), "idem-123");

    const std::string json_str = original.to_json();
    const auto decoded_opt = Message::from_json(json_str);
    ASSERT_TRUE(decoded_opt.has_value());

    const Message& decoded = *decoded_opt;
    EXPECT_EQ(decoded, original);
    EXPECT_EQ(decoded.message_id(), mid);
    EXPECT_EQ(decoded.conversation_id(), cid);
    EXPECT_EQ(decoded.sender_user_id(), sender_uid);
    EXPECT_EQ(decoded.sender_device_id(), sender_did);
    EXPECT_EQ(decoded.delivery_state(), DeliveryState::Delivered);
    EXPECT_EQ(decoded.encrypted_envelope_ref(), "scg:v1:opaque-ref");
    EXPECT_EQ(decoded.priority(), 2);
    EXPECT_EQ(decoded.sender_display_name(), "Alice");
    EXPECT_EQ(decoded.idempotency_key(), "idem-123");
    EXPECT_TRUE(decoded.emergency_acknowledged());
    EXPECT_EQ(decoded.attachment_name(), "report.pdf");
    EXPECT_EQ(decoded.attachment_size(), 4096);
    EXPECT_EQ(decoded.attachment_hash(), "sha256:abcd");
    EXPECT_EQ(decoded.server_sequence_number(), 42u);
    EXPECT_EQ(decoded.sender_key_epoch(), 3u);
    EXPECT_EQ(std::chrono::duration_cast<std::chrono::milliseconds>(decoded.sent_at().time_since_epoch()).count(),
              1760000500789LL);
}

TEST(MessageDomainTest, FromJsonRejectsMalformedOrIncompletePayloads) {
    EXPECT_FALSE(Message::from_json("{").has_value());
    EXPECT_FALSE(Message::from_json("{}").has_value());

    const std::string mid = "msg-002";
    const std::string cid = "conv-group-005";

    // Missing sender_device_id
    EXPECT_FALSE(Message::from_json(R"({"message_id":")" + mid + R"(","conversation_id":")" + cid +
                                    R"(","sender_user_id":"u1"})")
                     .has_value());

    // Empty message_id
    EXPECT_FALSE(
        Message::from_json(R"({"message_id":"","conversation_id":"c1","sender_user_id":"u1","sender_device_id":"d1"})")
            .has_value());

    // Invalid delivery_state
    EXPECT_FALSE(Message::from_json(R"({"message_id":")" + mid + R"(","conversation_id":")" + cid +
                                    R"(","sender_user_id":"u1","sender_device_id":"d1","delivery_state":"Bogus"})")
                     .has_value());
}

} // namespace
} // namespace securecloud::client::domain::test
