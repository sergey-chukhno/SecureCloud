#include "domain/audit_event.hpp"
#include "domain/audit_event_id.hpp"
#include "util/zero_plaintext_guard.hpp"

#include <gtest/gtest.h>
#include <set>
#include <stdexcept>
#include <string>

namespace securecloud::messaging::domain::test {
namespace {

using util::ZeroPlaintextGuard;

TEST(MessagingAuditEventTest, AllTenEventTypesRoundTripCanonicalStrings) {
    const struct {
        MessagingAuditEventType type;
        std::string_view expected_str;
        MessagingAuditSeverity expected_severity;
    } kCases[] = {
        {MessagingAuditEventType::MessageSubmitted, "message.submitted", MessagingAuditSeverity::Info},
        {MessagingAuditEventType::MessageDelivered, "message.delivered", MessagingAuditSeverity::Info},
        {MessagingAuditEventType::MessageRead, "message.read", MessagingAuditSeverity::Info},
        {MessagingAuditEventType::MessageDeliveryFailed, "message.delivery.failed", MessagingAuditSeverity::Warning},
        {MessagingAuditEventType::ConversationCreated, "conversation.created", MessagingAuditSeverity::Info},
        {MessagingAuditEventType::ConversationMembershipChanged, "conversation.membership.changed",
         MessagingAuditSeverity::Info},
        {MessagingAuditEventType::ConversationClosed, "conversation.closed", MessagingAuditSeverity::Info},
        {MessagingAuditEventType::SecurityAuthorizationDenied, "security.authorization.denied",
         MessagingAuditSeverity::Security},
        {MessagingAuditEventType::EmergencyActivated, "emergency.activated", MessagingAuditSeverity::Critical},
        {MessagingAuditEventType::RateLimitExceeded, "messaging.rate_limit.exceeded", MessagingAuditSeverity::Warning},
    };

    for (const auto& c : kCases) {
        EXPECT_EQ(to_string(c.type), c.expected_str);
        const auto parsed = messaging_audit_event_type_from_string(c.expected_str);
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(*parsed, c.type);
        EXPECT_EQ(default_severity(c.type), c.expected_severity);
    }

    EXPECT_FALSE(messaging_audit_event_type_from_string("unknown.event").has_value());
}

TEST(MessagingAuditEventTest, DeterministicMessageAuditEventIdIsStableAndValidUuidV7) {
    const MessageId msg_id = MessageId::generate_v7();

    const std::string id_a = generate_message_audit_event_id(msg_id, MessagingAuditEventType::MessageSubmitted);
    const std::string id_b = generate_message_audit_event_id(msg_id, MessagingAuditEventType::MessageSubmitted);
    const std::string id_delivered = generate_message_audit_event_id(msg_id, MessagingAuditEventType::MessageDelivered);

    EXPECT_EQ(id_a, id_b);
    EXPECT_NE(id_a, id_delivered);
    EXPECT_TRUE(is_valid_audit_uuid_v7(id_a));
    EXPECT_TRUE(is_valid_audit_uuid_v7(id_delivered));

    // Preserves the 48-bit timestamp prefix of msg_id (first 13 chars: xxxxxxxx-xxxx)
    EXPECT_EQ(id_a.substr(0, 13), msg_id.to_string().substr(0, 13));

    const MessageId nil_id{};
    EXPECT_THROW((void)generate_message_audit_event_id(nil_id, MessagingAuditEventType::MessageSubmitted),
                 std::invalid_argument);
}

TEST(MessagingAuditEventTest, OutboxBucketAndShardIdAreDeterministicAndBounded) {
    const std::chrono::sys_days day{std::chrono::year{2026} / std::chrono::November / std::chrono::day{5}};
    const auto tp = day + std::chrono::hours{17} + std::chrono::minutes{42};
    EXPECT_EQ(compute_outbox_bucket_utc(tp), "2026110517");

    std::set<int32_t> observed_shards;
    for (int i = 0; i < 200; ++i) {
        const std::string conv_id = "conv-" + std::to_string(i);
        const int32_t shard = compute_outbox_shard_id(conv_id);
        EXPECT_GE(shard, 0);
        EXPECT_LT(shard, kMessagingAuditOutboxShardCount);
        EXPECT_EQ(shard, compute_outbox_shard_id(conv_id));
        observed_shards.insert(shard);
    }
    EXPECT_EQ(observed_shards.size(), static_cast<size_t>(kMessagingAuditOutboxShardCount));
}

TEST(MessagingAuditEventTest, ZeroPlaintextGuardAcceptsValidStructuralMetadata) {
    EXPECT_NO_THROW(ZeroPlaintextGuard::validate_audit_payload(
        R"({"sequence":42,"priority":"NORMAL","recipient_device_count":3,"envelope_bytes":512,"protocol_version":1})"));

    EXPECT_NO_THROW(ZeroPlaintextGuard::validate_audit_payload(
        R"({"conversation_id":"01930000-0000-7000-8000-000000000001","delivery_latency_ms":128,"attempt_count":1})"));
}

TEST(MessagingAuditEventTest, ZeroPlaintextGuardRejectsForbiddenKeysAndSecrets) {
    EXPECT_THROW(ZeroPlaintextGuard::validate_audit_payload(R"({"ciphertext":"aGVsbG8="})"), std::logic_error);
    EXPECT_THROW(ZeroPlaintextGuard::validate_audit_payload(R"({"ciphertext_blob":"deadbeef"})"), std::logic_error);
    EXPECT_THROW(ZeroPlaintextGuard::validate_audit_payload(R"({"ephemeral_public_key":"abcd"})"), std::logic_error);
    EXPECT_THROW(ZeroPlaintextGuard::validate_audit_payload(R"({"nested":{"private_key":"secret"}})"), std::logic_error);
    EXPECT_THROW(ZeroPlaintextGuard::validate_audit_payload(R"({"access_token":"xyz"})"), std::logic_error);
    EXPECT_THROW(ZeroPlaintextGuard::validate_audit_payload(R"({"ratchet_state":"abc"})"), std::logic_error);
    EXPECT_THROW(ZeroPlaintextGuard::validate_audit_payload(R"({"prekey_id":"123"})"), std::logic_error);
    EXPECT_THROW(ZeroPlaintextGuard::validate_audit_payload(R"({"iv":"01020304"})"), std::logic_error);
    EXPECT_THROW(ZeroPlaintextGuard::validate_audit_payload(R"({"detail":"Bearer eyJhbGciOiJIUzI1NiJ9.aaa.bbb"})"),
                 std::logic_error);
    EXPECT_THROW(ZeroPlaintextGuard::validate_audit_payload("not-json"), std::logic_error);
    EXPECT_THROW(ZeroPlaintextGuard::validate_audit_payload("[1,2,3]"), std::logic_error);
}

} // namespace
} // namespace securecloud::messaging::domain::test
