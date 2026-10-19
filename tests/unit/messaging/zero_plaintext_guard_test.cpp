#include "messaging/util/zero_plaintext_guard.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::messaging::util::test {
namespace {

using domain::ConversationId;
using domain::DeviceDeliveryTarget;
using domain::DeviceId;
using domain::E2EAlgorithm;
using domain::E2EMessageEnvelope;
using domain::E2EProtocolVersion;
using domain::MessageId;
using domain::MessagePriority;
using domain::MessageSubmissionCommand;
using domain::PerDeviceEnvelope;
using domain::UserId;

TEST(ZeroPlaintextGuardTest, FormatSafeSubmissionLogRedactsPayloadAndKeys) {
    MessageSubmissionCommand cmd;
    cmd.caller_user_id = UserId("user-alice-123");
    cmd.sender_device_id = DeviceId("dev-pixel-9");
    cmd.conversation_id = ConversationId::generate_v7();
    cmd.priority = MessagePriority::Urgent;
    cmd.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;

    DeviceDeliveryTarget target;
    target.recipient_user_id = UserId("user-bob-456");
    target.recipient_device_id = DeviceId("dev-iphone-16");
    target.ciphertext_blob = "SUPER_SECRET_PLAINTEXT_CIPHERTEXT_BYTES_XYZ";
    target.ephemeral_public_key = {0xDE, 0xAD, 0xBE, 0xEF};
    target.iv = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    target.auth_tag = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160};
    target.algorithm = "AES-256-GCM";
    cmd.delivery_targets.push_back(target);

    std::string safe_log = ZeroPlaintextGuard::format_safe_submission_log(cmd);

    // Verify metadata is logged
    EXPECT_NE(safe_log.find("user-alice-123"), std::string::npos);
    EXPECT_NE(safe_log.find("dev-pixel-9"), std::string::npos);
    EXPECT_NE(safe_log.find("user-bob-456"), std::string::npos);
    EXPECT_NE(safe_log.find("dev-iphone-16"), std::string::npos);
    EXPECT_NE(safe_log.find("AES-256-GCM"), std::string::npos);
    EXPECT_NE(safe_log.find("cipher_bytes=43"), std::string::npos);
    EXPECT_NE(safe_log.find("iv_bytes=12"), std::string::npos);
    EXPECT_NE(safe_log.find("tag_bytes=16"), std::string::npos);
    EXPECT_NE(safe_log.find("pubkey_bytes=4"), std::string::npos);

    // CRITICAL: Ensure zero raw secret ciphertext bytes appear in log
    EXPECT_EQ(safe_log.find("SUPER_SECRET_PLAINTEXT_CIPHERTEXT_BYTES_XYZ"), std::string::npos);
}

TEST(ZeroPlaintextGuardTest, FormatSafeEnvelopeLogRedactsPayloadAndKeys) {
    E2EMessageEnvelope env;
    env.message_id = MessageId::generate_v7();
    env.conversation_id = ConversationId::generate_v7();
    env.sender_user_id = UserId("user-alice");
    env.sender_device_id = DeviceId("dev-1");
    env.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;

    PerDeviceEnvelope pde;
    pde.recipient_device_id = DeviceId("dev-2");
    pde.ciphertext_blob = "CLASSIFIED_TOP_SECRET_PAYLOAD";
    pde.algorithm = E2EAlgorithm::XChaCha20_Poly1305;
    pde.iv = {0xAA, 0xBB, 0xCC, 0xDD};
    pde.auth_tag = {0x11, 0x22};
    pde.ephemeral_public_key = {0x33, 0x44};
    env.per_device_envelopes.push_back(pde);

    std::string safe_log = ZeroPlaintextGuard::format_safe_envelope_log(env);

    EXPECT_NE(safe_log.find("dev-1"), std::string::npos);
    EXPECT_NE(safe_log.find("dev-2"), std::string::npos);
    EXPECT_NE(safe_log.find("XChaCha20-Poly1305"), std::string::npos);
    EXPECT_NE(safe_log.find("cipher_bytes=29"), std::string::npos);

    // CRITICAL: Ensure zero payload bytes leaked
    EXPECT_EQ(safe_log.find("CLASSIFIED_TOP_SECRET_PAYLOAD"), std::string::npos);
}

TEST(ZeroPlaintextGuardTest, SanitizeErrorMessageRedactsSensitiveKeywords) {
    std::string raw = "Invalid auth tag: auth_tag=deadbeefcafebabe on device dev-1";
    std::string sanitized = ZeroPlaintextGuard::sanitize_error_message(raw);

    EXPECT_EQ(sanitized.find("deadbeefcafebabe"), std::string::npos);
    EXPECT_NE(sanitized.find("auth_tag=[REDACTED]"), std::string::npos);
    EXPECT_NE(sanitized.find("on device dev-1"), std::string::npos);
}

TEST(ZeroPlaintextGuardTest, SanitizeErrorMessageMultipleKeywords) {
    std::string raw = "Crypto error: ciphertext=abc123xyz key=secret456 iv=iv789";
    std::string sanitized = ZeroPlaintextGuard::sanitize_error_message(raw);

    EXPECT_EQ(sanitized.find("abc123xyz"), std::string::npos);
    EXPECT_EQ(sanitized.find("secret456"), std::string::npos);
    EXPECT_EQ(sanitized.find("iv789"), std::string::npos);

    EXPECT_NE(sanitized.find("ciphertext=[REDACTED]"), std::string::npos);
    EXPECT_NE(sanitized.find("key=[REDACTED]"), std::string::npos);
    EXPECT_NE(sanitized.find("iv=[REDACTED]"), std::string::npos);
}

TEST(ZeroPlaintextGuardTest, SanitizeErrorMessageScrubsNonPrintableBytes) {
    std::string raw = "Raw binary: \x01\x02\x03\x1F\x7F hello world";
    std::string sanitized = ZeroPlaintextGuard::sanitize_error_message(raw);

    EXPECT_NE(sanitized.find("hello world"), std::string::npos);
    EXPECT_NE(sanitized.find("?????"), std::string::npos);
}

TEST(ZeroPlaintextGuardTest, SanitizeErrorMessageTruncatesAtLimit) {
    std::string oversized(700, 'X');
    std::string sanitized = ZeroPlaintextGuard::sanitize_error_message(oversized);

    EXPECT_LT(sanitized.size(), 600U);
    EXPECT_NE(sanitized.find("... [TRUNCATED]"), std::string::npos);
}

TEST(ZeroPlaintextGuardTest, SummarizeTargetAndEnvelope) {
    DeviceDeliveryTarget target;
    target.recipient_user_id = UserId("user-1");
    target.recipient_device_id = DeviceId("dev-1");
    target.algorithm = "AES-256-GCM";
    target.ciphertext_blob = "12345";

    std::string sum = ZeroPlaintextGuard::summarize_target(target);
    EXPECT_NE(sum.find("recipient_user: \"user-1\""), std::string::npos);
    EXPECT_NE(sum.find("ciphertext_bytes: 5"), std::string::npos);
    EXPECT_EQ(sum.find("12345"), std::string::npos);

    PerDeviceEnvelope env;
    env.recipient_device_id = DeviceId("dev-2");
    env.algorithm = E2EAlgorithm::AES_256_GCM;
    env.ciphertext_blob = "67890";

    std::string env_sum = ZeroPlaintextGuard::summarize_envelope(env);
    EXPECT_NE(env_sum.find("recipient_device: \"dev-2\""), std::string::npos);
    EXPECT_NE(env_sum.find("ciphertext_bytes: 5"), std::string::npos);
    EXPECT_EQ(env_sum.find("67890"), std::string::npos);
}

} // namespace
} // namespace securecloud::messaging::util::test
