#include "messaging/service/submission_validator.hpp"

#include <chrono>
#include <gtest/gtest.h>

namespace securecloud::messaging::service::test {
namespace {

using domain::ConversationId;
using domain::DeviceDeliveryTarget;
using domain::DeviceId;
using domain::MessagePriority;
using domain::MessageSubmissionCommand;
using domain::UserId;

DeviceDeliveryTarget make_valid_target(const std::string& user_uuid = "018d0000-0000-7000-8000-000000000002",
                                       const std::string& device_id = "device-recipient-1") {
    DeviceDeliveryTarget target;
    target.recipient_user_id = UserId(user_uuid);
    target.recipient_device_id = DeviceId(device_id);
    target.ciphertext_blob = "valid-encrypted-blob-data";
    target.ephemeral_public_key = std::vector<uint8_t>(32, 0x11);
    target.iv = std::vector<uint8_t>(24, 0x22);
    target.auth_tag = std::vector<uint8_t>(16, 0x33);
    target.algorithm = "XChaCha20-Poly1305";
    return target;
}

MessageSubmissionCommand make_valid_command() {
    MessageSubmissionCommand cmd;
    cmd.caller_user_id = UserId("018d0000-0000-7000-8000-000000000001");
    cmd.sender_device_id = DeviceId("device-sender-1");
    cmd.conversation_id = *ConversationId::from_string("018d0000-0000-7000-8000-000000000010");
    cmd.client_idempotency_token = "valid-token-123";
    cmd.priority = MessagePriority::Normal;
    cmd.expires_at = std::nullopt;
    cmd.delivery_targets.push_back(make_valid_target());
    return cmd;
}

TEST(SubmissionValidatorTest, ValidCommandSucceeds) {
    auto cmd = make_valid_command();
    auto result = SubmissionValidator::validate(cmd);
    EXPECT_TRUE(result.is_valid);
    EXPECT_TRUE(static_cast<bool>(result));
    EXPECT_TRUE(result.error_message.empty());
    EXPECT_TRUE(result.field_name.empty());
}

TEST(SubmissionValidatorTest, ValidWithFutureExpiration) {
    auto cmd = make_valid_command();
    cmd.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);
    auto result = SubmissionValidator::validate(cmd);
    EXPECT_TRUE(result.is_valid);
}

TEST(SubmissionValidatorTest, RejectsExpiredMessage) {
    auto cmd = make_valid_command();
    cmd.expires_at = std::chrono::system_clock::now() - std::chrono::seconds(10);
    auto result = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.field_name, "expires_at");
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED);
}

TEST(SubmissionValidatorTest, CallerUserIdValidation) {
    auto cmd = make_valid_command();
    cmd.caller_user_id = UserId("");
    auto res1 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res1.is_valid);
    EXPECT_EQ(res1.field_name, "caller_user_id");

    cmd.caller_user_id = UserId("invalid-uuid-format");
    auto res2 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res2.is_valid);
    EXPECT_EQ(res2.field_name, "caller_user_id");
}

TEST(SubmissionValidatorTest, SenderDeviceIdValidation) {
    auto cmd = make_valid_command();
    cmd.sender_device_id = DeviceId("");
    auto res1 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res1.is_valid);
    EXPECT_EQ(res1.field_name, "sender_device_id");

    cmd.sender_device_id = DeviceId(std::string(129, 'x'));
    auto res2 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res2.is_valid);
    EXPECT_EQ(res2.field_name, "sender_device_id");

    // Non-printable character (e.g. newline / control char)
    cmd.sender_device_id = DeviceId("device\x01sender");
    auto res3 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res3.is_valid);
    EXPECT_EQ(res3.field_name, "sender_device_id");
}

TEST(SubmissionValidatorTest, ConversationIdNilRejected) {
    auto cmd = make_valid_command();
    cmd.conversation_id = ConversationId{}; // nil UUID
    auto result = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.field_name, "conversation_id");
}

TEST(SubmissionValidatorTest, ClientIdempotencyTokenValidation) {
    auto cmd = make_valid_command();
    cmd.client_idempotency_token = "";
    auto res1 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res1.is_valid);
    EXPECT_EQ(res1.field_name, "client_idempotency_token");

    cmd.client_idempotency_token = std::string(129, 'a');
    auto res2 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res2.is_valid);
    EXPECT_EQ(res2.field_name, "client_idempotency_token");

    cmd.client_idempotency_token = "token\twith\ncontrol";
    auto res3 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res3.is_valid);
    EXPECT_EQ(res3.field_name, "client_idempotency_token");
}

TEST(SubmissionValidatorTest, DeliveryTargetsEmptyOrTooMany) {
    auto cmd = make_valid_command();
    cmd.delivery_targets.clear();
    auto res1 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res1.is_valid);
    EXPECT_EQ(res1.field_name, "delivery_targets");

    for (std::size_t i = 0; i < 257; ++i) {
        cmd.delivery_targets.push_back(
            make_valid_target("018d0000-0000-7000-8000-000000000002", "dev-" + std::to_string(i)));
    }
    auto res2 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res2.is_valid);
    EXPECT_EQ(res2.field_name, "delivery_targets");
}

TEST(SubmissionValidatorTest, DeliveryTargetsDuplicateDeviceRejected) {
    auto cmd = make_valid_command();
    cmd.delivery_targets.push_back(
        make_valid_target("018d0000-0000-7000-8000-000000000003", "device-recipient-1")); // Duplicate device ID
    auto result = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.field_name, "delivery_targets");
}

TEST(SubmissionValidatorTest, MultiDevicePerUserAllowed) {
    auto cmd = make_valid_command();
    // Same user ID, different device IDs
    cmd.delivery_targets.push_back(
        make_valid_target("018d0000-0000-7000-8000-000000000002", "device-recipient-2-phone"));
    cmd.delivery_targets.push_back(
        make_valid_target("018d0000-0000-7000-8000-000000000002", "device-recipient-2-tablet"));
    auto result = SubmissionValidator::validate(cmd);
    EXPECT_TRUE(result.is_valid);
}

TEST(SubmissionValidatorTest, RecipientUserAndDeviceValidation) {
    auto cmd = make_valid_command();
    cmd.delivery_targets[0].recipient_user_id = UserId("");
    auto res1 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res1.is_valid);
    EXPECT_EQ(res1.field_name, "delivery_targets.recipient_user_id");

    cmd = make_valid_command();
    cmd.delivery_targets[0].recipient_user_id = UserId("not-a-uuid");
    auto res2 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res2.is_valid);
    EXPECT_EQ(res2.field_name, "delivery_targets.recipient_user_id");

    cmd = make_valid_command();
    cmd.delivery_targets[0].recipient_device_id = DeviceId("");
    auto res3 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res3.is_valid);
    EXPECT_EQ(res3.field_name, "delivery_targets.recipient_device_id");

    cmd = make_valid_command();
    cmd.delivery_targets[0].recipient_device_id = DeviceId(std::string(129, 'd'));
    auto res4 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res4.is_valid);
    EXPECT_EQ(res4.field_name, "delivery_targets.recipient_device_id");
}

TEST(SubmissionValidatorTest, CiphertextBlobValidation) {
    auto cmd = make_valid_command();
    cmd.delivery_targets[0].ciphertext_blob = "";
    auto res1 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res1.is_valid);
    EXPECT_EQ(res1.field_name, "delivery_targets.ciphertext_blob");

    // Exceeds 16MB
    cmd = make_valid_command();
    cmd.delivery_targets[0].ciphertext_blob = std::string(16 * 1024 * 1024 + 1, 'c');
    auto res2 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res2.is_valid);
    EXPECT_EQ(res2.field_name, "delivery_targets.ciphertext_blob");
    EXPECT_EQ(res2.error_code, v1::MESSAGING_ERROR_CODE_PAYLOAD_TOO_LARGE);
}

TEST(SubmissionValidatorTest, CryptographicAlgorithmValidation) {
    auto cmd = make_valid_command();
    cmd.delivery_targets[0].algorithm = "DES-EDE3-CBC";
    auto res1 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res1.is_valid);
    EXPECT_EQ(res1.field_name, "delivery_targets.algorithm");

    // AES-256-GCM is accepted with >= 12 byte IV
    cmd = make_valid_command();
    cmd.delivery_targets[0].algorithm = "AES-256-GCM";
    cmd.delivery_targets[0].iv = std::vector<uint8_t>(12, 0x01);
    auto res2 = SubmissionValidator::validate(cmd);
    EXPECT_TRUE(res2.is_valid);

    // AES-256-GCM with < 12 byte IV is rejected
    cmd.delivery_targets[0].iv = std::vector<uint8_t>(11, 0x01);
    auto res3 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res3.is_valid);
    EXPECT_EQ(res3.field_name, "delivery_targets.iv");

    // XChaCha20-Poly1305 with < 24 byte IV is rejected
    cmd = make_valid_command();
    cmd.delivery_targets[0].algorithm = "XChaCha20-Poly1305";
    cmd.delivery_targets[0].iv = std::vector<uint8_t>(23, 0x01);
    auto res4 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res4.is_valid);
    EXPECT_EQ(res4.field_name, "delivery_targets.iv");
}

TEST(SubmissionValidatorTest, AuthTagAndEphemeralKeyValidation) {
    auto cmd = make_valid_command();
    cmd.delivery_targets[0].auth_tag = std::vector<uint8_t>(15, 0xFF); // Under 16 bytes
    auto res1 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res1.is_valid);
    EXPECT_EQ(res1.field_name, "delivery_targets.auth_tag");

    cmd = make_valid_command();
    cmd.delivery_targets[0].ephemeral_public_key.clear();
    auto res2 = SubmissionValidator::validate(cmd);
    EXPECT_FALSE(res2.is_valid);
    EXPECT_EQ(res2.field_name, "delivery_targets.ephemeral_public_key");
}

} // namespace
} // namespace securecloud::messaging::service::test
