#include "messaging/domain/submission_fingerprint.hpp"

#include <algorithm>
#include <gtest/gtest.h>

namespace securecloud::messaging::domain::test {
namespace {

DeviceDeliveryTarget make_sample_target(const std::string& user_uuid, const std::string& device_id,
                                        const std::string& ciphertext) {
    DeviceDeliveryTarget target;
    target.recipient_user_id = UserId(user_uuid);
    target.recipient_device_id = DeviceId(device_id);
    target.ciphertext_blob = ciphertext;
    target.ephemeral_public_key = std::vector<uint8_t>(32, 0xAA);
    target.iv = std::vector<uint8_t>(24, 0xBB);
    target.auth_tag = std::vector<uint8_t>(16, 0xCC);
    target.algorithm = "XChaCha20-Poly1305";
    return target;
}

MessageSubmissionCommand make_sample_command() {
    MessageSubmissionCommand cmd;
    cmd.caller_user_id = UserId("018d0000-0000-7000-8000-000000000001");
    cmd.sender_device_id = DeviceId("device-sender-primary");
    cmd.conversation_id = *ConversationId::from_string("018d0000-0000-7000-8000-000000000010");
    cmd.client_idempotency_token = "idem-token-uuid-123456";
    cmd.priority = MessagePriority::Normal;
    cmd.delivery_targets.push_back(
        make_sample_target("018d0000-0000-7000-8000-000000000002", "device-bob-phone", "encrypted_payload_for_bob"));
    cmd.delivery_targets.push_back(make_sample_target("018d0000-0000-7000-8000-000000000003", "device-charlie-tablet",
                                                      "encrypted_payload_for_charlie"));
    return cmd;
}

TEST(SubmissionFingerprintTest, DeterministicOutputAndFormat) {
    auto cmd = make_sample_command();
    std::string fp1 = calculate_submission_fingerprint(cmd);
    std::string fp2 = calculate_submission_fingerprint(cmd);

    EXPECT_EQ(fp1, fp2);
    EXPECT_EQ(fp1.size(), 64U);

    // Ensure all characters are lowercase hexadecimal
    for (char c : fp1) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
            << "Unexpected non-hex character in fingerprint: " << c;
    }
}

TEST(SubmissionFingerprintTest, CanonicalTargetOrderInvariance) {
    auto cmd1 = make_sample_command();
    auto cmd2 = make_sample_command();

    // In cmd2, reverse the delivery target order in the vector
    std::reverse(cmd2.delivery_targets.begin(), cmd2.delivery_targets.end());

    std::string fp1 = calculate_submission_fingerprint(cmd1);
    std::string fp2 = calculate_submission_fingerprint(cmd2);

    EXPECT_EQ(fp1, fp2) << "Fingerprint should be identical regardless of delivery target order";
}

TEST(SubmissionFingerprintTest, SensitiveToConversationId) {
    auto cmd1 = make_sample_command();
    auto cmd2 = make_sample_command();
    cmd2.conversation_id = *ConversationId::from_string("018d0000-0000-7000-8000-000000000099");

    EXPECT_NE(calculate_submission_fingerprint(cmd1), calculate_submission_fingerprint(cmd2));
}

TEST(SubmissionFingerprintTest, SensitiveToSenderDeviceId) {
    auto cmd1 = make_sample_command();
    auto cmd2 = make_sample_command();
    cmd2.sender_device_id = DeviceId("device-sender-alternate");

    EXPECT_NE(calculate_submission_fingerprint(cmd1), calculate_submission_fingerprint(cmd2));
}

TEST(SubmissionFingerprintTest, SensitiveToPriority) {
    auto cmd1 = make_sample_command();
    auto cmd2 = make_sample_command();
    cmd2.priority = MessagePriority::Urgent;

    EXPECT_NE(calculate_submission_fingerprint(cmd1), calculate_submission_fingerprint(cmd2));
}

TEST(SubmissionFingerprintTest, SensitiveToCiphertextBlob) {
    auto cmd1 = make_sample_command();
    auto cmd2 = make_sample_command();
    cmd2.delivery_targets[0].ciphertext_blob = "tampered_ciphertext_blob_for_bob";

    EXPECT_NE(calculate_submission_fingerprint(cmd1), calculate_submission_fingerprint(cmd2));
}

TEST(SubmissionFingerprintTest, SensitiveToRecipientDeviceId) {
    auto cmd1 = make_sample_command();
    auto cmd2 = make_sample_command();
    cmd2.delivery_targets[0].recipient_device_id = DeviceId("device-bob-desktop");

    EXPECT_NE(calculate_submission_fingerprint(cmd1), calculate_submission_fingerprint(cmd2));
}

TEST(SubmissionFingerprintTest, HandlesEmptyAndSingleTarget) {
    MessageSubmissionCommand cmd_empty;
    cmd_empty.caller_user_id = UserId("018d0000-0000-7000-8000-000000000001");
    cmd_empty.sender_device_id = DeviceId("device-1");
    cmd_empty.conversation_id = *ConversationId::from_string("018d0000-0000-7000-8000-000000000001");
    std::string fp_empty = calculate_submission_fingerprint(cmd_empty);
    EXPECT_EQ(fp_empty.size(), 64U);

    cmd_empty.delivery_targets.push_back(
        make_sample_target("018d0000-0000-7000-8000-000000000002", "device-2", "blob"));
    std::string fp_single = calculate_submission_fingerprint(cmd_empty);
    EXPECT_EQ(fp_single.size(), 64U);
    EXPECT_NE(fp_empty, fp_single);
}

} // namespace
} // namespace securecloud::messaging::domain::test
