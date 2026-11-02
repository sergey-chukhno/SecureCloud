#include "client/auth_crypto_directory_client_interface.hpp"
#include "service/e2e_envelope_validator.hpp"
#include "service/recipient_device_resolution_service.hpp"

#include <gtest/gtest.h>

namespace securecloud::messaging::service {
namespace {

using client::CryptoDirectoryError;
using client::CryptoDirectoryErrorKind;
using client::DeviceCryptoRecord;
using client::IAuthCryptoDirectoryClient;
using client::Result;
using domain::ConversationId;
using domain::DeviceId;
using domain::E2EAlgorithm;
using domain::E2EMessageEnvelope;
using domain::E2EProtocolVersion;
using domain::MessageId;
using domain::MessagePriority;
using domain::PerDeviceEnvelope;
using domain::UserId;

class MockAuthDirectoryClient : public IAuthCryptoDirectoryClient {
  public:
    void add_device(const UserId& user_id, const DeviceId& device_id,
                    securecloud::auth::v1::DeviceStatus status = securecloud::auth::v1::DEVICE_STATUS_ACTIVE) {
        DeviceCryptoRecord rec{
            .device_id = device_id,
            .user_id = user_id,
            .identity_key = std::vector<uint8_t>(32, 0x01),
            .signed_prekey = std::vector<uint8_t>(32, 0x02),
            .signed_prekey_signature = std::vector<uint8_t>(64, 0x03),
            .one_time_prekey = std::vector<uint8_t>(32, 0x04),
            .one_time_prekey_id = "otk-1",
            .status = status,
            .identity_key_fingerprint = "fp-" + device_id.str(),
            .signed_prekey_created_at_epoch_ms = 1000,
            .remaining_one_time_prekeys = 50,
        };
        user_devices_[user_id].push_back(rec);
    }

    Result<std::vector<DeviceCryptoRecord>, CryptoDirectoryError>
    get_user_device_crypto_records(const UserId& user_id, std::chrono::milliseconds /*timeout*/) override {
        auto it = user_devices_.find(user_id);
        if (it != user_devices_.end()) {
            return it->second;
        }
        return std::vector<DeviceCryptoRecord>{};
    }

    Result<DeviceCryptoRecord, CryptoDirectoryError>
    get_device_crypto_identity(const DeviceId& /*device_id*/, std::chrono::milliseconds /*timeout*/) override {
        return CryptoDirectoryError{
            .kind = CryptoDirectoryErrorKind::NotFound,
            .message = "Not implemented in mock",
            .grpc_code = ::grpc::StatusCode::NOT_FOUND,
        };
    }

  private:
    std::unordered_map<UserId, std::vector<DeviceCryptoRecord>> user_devices_;
};

// Generates high-entropy pseudorandom binary payload
std::string make_pseudorandom_ciphertext(size_t length = 64) {
    std::string s;
    s.resize(length);
    for (size_t i = 0; i < length; ++i) {
        s[i] = static_cast<char>((i * 137 + 73) & 0xFF);
    }
    return s;
}

PerDeviceEnvelope make_test_per_device_envelope(const UserId& recp_user, const DeviceId& recp_dev) {
    return PerDeviceEnvelope{
        .recipient_user_id = recp_user,
        .recipient_device_id = recp_dev,
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .algorithm = E2EAlgorithm::XChaCha20_Poly1305,
        .ciphertext_blob = make_pseudorandom_ciphertext(64),
        .ephemeral_public_key = std::vector<uint8_t>(32, 0xAA),
        .iv = std::vector<uint8_t>(24, 0xBB),
        .auth_tag = std::vector<uint8_t>(16, 0xCC),
        .one_time_prekey_id = std::nullopt,
    };
}

E2EMessageEnvelope make_test_envelope(const UserId& sender_user, const DeviceId& sender_dev, const UserId& recp_user,
                                      const DeviceId& recp_dev) {
    return E2EMessageEnvelope{
        .message_id = MessageId::generate_v7(),
        .conversation_id = ConversationId::generate_v7(),
        .sender_user_id = sender_user,
        .sender_device_id = sender_dev,
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .priority = MessagePriority::Normal,
        .created_at = std::chrono::system_clock::now(),
        .expires_at = std::chrono::system_clock::now() + std::chrono::hours(24),
        .per_device_envelopes = {make_test_per_device_envelope(recp_user, recp_dev)},
    };
}

MessagingCallerContext make_caller_context(const UserId& user_id, const DeviceId& device_id) {
    MessagingCallerContext ctx;
    ctx.base.user_id = user_id.str();
    ctx.base.device_id = device_id.str();
    ctx.base.correlation_id = "corr-123";
    ctx.base.peer_identity = "peer-auth";
    return ctx;
}

// ============================================================================
// Unit Tests for E2EEnvelopeValidator
// ============================================================================

TEST(E2EEnvelopeValidatorTest, HappyPathValidationSucceeds) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice{"dev-alice-1"};
    DeviceId dev_bob{"dev-bob-1"};

    mock_client->add_device(alice, dev_alice, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(bob, dev_bob, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    auto envelope = make_test_envelope(alice, dev_alice, bob, dev_bob);
    auto caller_ctx = make_caller_context(alice, dev_alice);
    std::vector<UserId> participants = {alice, bob};

    auto res = validator.validate(envelope, caller_ctx, participants, /*enforce_completeness=*/true);
    EXPECT_TRUE(res.is_valid);
    EXPECT_TRUE(res.omitted_device_ids.empty());
    EXPECT_EQ(res.error_message, "");
}

TEST(E2EEnvelopeValidatorTest, Rule1_RejectsSenderUserMismatch) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId charlie{"018f2d52-0000-7000-8000-000000000003"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice{"dev-alice-1"};
    DeviceId dev_bob{"dev-bob-1"};

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    auto envelope = make_test_envelope(alice, dev_alice, bob, dev_bob);
    // Caller context claims to be Charlie, but envelope declares Alice
    auto caller_ctx = make_caller_context(charlie, dev_alice);
    std::vector<UserId> participants = {alice, bob};

    auto res = validator.validate(envelope, caller_ctx, participants);
    EXPECT_FALSE(res.is_valid);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);
    EXPECT_NE(res.error_message.find("Sender user ID"), std::string::npos);
}

TEST(E2EEnvelopeValidatorTest, Rule1_RejectsSenderDeviceMismatch) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice1{"dev-alice-1"};
    DeviceId dev_alice2{"dev-alice-2"};
    DeviceId dev_bob{"dev-bob-1"};

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    auto envelope = make_test_envelope(alice, dev_alice1, bob, dev_bob);
    // Caller context claims DevAlice2, but envelope declares DevAlice1
    auto caller_ctx = make_caller_context(alice, dev_alice2);
    std::vector<UserId> participants = {alice, bob};

    auto res = validator.validate(envelope, caller_ctx, participants);
    EXPECT_FALSE(res.is_valid);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED);
    EXPECT_NE(res.error_message.find("Sender device ID"), std::string::npos);
}

TEST(E2EEnvelopeValidatorTest, Rule2_RejectsUnsupportedTopLevelProtocol) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice{"dev-alice-1"};
    DeviceId dev_bob{"dev-bob-1"};

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    auto envelope = make_test_envelope(alice, dev_alice, bob, dev_bob);
    envelope.protocol_version = E2EProtocolVersion::Unspecified;

    auto caller_ctx = make_caller_context(alice, dev_alice);
    std::vector<UserId> participants = {alice, bob};

    auto res = validator.validate(envelope, caller_ctx, participants);
    EXPECT_FALSE(res.is_valid);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_UNSPECIFIED);
    EXPECT_NE(res.error_message.find("Unsupported or deprecated E2E protocol version"), std::string::npos);
}

TEST(E2EEnvelopeValidatorTest, Rule2_RejectsUnsupportedDeviceProtocol) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice{"dev-alice-1"};
    DeviceId dev_bob{"dev-bob-1"};

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    auto envelope = make_test_envelope(alice, dev_alice, bob, dev_bob);
    envelope.per_device_envelopes[0].protocol_version = static_cast<E2EProtocolVersion>(99);

    auto caller_ctx = make_caller_context(alice, dev_alice);
    std::vector<UserId> participants = {alice, bob};

    auto res = validator.validate(envelope, caller_ctx, participants);
    EXPECT_FALSE(res.is_valid);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_UNSPECIFIED);
    EXPECT_NE(res.error_message.find("Unsupported E2E protocol version"), std::string::npos);
}

TEST(E2EEnvelopeValidatorTest, Rule4_RejectsShortCryptoParameters) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice{"dev-alice-1"};
    DeviceId dev_bob{"dev-bob-1"};

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);
    auto caller_ctx = make_caller_context(alice, dev_alice);
    std::vector<UserId> participants = {alice, bob};

    // Short IV (23 bytes instead of 24)
    auto env1 = make_test_envelope(alice, dev_alice, bob, dev_bob);
    env1.per_device_envelopes[0].iv.resize(23);
    auto res1 = validator.validate(env1, caller_ctx, participants);
    EXPECT_FALSE(res1.is_valid);
    EXPECT_NE(res1.error_message.find("Initialization vector (IV) size"), std::string::npos);

    // Short Auth Tag (15 bytes instead of 16)
    auto env2 = make_test_envelope(alice, dev_alice, bob, dev_bob);
    env2.per_device_envelopes[0].auth_tag.resize(15);
    auto res2 = validator.validate(env2, caller_ctx, participants);
    EXPECT_FALSE(res2.is_valid);
    EXPECT_NE(res2.error_message.find("Authentication tag size"), std::string::npos);

    // Short Ephemeral Public Key (31 bytes instead of 32)
    auto env3 = make_test_envelope(alice, dev_alice, bob, dev_bob);
    env3.per_device_envelopes[0].ephemeral_public_key.resize(31);
    auto res3 = validator.validate(env3, caller_ctx, participants);
    EXPECT_FALSE(res3.is_valid);
    EXPECT_NE(res3.error_message.find("Ephemeral public key size"), std::string::npos);
}

TEST(E2EEnvelopeValidatorTest, Rule4_RejectsOversizedPayload) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice{"dev-alice-1"};
    DeviceId dev_bob{"dev-bob-1"};

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    auto envelope = make_test_envelope(alice, dev_alice, bob, dev_bob);
    envelope.per_device_envelopes[0].ciphertext_blob =
        std::string(ProtocolVersionPolicy::k_max_ciphertext_bytes + 1, 'C');

    auto caller_ctx = make_caller_context(alice, dev_alice);
    std::vector<UserId> participants = {alice, bob};

    auto res = validator.validate(envelope, caller_ctx, participants);
    EXPECT_FALSE(res.is_valid);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_PAYLOAD_TOO_LARGE);
    EXPECT_NE(res.error_message.find("exceeds maximum permitted limit"), std::string::npos);
}

TEST(E2EEnvelopeValidatorTest, Rule5_AntiPlaintextGuardRejectsJson) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice{"dev-alice-1"};
    DeviceId dev_bob{"dev-bob-1"};

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    auto envelope = make_test_envelope(alice, dev_alice, bob, dev_bob);
    // Malicious or misconfigured client sends unencrypted JSON payload
    envelope.per_device_envelopes[0].ciphertext_blob =
        "{\"message\":\"Hello Bob! How are you today?\",\"timestamp\":1234567890}";

    auto caller_ctx = make_caller_context(alice, dev_alice);
    std::vector<UserId> participants = {alice, bob};

    auto res = validator.validate(envelope, caller_ctx, participants);
    EXPECT_FALSE(res.is_valid);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
    EXPECT_NE(res.error_message.find("Unencrypted plaintext payload rejected"), std::string::npos);
}

TEST(E2EEnvelopeValidatorTest, Rule5_AntiPlaintextGuardRejectsAsciiText) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice{"dev-alice-1"};
    DeviceId dev_bob{"dev-bob-1"};

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    auto envelope = make_test_envelope(alice, dev_alice, bob, dev_bob);
    // Unencrypted raw ASCII text
    envelope.per_device_envelopes[0].ciphertext_blob =
        "This is a raw unencrypted message body that should never be accepted by the server!";

    auto caller_ctx = make_caller_context(alice, dev_alice);
    std::vector<UserId> participants = {alice, bob};

    auto res = validator.validate(envelope, caller_ctx, participants);
    EXPECT_FALSE(res.is_valid);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
    EXPECT_NE(res.error_message.find("Unencrypted plaintext payload rejected"), std::string::npos);
}

TEST(E2EEnvelopeValidatorTest, Rule3_RejectsNonParticipantRecipient) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId charlie{"018f2d52-0000-7000-8000-000000000003"};
    DeviceId dev_alice{"dev-alice-1"};
    DeviceId dev_charlie{"dev-charlie-1"};

    mock_client->add_device(alice, dev_alice);
    mock_client->add_device(charlie, dev_charlie);

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    // Target Charlie who is not in the participants list {Alice}
    auto envelope = make_test_envelope(alice, dev_alice, charlie, dev_charlie);
    auto caller_ctx = make_caller_context(alice, dev_alice);
    std::vector<UserId> participants = {alice};

    auto res = validator.validate(envelope, caller_ctx, participants);
    EXPECT_FALSE(res.is_valid);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);
}

TEST(E2EEnvelopeValidatorTest, Rule3_RejectsRevokedTargetDevice) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice{"dev-alice-1"};
    DeviceId dev_bob_lost{"dev-bob-lost"};

    mock_client->add_device(alice, dev_alice, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(bob, dev_bob_lost, securecloud::auth::v1::DEVICE_STATUS_REVOKED);

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    auto envelope = make_test_envelope(alice, dev_alice, bob, dev_bob_lost);
    auto caller_ctx = make_caller_context(alice, dev_alice);
    std::vector<UserId> participants = {alice, bob};

    auto res = validator.validate(envelope, caller_ctx, participants);
    EXPECT_FALSE(res.is_valid);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED);
    EXPECT_NE(res.error_message.find("has been revoked"), std::string::npos);
}

TEST(E2EEnvelopeValidatorTest, DetectsSelectiveDeviceOmission) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice{"dev-alice-1"};
    DeviceId dev_bob1{"dev-bob-1"};
    DeviceId dev_bob2{"dev-bob-2"};

    mock_client->add_device(alice, dev_alice, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(bob, dev_bob1, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(bob, dev_bob2, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    // Only target dev_bob1, omitting dev_bob2
    auto envelope = make_test_envelope(alice, dev_alice, bob, dev_bob1);
    auto caller_ctx = make_caller_context(alice, dev_alice);
    std::vector<UserId> participants = {alice, bob};

    // When enforce_completeness is false: valid, but omitted_device_ids populated
    auto res1 = validator.validate(envelope, caller_ctx, participants, /*enforce_completeness=*/false);
    EXPECT_TRUE(res1.is_valid);
    ASSERT_EQ(res1.omitted_device_ids.size(), 1u);
    EXPECT_EQ(res1.omitted_device_ids[0], dev_bob2);

    // When enforce_completeness is true: invalid
    auto res2 = validator.validate(envelope, caller_ctx, participants, /*enforce_completeness=*/true);
    EXPECT_FALSE(res2.is_valid);
    EXPECT_EQ(res2.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
    ASSERT_EQ(res2.omitted_device_ids.size(), 1u);
    EXPECT_EQ(res2.omitted_device_ids[0], dev_bob2);
}

TEST(E2EEnvelopeValidatorTest, Rule3_RejectsEnvelopeTargetingSenderDeviceItself) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice{"dev-alice-phone"};
    DeviceId dev_bob{"dev-bob-phone"};

    mock_client->add_device(alice, dev_alice, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(bob, dev_bob, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    // Target dev_alice (self) alongside dev_bob
    auto envelope = make_test_envelope(alice, dev_alice, bob, dev_bob);
    // Add target for dev_alice (self-targeting)
    envelope.per_device_envelopes.push_back(make_test_per_device_envelope(alice, dev_alice));

    auto caller_ctx = make_caller_context(alice, dev_alice);
    std::vector<UserId> participants = {alice, bob};

    auto res = validator.validate(envelope, caller_ctx, participants);
    EXPECT_FALSE(res.is_valid);
    EXPECT_EQ(res.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
    EXPECT_NE(res.error_message.find("cannot target itself"), std::string::npos);
}

TEST(E2EEnvelopeValidatorTest, EnforcesSenderCompanionDeviceFanoutUnderCompleteness) {
    auto mock_client = std::make_shared<MockAuthDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice_phone{"dev-alice-phone"};
    DeviceId dev_alice_laptop{"dev-alice-laptop"};
    DeviceId dev_bob{"dev-bob-phone"};

    mock_client->add_device(alice, dev_alice_phone, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(alice, dev_alice_laptop, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(bob, dev_bob, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    auto resolution_service = std::make_shared<RecipientDeviceResolutionService>(mock_client);
    E2EEnvelopeValidator validator(resolution_service);

    auto caller_ctx = make_caller_context(alice, dev_alice_phone);
    std::vector<UserId> participants = {alice, bob};

    // Case 1: Incomplete envelope - targets Bob Phone only, omitting companion Alice Laptop
    auto incomplete_envelope = make_test_envelope(alice, dev_alice_phone, bob, dev_bob);

    // With enforce_completeness = false -> valid, omitted contains dev_alice_laptop
    auto res1 = validator.validate(incomplete_envelope, caller_ctx, participants, /*enforce_completeness=*/false);
    EXPECT_TRUE(res1.is_valid);
    ASSERT_EQ(res1.omitted_device_ids.size(), 1u);
    EXPECT_EQ(res1.omitted_device_ids[0], dev_alice_laptop);

    // With enforce_completeness = true -> rejected
    auto res2 = validator.validate(incomplete_envelope, caller_ctx, participants, /*enforce_completeness=*/true);
    EXPECT_FALSE(res2.is_valid);
    EXPECT_EQ(res2.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
    ASSERT_EQ(res2.omitted_device_ids.size(), 1u);
    EXPECT_EQ(res2.omitted_device_ids[0], dev_alice_laptop);

    // Case 2: Complete envelope - targets Bob Phone and Alice Laptop
    auto complete_envelope = make_test_envelope(alice, dev_alice_phone, bob, dev_bob);
    complete_envelope.per_device_envelopes.push_back(make_test_per_device_envelope(alice, dev_alice_laptop));

    auto res3 = validator.validate(complete_envelope, caller_ctx, participants, /*enforce_completeness=*/true);
    EXPECT_TRUE(res3.is_valid);
    EXPECT_TRUE(res3.omitted_device_ids.empty());
}

} // namespace
} // namespace securecloud::messaging::service
