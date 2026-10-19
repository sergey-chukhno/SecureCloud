#include "service/protocol_version_policy.hpp"

#include <gtest/gtest.h>

namespace securecloud::messaging::service {
namespace {

using domain::DeviceId;
using domain::E2EAlgorithm;
using domain::E2EProtocolVersion;
using domain::PerDeviceEnvelope;
using domain::UserId;

TEST(ProtocolVersionPolicyTest, ProtocolVersionWhitelisting) {
    // Approved protocol versions
    EXPECT_TRUE(ProtocolVersionPolicy::is_supported_protocol_version(1));
    EXPECT_TRUE(ProtocolVersionPolicy::is_supported_protocol_version(2));
    EXPECT_TRUE(
        ProtocolVersionPolicy::is_supported_protocol_version(E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet));
    EXPECT_TRUE(ProtocolVersionPolicy::is_supported_protocol_version(E2EProtocolVersion::V2_Hybrid_PostQuantum));

    // Strictly reject unapproved, obsolete, or unknown versions (fail-closed anti-downgrade)
    EXPECT_FALSE(ProtocolVersionPolicy::is_supported_protocol_version(0));
    EXPECT_FALSE(ProtocolVersionPolicy::is_supported_protocol_version(-1));
    EXPECT_FALSE(ProtocolVersionPolicy::is_supported_protocol_version(3));
    EXPECT_FALSE(ProtocolVersionPolicy::is_supported_protocol_version(99));
    EXPECT_FALSE(ProtocolVersionPolicy::is_supported_protocol_version(E2EProtocolVersion::Unspecified));
    EXPECT_FALSE(ProtocolVersionPolicy::is_supported_protocol_version(static_cast<E2EProtocolVersion>(42)));
}

TEST(ProtocolVersionPolicyTest, ApprovedAlgorithms) {
    // Approved algorithms
    EXPECT_TRUE(ProtocolVersionPolicy::is_approved_algorithm("XChaCha20-Poly1305"));
    EXPECT_TRUE(ProtocolVersionPolicy::is_approved_algorithm("xchacha20-poly1305"));
    EXPECT_TRUE(ProtocolVersionPolicy::is_approved_algorithm("AES-256-GCM"));
    EXPECT_TRUE(ProtocolVersionPolicy::is_approved_algorithm("aes-256-gcm"));
    EXPECT_TRUE(ProtocolVersionPolicy::is_approved_algorithm(E2EAlgorithm::XChaCha20_Poly1305));
    EXPECT_TRUE(ProtocolVersionPolicy::is_approved_algorithm(E2EAlgorithm::AES_256_GCM));

    // Unapproved / insecure algorithms
    EXPECT_FALSE(ProtocolVersionPolicy::is_approved_algorithm("AES-128-CBC"));
    EXPECT_FALSE(ProtocolVersionPolicy::is_approved_algorithm("DES"));
    EXPECT_FALSE(ProtocolVersionPolicy::is_approved_algorithm("RC4"));
    EXPECT_FALSE(ProtocolVersionPolicy::is_approved_algorithm("PLAINTEXT"));
    EXPECT_FALSE(ProtocolVersionPolicy::is_approved_algorithm(""));
    EXPECT_FALSE(ProtocolVersionPolicy::is_approved_algorithm(E2EAlgorithm::Unspecified));
    EXPECT_FALSE(ProtocolVersionPolicy::is_approved_algorithm(static_cast<E2EAlgorithm>(99)));
}

TEST(ProtocolVersionPolicyTest, MinimumCryptographicParameterSizes) {
    // XChaCha20-Poly1305
    EXPECT_EQ(ProtocolVersionPolicy::get_minimum_iv_size(E2EAlgorithm::XChaCha20_Poly1305), 24u);
    EXPECT_EQ(ProtocolVersionPolicy::get_minimum_auth_tag_size(E2EAlgorithm::XChaCha20_Poly1305), 16u);
    EXPECT_EQ(ProtocolVersionPolicy::get_minimum_ephemeral_key_size(E2EAlgorithm::XChaCha20_Poly1305), 32u);

    // AES-256-GCM
    EXPECT_EQ(ProtocolVersionPolicy::get_minimum_iv_size(E2EAlgorithm::AES_256_GCM), 12u);
    EXPECT_EQ(ProtocolVersionPolicy::get_minimum_auth_tag_size(E2EAlgorithm::AES_256_GCM), 16u);
    EXPECT_EQ(ProtocolVersionPolicy::get_minimum_ephemeral_key_size(E2EAlgorithm::AES_256_GCM), 32u);

    // Unspecified
    EXPECT_EQ(ProtocolVersionPolicy::get_minimum_iv_size(E2EAlgorithm::Unspecified), 0u);
    EXPECT_EQ(ProtocolVersionPolicy::get_minimum_auth_tag_size(E2EAlgorithm::Unspecified), 0u);
    EXPECT_EQ(ProtocolVersionPolicy::get_minimum_ephemeral_key_size(E2EAlgorithm::Unspecified), 0u);
}

TEST(ProtocolVersionPolicyTest, CanonicalAlgorithmNames) {
    EXPECT_EQ(ProtocolVersionPolicy::get_canonical_algorithm_name(E2EAlgorithm::XChaCha20_Poly1305),
              "XChaCha20-Poly1305");
    EXPECT_EQ(ProtocolVersionPolicy::get_canonical_algorithm_name(E2EAlgorithm::AES_256_GCM), "AES-256-GCM");
    EXPECT_EQ(ProtocolVersionPolicy::get_canonical_algorithm_name(E2EAlgorithm::Unspecified), "UNSPECIFIED");
}

TEST(ProtocolVersionPolicyTest, ValidateEnvelopeSecurityValidXChaCha20) {
    PerDeviceEnvelope env{
        .recipient_user_id = UserId{"usr-001"},
        .recipient_device_id = DeviceId{"dev-001"},
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .algorithm = E2EAlgorithm::XChaCha20_Poly1305,
        .ciphertext_blob = "valid-ciphertext-payload",
        .ephemeral_public_key = std::vector<uint8_t>(32, 0xAA),
        .iv = std::vector<uint8_t>(24, 0xBB),
        .auth_tag = std::vector<uint8_t>(16, 0xCC),
        .one_time_prekey_id = std::nullopt,
    };

    auto err = ProtocolVersionPolicy::validate_envelope_security(env);
    EXPECT_FALSE(err.has_value());
}

TEST(ProtocolVersionPolicyTest, ValidateEnvelopeSecurityValidAESGCM) {
    PerDeviceEnvelope env{
        .recipient_user_id = UserId{"usr-001"},
        .recipient_device_id = DeviceId{"dev-001"},
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .algorithm = E2EAlgorithm::AES_256_GCM,
        .ciphertext_blob = "valid-aes-gcm-ciphertext",
        .ephemeral_public_key = std::vector<uint8_t>(32, 0x11),
        .iv = std::vector<uint8_t>(12, 0x22),
        .auth_tag = std::vector<uint8_t>(16, 0x33),
        .one_time_prekey_id = "prekey-456",
    };

    auto err = ProtocolVersionPolicy::validate_envelope_security(env);
    EXPECT_FALSE(err.has_value());
}

TEST(ProtocolVersionPolicyTest, ValidateEnvelopeSecurityRejectsUnsupportedProtocol) {
    PerDeviceEnvelope env{
        .recipient_user_id = UserId{"usr-001"},
        .recipient_device_id = DeviceId{"dev-001"},
        .protocol_version = E2EProtocolVersion::Unspecified,
        .algorithm = E2EAlgorithm::XChaCha20_Poly1305,
        .ciphertext_blob = "valid-ciphertext",
        .ephemeral_public_key = std::vector<uint8_t>(32, 0x01),
        .iv = std::vector<uint8_t>(24, 0x02),
        .auth_tag = std::vector<uint8_t>(16, 0x03),
    };

    auto err = ProtocolVersionPolicy::validate_envelope_security(env);
    ASSERT_TRUE(err.has_value());
    EXPECT_NE(err->find("Unsupported or deprecated E2E protocol version"), std::string::npos);
}

TEST(ProtocolVersionPolicyTest, ValidateEnvelopeSecurityRejectsUnapprovedAlgorithm) {
    PerDeviceEnvelope env{
        .recipient_user_id = UserId{"usr-001"},
        .recipient_device_id = DeviceId{"dev-001"},
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .algorithm = E2EAlgorithm::Unspecified,
        .ciphertext_blob = "valid-ciphertext",
        .ephemeral_public_key = std::vector<uint8_t>(32, 0x01),
        .iv = std::vector<uint8_t>(24, 0x02),
        .auth_tag = std::vector<uint8_t>(16, 0x03),
    };

    auto err = ProtocolVersionPolicy::validate_envelope_security(env);
    ASSERT_TRUE(err.has_value());
    EXPECT_NE(err->find("Unapproved cryptographic algorithm"), std::string::npos);
}

TEST(ProtocolVersionPolicyTest, ValidateEnvelopeSecurityRejectsEmptyCiphertext) {
    PerDeviceEnvelope env{
        .recipient_user_id = UserId{"usr-001"},
        .recipient_device_id = DeviceId{"dev-001"},
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .algorithm = E2EAlgorithm::XChaCha20_Poly1305,
        .ciphertext_blob = "",
        .ephemeral_public_key = std::vector<uint8_t>(32, 0x01),
        .iv = std::vector<uint8_t>(24, 0x02),
        .auth_tag = std::vector<uint8_t>(16, 0x03),
    };

    auto err = ProtocolVersionPolicy::validate_envelope_security(env);
    ASSERT_TRUE(err.has_value());
    EXPECT_NE(err->find("Ciphertext blob cannot be empty"), std::string::npos);
}

TEST(ProtocolVersionPolicyTest, ValidateEnvelopeSecurityRejectsOversizedCiphertext) {
    PerDeviceEnvelope env{
        .recipient_user_id = UserId{"usr-001"},
        .recipient_device_id = DeviceId{"dev-001"},
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .algorithm = E2EAlgorithm::XChaCha20_Poly1305,
        .ciphertext_blob = std::string(ProtocolVersionPolicy::k_max_ciphertext_bytes + 1, 'X'),
        .ephemeral_public_key = std::vector<uint8_t>(32, 0x01),
        .iv = std::vector<uint8_t>(24, 0x02),
        .auth_tag = std::vector<uint8_t>(16, 0x03),
    };

    auto err = ProtocolVersionPolicy::validate_envelope_security(env);
    ASSERT_TRUE(err.has_value());
    EXPECT_NE(err->find("exceeds maximum permitted limit"), std::string::npos);
}

TEST(ProtocolVersionPolicyTest, ValidateEnvelopeSecurityRejectsShortIV) {
    // XChaCha20 requires 24 bytes, test with 23
    PerDeviceEnvelope env{
        .recipient_user_id = UserId{"usr-001"},
        .recipient_device_id = DeviceId{"dev-001"},
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .algorithm = E2EAlgorithm::XChaCha20_Poly1305,
        .ciphertext_blob = "ciphertext",
        .ephemeral_public_key = std::vector<uint8_t>(32, 0x01),
        .iv = std::vector<uint8_t>(23, 0x02),
        .auth_tag = std::vector<uint8_t>(16, 0x03),
    };

    auto err = ProtocolVersionPolicy::validate_envelope_security(env);
    ASSERT_TRUE(err.has_value());
    EXPECT_NE(err->find("Initialization vector (IV) size"), std::string::npos);

    // AES-GCM requires 12 bytes, test with 11
    env.algorithm = E2EAlgorithm::AES_256_GCM;
    env.iv = std::vector<uint8_t>(11, 0x02);
    err = ProtocolVersionPolicy::validate_envelope_security(env);
    ASSERT_TRUE(err.has_value());
    EXPECT_NE(err->find("Initialization vector (IV) size"), std::string::npos);
}

TEST(ProtocolVersionPolicyTest, ValidateEnvelopeSecurityRejectsShortAuthTag) {
    // Requires 16 bytes, test with 15
    PerDeviceEnvelope env{
        .recipient_user_id = UserId{"usr-001"},
        .recipient_device_id = DeviceId{"dev-001"},
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .algorithm = E2EAlgorithm::XChaCha20_Poly1305,
        .ciphertext_blob = "ciphertext",
        .ephemeral_public_key = std::vector<uint8_t>(32, 0x01),
        .iv = std::vector<uint8_t>(24, 0x02),
        .auth_tag = std::vector<uint8_t>(15, 0x03),
    };

    auto err = ProtocolVersionPolicy::validate_envelope_security(env);
    ASSERT_TRUE(err.has_value());
    EXPECT_NE(err->find("Authentication tag size"), std::string::npos);
}

TEST(ProtocolVersionPolicyTest, ValidateEnvelopeSecurityRejectsShortEphemeralKey) {
    // Requires 32 bytes, test with 31
    PerDeviceEnvelope env{
        .recipient_user_id = UserId{"usr-001"},
        .recipient_device_id = DeviceId{"dev-001"},
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .algorithm = E2EAlgorithm::XChaCha20_Poly1305,
        .ciphertext_blob = "ciphertext",
        .ephemeral_public_key = std::vector<uint8_t>(31, 0x01),
        .iv = std::vector<uint8_t>(24, 0x02),
        .auth_tag = std::vector<uint8_t>(16, 0x03),
    };

    auto err = ProtocolVersionPolicy::validate_envelope_security(env);
    ASSERT_TRUE(err.has_value());
    EXPECT_NE(err->find("Ephemeral public key size"), std::string::npos);
}

} // namespace
} // namespace securecloud::messaging::service
