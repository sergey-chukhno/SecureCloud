#include "domain/envelope_types.hpp"

#include <gtest/gtest.h>

namespace securecloud::messaging::domain {
namespace {

TEST(EnvelopeTypesTest, ProtocolVersionToStringAndParsing) {
    EXPECT_EQ(to_string(E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet), "V1_Signal_PQXDH_DoubleRatchet");
    EXPECT_EQ(to_string(E2EProtocolVersion::V2_Hybrid_PostQuantum), "V2_Hybrid_PostQuantum");
    EXPECT_EQ(to_string(E2EProtocolVersion::Unspecified), "UNSPECIFIED");
    EXPECT_EQ(to_string(static_cast<E2EProtocolVersion>(999)), "UNKNOWN");

    EXPECT_EQ(e2e_protocol_version_from_int(1), E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet);
    EXPECT_EQ(e2e_protocol_version_from_int(2), E2EProtocolVersion::V2_Hybrid_PostQuantum);
    EXPECT_FALSE(e2e_protocol_version_from_int(0).has_value());
    EXPECT_FALSE(e2e_protocol_version_from_int(-1).has_value());
    EXPECT_FALSE(e2e_protocol_version_from_int(3).has_value());

    EXPECT_EQ(e2e_protocol_version_from_string("V1_Signal_PQXDH_DoubleRatchet"),
              E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet);
    EXPECT_EQ(e2e_protocol_version_from_string("1"), E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet);
    EXPECT_EQ(e2e_protocol_version_from_string("v1"), E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet);
    EXPECT_EQ(e2e_protocol_version_from_string("V2_Hybrid_PostQuantum"), E2EProtocolVersion::V2_Hybrid_PostQuantum);
    EXPECT_EQ(e2e_protocol_version_from_string("2"), E2EProtocolVersion::V2_Hybrid_PostQuantum);
    EXPECT_EQ(e2e_protocol_version_from_string("v2"), E2EProtocolVersion::V2_Hybrid_PostQuantum);
    EXPECT_FALSE(e2e_protocol_version_from_string("unknown").has_value());
    EXPECT_FALSE(e2e_protocol_version_from_string("").has_value());
}

TEST(EnvelopeTypesTest, AlgorithmToStringAndParsing) {
    EXPECT_EQ(to_string(E2EAlgorithm::XChaCha20_Poly1305), "XChaCha20-Poly1305");
    EXPECT_EQ(to_string(E2EAlgorithm::AES_256_GCM), "AES-256-GCM");
    EXPECT_EQ(to_string(E2EAlgorithm::Unspecified), "UNSPECIFIED");
    EXPECT_EQ(to_string(static_cast<E2EAlgorithm>(99)), "UNKNOWN");

    EXPECT_EQ(e2e_algorithm_from_string("XChaCha20-Poly1305"), E2EAlgorithm::XChaCha20_Poly1305);
    EXPECT_EQ(e2e_algorithm_from_string("xchacha20-poly1305"), E2EAlgorithm::XChaCha20_Poly1305);
    EXPECT_EQ(e2e_algorithm_from_string("XCHACHA20_POLY1305"), E2EAlgorithm::XChaCha20_Poly1305);

    EXPECT_EQ(e2e_algorithm_from_string("AES-256-GCM"), E2EAlgorithm::AES_256_GCM);
    EXPECT_EQ(e2e_algorithm_from_string("aes-256-gcm"), E2EAlgorithm::AES_256_GCM);
    EXPECT_EQ(e2e_algorithm_from_string("AES_256_GCM"), E2EAlgorithm::AES_256_GCM);

    EXPECT_FALSE(e2e_algorithm_from_string("DES").has_value());
    EXPECT_FALSE(e2e_algorithm_from_string("AES-128-CBC").has_value());
    EXPECT_FALSE(e2e_algorithm_from_string("").has_value());
}

TEST(EnvelopeTypesTest, PerDeviceEnvelopeEqualityAndComparison) {
    PerDeviceEnvelope env1{
        .recipient_user_id = UserId{"018f2d52-0000-7000-8000-000000000001"},
        .recipient_device_id = DeviceId{"device-uuid-1"},
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .algorithm = E2EAlgorithm::XChaCha20_Poly1305,
        .ciphertext_blob = "encrypted-payload-data",
        .ephemeral_public_key = std::vector<uint8_t>(32, 0xAA),
        .iv = std::vector<uint8_t>(24, 0x11),
        .auth_tag = std::vector<uint8_t>(16, 0x22),
        .one_time_prekey_id = "prekey-123",
    };

    PerDeviceEnvelope env2 = env1;
    EXPECT_EQ(env1, env2);

    PerDeviceEnvelope env3 = env1;
    env3.recipient_device_id = DeviceId{"device-uuid-2"};
    EXPECT_NE(env1, env3);
}

TEST(EnvelopeTypesTest, E2EMessageEnvelopeStructure) {
    const auto now = std::chrono::system_clock::now();
    const auto msg_id = MessageId::generate_v7();
    const auto conv_id = ConversationId::generate_v7();

    PerDeviceEnvelope dev_env{
        .recipient_user_id = UserId{"018f2d52-0000-7000-8000-000000000001"},
        .recipient_device_id = DeviceId{"device-uuid-recp"},
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .algorithm = E2EAlgorithm::XChaCha20_Poly1305,
        .ciphertext_blob = "device-ciphertext",
        .ephemeral_public_key = std::vector<uint8_t>(32, 0x01),
        .iv = std::vector<uint8_t>(24, 0x02),
        .auth_tag = std::vector<uint8_t>(16, 0x03),
        .one_time_prekey_id = std::nullopt,
    };

    E2EMessageEnvelope envelope{
        .message_id = msg_id,
        .conversation_id = conv_id,
        .sender_user_id = UserId{"018f2d52-0000-7000-8000-000000000002"},
        .sender_device_id = DeviceId{"device-uuid-sender"},
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .priority = MessagePriority::Urgent,
        .created_at = now,
        .expires_at = now + std::chrono::hours(24),
        .per_device_envelopes = {dev_env},
    };

    EXPECT_EQ(envelope.message_id, msg_id);
    EXPECT_EQ(envelope.conversation_id, conv_id);
    EXPECT_EQ(envelope.sender_user_id.str(), "018f2d52-0000-7000-8000-000000000002");
    EXPECT_EQ(envelope.sender_device_id.str(), "device-uuid-sender");
    EXPECT_EQ(envelope.protocol_version, E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet);
    EXPECT_EQ(envelope.priority, MessagePriority::Urgent);
    EXPECT_TRUE(envelope.expires_at.has_value());
    ASSERT_EQ(envelope.per_device_envelopes.size(), 1u);
    EXPECT_EQ(envelope.per_device_envelopes[0].recipient_device_id.str(), "device-uuid-recp");

    E2EMessageEnvelope envelope_copy = envelope;
    EXPECT_EQ(envelope, envelope_copy);
}

} // namespace
} // namespace securecloud::messaging::domain
