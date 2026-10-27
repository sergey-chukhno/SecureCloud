#include "files/domain/file_capability_serializer.hpp"

#include <gtest/gtest.h>

namespace securecloud::files {
namespace {

using auth::crypto::Ed25519TokenSigner;
using auth::crypto::Ed25519TokenVerifier;

FileAccessCapabilityClaims make_valid_claims() {
    auto now = std::chrono::system_clock::now();
    return FileAccessCapabilityClaims{
        .capability_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
        .user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
        .device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003",
        .file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36004",
        .file_version = 1,
        .operation = FileCapabilityOperation::Read,
        .issued_at = std::chrono::time_point_cast<std::chrono::seconds>(now),
        .expires_at = std::chrono::time_point_cast<std::chrono::seconds>(now + std::chrono::minutes(15)),
        .issuer = "securecloud-files"};
}

TEST(FileCapabilitySerializerTest, RoundTripSerializationAndVerification) {
    Ed25519TokenSigner signer("sc-files-v1");
    auto verifier = Ed25519TokenVerifier::from_signer(signer);

    auto claims = make_valid_claims();
    std::string token = FileCapabilitySerializer::serialize(claims, signer);
    EXPECT_FALSE(token.empty());

    std::string error;
    auto parsed = FileCapabilitySerializer::deserialize_and_verify(token, *verifier, &error);
    ASSERT_TRUE(parsed.has_value()) << "Verification failed: " << error;

    EXPECT_EQ(parsed->capability_id, claims.capability_id);
    EXPECT_EQ(parsed->user_id, claims.user_id);
    EXPECT_EQ(parsed->device_id, claims.device_id);
    EXPECT_EQ(parsed->file_id, claims.file_id);
    EXPECT_EQ(parsed->file_version, claims.file_version);
    EXPECT_EQ(parsed->operation, claims.operation);
    EXPECT_EQ(parsed->issued_at, claims.issued_at);
    EXPECT_EQ(parsed->expires_at, claims.expires_at);
    EXPECT_EQ(parsed->issuer, claims.issuer);
}

TEST(FileCapabilitySerializerTest, RejectsTamperedSignature) {
    Ed25519TokenSigner signer("sc-files-v1");
    auto verifier = Ed25519TokenVerifier::from_signer(signer);

    auto claims = make_valid_claims();
    std::string token = FileCapabilitySerializer::serialize(claims, signer);

    // Tamper with last signature character
    token.back() = (token.back() == 'A') ? 'B' : 'A';

    std::string error;
    auto parsed = FileCapabilitySerializer::deserialize_and_verify(token, *verifier, &error);
    EXPECT_FALSE(parsed.has_value());
    EXPECT_NE(error.find("signature"), std::string::npos);
}

TEST(FileCapabilitySerializerTest, RejectsTamperedPayload) {
    Ed25519TokenSigner signer("sc-files-v1");
    auto verifier = Ed25519TokenVerifier::from_signer(signer);

    auto claims = make_valid_claims();
    std::string token = FileCapabilitySerializer::serialize(claims, signer);

    // Split token and alter payload
    auto first_dot = token.find('.');
    auto second_dot = token.find('.', first_dot + 1);
    ASSERT_NE(first_dot, std::string::npos);
    ASSERT_NE(second_dot, std::string::npos);

    std::string header_b64 = token.substr(0, first_dot);
    std::string payload_b64 = token.substr(first_dot + 1, second_dot - first_dot - 1);
    std::string sig_b64 = token.substr(second_dot + 1);

    // Corrupt one character in payload
    payload_b64[5] = (payload_b64[5] == 'X') ? 'Y' : 'X';
    std::string tampered_token = header_b64 + "." + payload_b64 + "." + sig_b64;

    std::string error;
    auto parsed = FileCapabilitySerializer::deserialize_and_verify(tampered_token, *verifier, &error);
    EXPECT_FALSE(parsed.has_value());
    EXPECT_FALSE(error.empty());
}

TEST(FileCapabilitySerializerTest, RejectsWrongVerifierKey) {
    Ed25519TokenSigner signer1("sc-files-v1");
    Ed25519TokenSigner signer2("sc-files-v2");
    auto verifier2 = Ed25519TokenVerifier::from_signer(signer2);

    auto claims = make_valid_claims();
    std::string token = FileCapabilitySerializer::serialize(claims, signer1);

    std::string error;
    auto parsed = FileCapabilitySerializer::deserialize_and_verify(token, *verifier2, &error);
    EXPECT_FALSE(parsed.has_value());
    EXPECT_NE(error.find("signature"), std::string::npos);
}

TEST(FileCapabilitySerializerTest, RejectsMalformedTokens) {
    Ed25519TokenSigner signer("sc-files-v1");
    auto verifier = Ed25519TokenVerifier::from_signer(signer);

    std::string error;

    // No dots
    EXPECT_FALSE(FileCapabilitySerializer::deserialize_and_verify("not_a_valid_token", *verifier, &error));

    // One dot only
    EXPECT_FALSE(FileCapabilitySerializer::deserialize_and_verify("header.payload", *verifier, &error));

    // Three dots (four parts)
    EXPECT_FALSE(FileCapabilitySerializer::deserialize_and_verify("a.b.c.d", *verifier, &error));

    // Empty segments
    EXPECT_FALSE(FileCapabilitySerializer::deserialize_and_verify(".payload.sig", *verifier, &error));
    EXPECT_FALSE(FileCapabilitySerializer::deserialize_and_verify("header..sig", *verifier, &error));
    EXPECT_FALSE(FileCapabilitySerializer::deserialize_and_verify("header.payload.", *verifier, &error));
}

TEST(FileCapabilitySerializerTest, RejectsUnknownOperation) {
    Ed25519TokenSigner signer("sc-files-v1");
    auto verifier = Ed25519TokenVerifier::from_signer(signer);

    // Construct valid header and payload with invalid op
    std::string header_json = R"({"alg":"EdDSA","typ":"sc-file-cap/v1","kid":"test"})";
    std::string payload_json = R"({
        "cap_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
        "uid": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
        "did": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003",
        "fid": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36004",
        "ver": 1,
        "op": "super_admin_bypass",
        "iat": 1729938000,
        "exp": 1729938900,
        "iss": "securecloud-files"
    })";

    std::string h_b64 = auth::crypto::Base64Url::encode(header_json);
    std::string p_b64 = auth::crypto::Base64Url::encode(payload_json);
    std::string signing_input = h_b64 + "." + p_b64;
    std::string sig_b64 = signer.sign(signing_input);
    std::string token = signing_input + "." + sig_b64;

    std::string error;
    auto parsed = FileCapabilitySerializer::deserialize_and_verify(token, *verifier, &error);
    EXPECT_FALSE(parsed.has_value());
    EXPECT_NE(error.find("Unknown file capability operation"), std::string::npos);
}

} // namespace
} // namespace securecloud::files
