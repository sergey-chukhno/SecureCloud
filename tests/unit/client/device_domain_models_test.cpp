#include "domain/device.hpp"
#include "domain/device_platform_info.hpp"
#include "domain/device_trust_level.hpp"
#include "domain/hardware_attestation_record.hpp"
#include "domain/pairing_challenge_payload.hpp"
#include "domain/short_authentication_string.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::client::domain::test {

TEST(DeviceTrustLevelTest, ToStringAndParseRoundTrip) {
    EXPECT_EQ(to_string(DeviceTrustLevel::Untrusted), "Untrusted");
    EXPECT_EQ(to_string(DeviceTrustLevel::PendingVerification), "PendingVerification");
    EXPECT_EQ(to_string(DeviceTrustLevel::VerifiedOutOfBand), "VerifiedOutOfBand");
    EXPECT_EQ(to_string(DeviceTrustLevel::HardwareAttested), "HardwareAttested");
    EXPECT_EQ(to_string(DeviceTrustLevel::EnterpriseAttested), "EnterpriseAttested");
    EXPECT_EQ(to_string(DeviceTrustLevel::Revoked), "Revoked");

    EXPECT_EQ(parse_device_trust_level("Untrusted"), DeviceTrustLevel::Untrusted);
    EXPECT_EQ(parse_device_trust_level("PendingVerification"), DeviceTrustLevel::PendingVerification);
    EXPECT_EQ(parse_device_trust_level("Pending"), DeviceTrustLevel::PendingVerification);
    EXPECT_EQ(parse_device_trust_level("VerifiedOutOfBand"), DeviceTrustLevel::VerifiedOutOfBand);
    EXPECT_EQ(parse_device_trust_level("Verified"), DeviceTrustLevel::VerifiedOutOfBand);
    EXPECT_EQ(parse_device_trust_level("HardwareAttested"), DeviceTrustLevel::HardwareAttested);
    EXPECT_EQ(parse_device_trust_level("Attested"), DeviceTrustLevel::HardwareAttested);
    EXPECT_EQ(parse_device_trust_level("EnterpriseAttested"), DeviceTrustLevel::EnterpriseAttested);
    EXPECT_EQ(parse_device_trust_level("Enterprise"), DeviceTrustLevel::EnterpriseAttested);
    EXPECT_EQ(parse_device_trust_level("Revoked"), DeviceTrustLevel::Revoked);

    EXPECT_EQ(parse_device_trust_level("InvalidLevel"), std::nullopt);
    EXPECT_EQ(parse_device_trust_level(""), std::nullopt);
}

TEST(DevicePlatformInfoTest, DefaultValuesAndFormattedSummary) {
    DevicePlatformInfo default_info;
    EXPECT_EQ(default_info.os_name(), "macOS");
    EXPECT_EQ(default_info.os_version(), "15.0");
    EXPECT_EQ(default_info.hardware_architecture(), "arm64");
    EXPECT_FALSE(default_info.secure_enclave_available());
    EXPECT_FALSE(default_info.hardware_key_enforced());

    DevicePlatformInfo custom_info("macOS", "15.1", "arm64", "MacBookPro18,1", true, true, "1.2.0");
    EXPECT_EQ(custom_info.device_model(), "MacBookPro18,1");
    EXPECT_TRUE(custom_info.secure_enclave_available());
    EXPECT_TRUE(custom_info.hardware_key_enforced());
    EXPECT_EQ(custom_info.client_version(), "1.2.0");

    std::string summary = custom_info.formatted_summary();
    EXPECT_NE(summary.find("MacBookPro18,1"), std::string::npos);
    EXPECT_NE(summary.find("macOS 15.1"), std::string::npos);
    EXPECT_NE(summary.find("arm64"), std::string::npos);
    EXPECT_NE(summary.find("FIDO2 Enforced"), std::string::npos);

    // Test enclave fallback without specific device model
    DevicePlatformInfo enclave_info("Windows", "11", "x86_64", "", true, false);
    std::string enc_summary = enclave_info.formatted_summary();
    EXPECT_NE(enc_summary.find("Apple M-Series Secure Enclave"), std::string::npos);
    EXPECT_NE(enc_summary.find("Windows 11"), std::string::npos);
}

TEST(DevicePlatformInfoTest, EqualityOperator) {
    DevicePlatformInfo a("macOS", "15.1", "arm64");
    DevicePlatformInfo b("macOS", "15.1", "arm64");
    DevicePlatformInfo c("Windows", "11", "x86_64");

    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);

    b.set_hardware_key_enforced(true);
    EXPECT_NE(a, b);
}

TEST(HardwareAttestationRecordTest, ConstructionAndAccessors) {
    auto now = std::chrono::system_clock::now();
    HardwareAttestationRecord record(AuthenticatorType::Platform, "00112233-4455-6677-8899-aabbccddeeff", "apple",
                                     "deadbeef01020304", now, true);

    EXPECT_EQ(record.authenticator_type(), AuthenticatorType::Platform);
    EXPECT_EQ(to_string(record.authenticator_type()), "Platform");
    EXPECT_EQ(to_string(AuthenticatorType::CrossPlatformSecurityKey), "CrossPlatformSecurityKey");
    EXPECT_EQ(record.aaguid(), "00112233-4455-6677-8899-aabbccddeeff");
    EXPECT_EQ(record.attestation_format(), "apple");
    EXPECT_EQ(record.attestation_statement_hex(), "deadbeef01020304");
    EXPECT_EQ(record.attested_at(), now);
    EXPECT_TRUE(record.is_verified());

    HardwareAttestationRecord other = record;
    EXPECT_EQ(record, other);

    other.set_verified(false);
    EXPECT_NE(record, other);
}

TEST(ShortAuthenticationStringTest, DerivationSymmetryAndFormatting) {
    std::vector<uint8_t> primary_key(32, 0x11);
    std::vector<uint8_t> companion_key(32, 0x22);
    std::string pairing_code = "PAIR-9482";

    auto sas1 = ShortAuthenticationString::from_handshake_material(primary_key, companion_key, pairing_code);
    auto sas2 = ShortAuthenticationString::from_handshake_material(companion_key, primary_key, pairing_code);

    // Derivation must be order-independent (symmetric)
    EXPECT_EQ(sas1, sas2);
    EXPECT_EQ(sas1.numeric_code(), sas2.numeric_code());
    EXPECT_EQ(sas1.visual_emojis(), sas2.visual_emojis());

    // 6-digit numeric code constraint
    EXPECT_EQ(sas1.numeric_code().size(), 6U);
    for (char c : sas1.numeric_code()) {
        EXPECT_TRUE(c >= '0' && c <= '9');
    }

    // Formatted code has space in middle: "XXX XXX"
    std::string formatted_code = sas1.formatted_code();
    EXPECT_EQ(formatted_code.size(), 7U);
    EXPECT_EQ(formatted_code[3], ' ');

    // 4 visual emojis
    EXPECT_EQ(sas1.visual_emojis().size(), 4U);
    for (const auto& emoji : sas1.visual_emojis()) {
        EXPECT_FALSE(emoji.empty());
    }

    std::string formatted_emojis = sas1.formatted_emojis();
    EXPECT_FALSE(formatted_emojis.empty());

    std::string formatted_text = sas1.formatted_text();
    EXPECT_NE(formatted_text.find(formatted_code), std::string::npos);
    EXPECT_NE(formatted_text.find('['), std::string::npos);
    EXPECT_NE(formatted_text.find(']'), std::string::npos);

    // Different pairing code must produce different SAS
    auto sas_diff = ShortAuthenticationString::from_handshake_material(primary_key, companion_key, "PAIR-DIFFERENT");
    EXPECT_NE(sas1, sas_diff);
}

TEST(PairingChallengePayloadTest, UriSerializationRoundTrip) {
    UserId user_id("usr-alice-01");
    DeviceId device_id("dev-laptop-02");
    std::vector<uint8_t> ephemeral_pk(32, 0xAA);
    std::string pairing_code = "948201";
    auto exp =
        std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now() + std::chrono::hours(1));
    std::string display_name = "MacBook Pro 16\"";

    PairingChallengePayload payload(user_id, device_id, ephemeral_pk, pairing_code, exp, display_name);

    EXPECT_FALSE(payload.is_expired());
    EXPECT_EQ(payload.version(), 1U);
    EXPECT_EQ(payload.user_id(), user_id);
    EXPECT_EQ(payload.device_id(), device_id);
    EXPECT_EQ(payload.ephemeral_public_key(), ephemeral_pk);
    EXPECT_EQ(payload.pairing_code(), pairing_code);
    EXPECT_EQ(payload.display_name(), display_name);

    std::string uri = payload.to_uri();
    EXPECT_NE(uri.find("securecloud://pair?"), std::string::npos);
    EXPECT_NE(uri.find("uid=usr-alice-01"), std::string::npos);
    EXPECT_NE(uri.find("did=dev-laptop-02"), std::string::npos);
    EXPECT_NE(uri.find("code=948201"), std::string::npos);
    EXPECT_NE(uri.find("pk="), std::string::npos);
    EXPECT_NE(uri.find("exp="), std::string::npos);

    // Deserialization round-trip
    auto parsed_res = PairingChallengePayload::from_uri(uri);
    ASSERT_TRUE(parsed_res.is_ok());

    const auto& parsed = parsed_res.value();
    EXPECT_EQ(parsed.version(), payload.version());
    EXPECT_EQ(parsed.user_id(), payload.user_id());
    EXPECT_EQ(parsed.device_id(), payload.device_id());
    EXPECT_EQ(parsed.ephemeral_public_key(), payload.ephemeral_public_key());
    EXPECT_EQ(parsed.pairing_code(), payload.pairing_code());
    EXPECT_EQ(parsed.expires_at(), payload.expires_at());
    EXPECT_EQ(parsed.display_name(), payload.display_name());
    EXPECT_EQ(parsed, payload);
}

TEST(PairingChallengePayloadTest, ExpirationDetection) {
    UserId user_id("usr-bob");
    DeviceId device_id("dev-bob-phone");
    std::vector<uint8_t> pk(32, 0x05);

    auto past_time = std::chrono::system_clock::now() - std::chrono::minutes(5);
    PairingChallengePayload expired_payload(user_id, device_id, pk, "code-123", past_time);
    EXPECT_TRUE(expired_payload.is_expired());

    auto future_time = std::chrono::system_clock::now() + std::chrono::minutes(5);
    PairingChallengePayload valid_payload(user_id, device_id, pk, "code-123", future_time);
    EXPECT_FALSE(valid_payload.is_expired());
}

TEST(PairingChallengePayloadTest, MalformedUriRejection) {
    // Bad scheme
    auto res1 = PairingChallengePayload::from_uri("https://securecloud.org/pair?v=1&uid=a&did=b&code=c&pk=00&exp=1");
    EXPECT_TRUE(res1.is_error());

    // Missing fields
    auto res2 = PairingChallengePayload::from_uri("securecloud://pair?v=1&uid=a&did=b");
    EXPECT_TRUE(res2.is_error());

    // Invalid version
    auto res3 =
        PairingChallengePayload::from_uri("securecloud://pair?v=abc&uid=a&did=b&code=c&pk="
                                          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&exp=100");
    EXPECT_TRUE(res3.is_error());

    // Invalid hex public key (not 32 bytes)
    auto res4 =
        PairingChallengePayload::from_uri("securecloud://pair?v=1&uid=a&did=b&code=c&pk=deadbeef&exp=1000000000");
    EXPECT_TRUE(res4.is_error());

    // Invalid hex characters in public key
    auto res5 = PairingChallengePayload::from_uri(
        "securecloud://pair?v=1&uid=a&did=b&code=c&pk="
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz&exp=1000000000");
    EXPECT_TRUE(res5.is_error());

    // Invalid expiration timestamp
    auto res6 = PairingChallengePayload::from_uri(
        "securecloud://pair?v=1&uid=a&did=b&code=c&pk="
        "0000000000000000000000000000000000000000000000000000000000000000&exp=notanumber");
    EXPECT_TRUE(res6.is_error());
}

TEST(EnrichedDeviceTest, BackwardCompatibilityAndExtendedFields) {
    DeviceId dev_id("dev-main-01");
    UserId user_id("usr-alice-01");
    CryptoIdentity identity;
    auto now = std::chrono::system_clock::now();

    // 1. Backward-compatible construction (existing 6 parameters)
    Device dev_compat(dev_id, user_id, "Primary Workstation", identity, DeviceAuthorizationStatus::Authorized, now);
    EXPECT_EQ(dev_compat.device_id(), dev_id);
    EXPECT_EQ(dev_compat.user_id(), user_id);
    EXPECT_EQ(dev_compat.display_name(), "Primary Workstation");
    EXPECT_EQ(dev_compat.status(), DeviceAuthorizationStatus::Authorized);
    EXPECT_EQ(dev_compat.trust_level(), DeviceTrustLevel::Untrusted);
    EXPECT_FALSE(dev_compat.is_hardware_backed());
    EXPECT_FALSE(dev_compat.hardware_attestation().has_value());

    // 2. Full construction with trust level and platform info
    DevicePlatformInfo platform("macOS", "15.1", "arm64", "MacBook Pro", true, true);
    HardwareAttestationRecord attestation(AuthenticatorType::Platform, "00112233-4455-6677-8899-aabbccddeeff");

    Device dev_full(dev_id, user_id, "SecOps Workstation", identity, DeviceAuthorizationStatus::Authorized, now,
                    DeviceTrustLevel::HardwareAttested, platform, true, attestation);

    EXPECT_EQ(dev_full.trust_level(), DeviceTrustLevel::HardwareAttested);
    EXPECT_TRUE(dev_full.is_hardware_backed());
    ASSERT_TRUE(dev_full.hardware_attestation().has_value());
    EXPECT_EQ(dev_full.hardware_attestation()->aaguid(), "00112233-4455-6677-8899-aabbccddeeff");
    EXPECT_EQ(dev_full.platform_info().device_model(), "MacBook Pro");

    // 3. Mutators
    dev_full.set_trust_level(DeviceTrustLevel::VerifiedOutOfBand);
    EXPECT_EQ(dev_full.trust_level(), DeviceTrustLevel::VerifiedOutOfBand);

    dev_full.set_hardware_backed(false);
    EXPECT_FALSE(dev_full.is_hardware_backed());

    dev_full.set_hardware_attestation(std::nullopt);
    EXPECT_FALSE(dev_full.hardware_attestation().has_value());
}

} // namespace securecloud::client::domain::test
