#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"

#include <gtest/gtest.h>
#include <thread>
#include <unordered_set>

namespace securecloud::auth::domain::test {

// --- 1. UUIDv7 Tests ---

TEST(DomainEntitiesTest, UuidV7GenerationProperties) {
    auto before_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());

    Uuid id = Uuid::generate_v7();

    auto after_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());

    EXPECT_FALSE(id.is_nil());
    EXPECT_TRUE(static_cast<bool>(id));
    EXPECT_EQ(id.version(), 7);
    EXPECT_EQ(id.variant(), 2);

    uint64_t ts = id.timestamp_ms();
    EXPECT_GE(ts, before_ms);
    EXPECT_LE(ts, after_ms);
}

TEST(DomainEntitiesTest, UuidV7MonotonicOrdering) {
    Uuid id1 = Uuid::generate_v7();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    Uuid id2 = Uuid::generate_v7();

    EXPECT_LT(id1, id2);
    EXPECT_LT(id1.timestamp_ms(), id2.timestamp_ms());
}

TEST(DomainEntitiesTest, UuidUniqueness) {
    std::unordered_set<Uuid> ids;
    ids.reserve(1000);

    for (int i = 0; i < 1000; ++i) {
        Uuid id = Uuid::generate_v7();
        auto [it, inserted] = ids.insert(id);
        EXPECT_TRUE(inserted) << "Duplicate UUIDv7 generated: " << id.to_string();
    }
}

TEST(DomainEntitiesTest, UuidParsingAndFormattingRoundTrip) {
    std::string canonical = "01923e20-336c-7e61-8280-4cf6d14878a1";
    auto parsed = Uuid::from_string(canonical);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->to_string(), canonical);

    // Case-insensitivity
    std::string upper = "01923E20-336C-7E61-8280-4CF6D14878A1";
    auto parsed_upper = Uuid::from_string(upper);
    ASSERT_TRUE(parsed_upper.has_value());
    EXPECT_EQ(*parsed, *parsed_upper);

    // Rejection of invalid UUID strings
    EXPECT_FALSE(Uuid::from_string("").has_value());
    EXPECT_FALSE(Uuid::from_string("short-uuid").has_value());
    EXPECT_FALSE(Uuid::from_string("01923e20_336c_7e61_8280_4cf6d14878a1").has_value());
    EXPECT_FALSE(Uuid::from_string("01923e20-336c-7e61-8280-4cf6d14878az").has_value());
    EXPECT_FALSE(Uuid::from_string("01923e20-336c-7e61-8280-4cf6d14878a11").has_value());
}

TEST(DomainEntitiesTest, NilUuidBehavior) {
    Uuid nil_id;
    EXPECT_TRUE(nil_id.is_nil());
    EXPECT_FALSE(static_cast<bool>(nil_id));
    EXPECT_EQ(nil_id.to_string(), "00000000-0000-0000-0000-000000000000");

    auto parsed_nil = Uuid::from_string("00000000-0000-0000-0000-000000000000");
    ASSERT_TRUE(parsed_nil.has_value());
    EXPECT_EQ(nil_id, *parsed_nil);
}

// --- 2. Enums Tests ---

TEST(DomainEntitiesTest, AllEnumsRoundTripStringConversions) {
    // AccountStatus
    EXPECT_EQ(parse_enum<AccountStatus>("Active"), AccountStatus::Active);
    EXPECT_EQ(parse_enum<AccountStatus>("Disabled"), AccountStatus::Disabled);
    EXPECT_EQ(parse_enum<AccountStatus>("INVALID"), std::nullopt);
    EXPECT_EQ(to_string(AccountStatus::Active), "Active");

    // DeviceStatus
    EXPECT_EQ(parse_enum<DeviceStatus>("Active"), DeviceStatus::Active);
    EXPECT_EQ(parse_enum<DeviceStatus>("Revoked"), DeviceStatus::Revoked);
    EXPECT_EQ(to_string(DeviceStatus::Revoked), "Revoked");

    // KeyType
    EXPECT_EQ(parse_enum<KeyType>("IDENTITY_SIGNING"), KeyType::IdentitySigning);
    EXPECT_EQ(parse_enum<KeyType>("SIGNED_PREKEY"), KeyType::SignedPrekey);
    EXPECT_EQ(to_string(KeyType::OneTimePrekey), "ONE_TIME_PREKEY");

    // KeyStatus
    EXPECT_EQ(parse_enum<KeyStatus>("Active"), KeyStatus::Active);
    EXPECT_EQ(parse_enum<KeyStatus>("Replaced"), KeyStatus::Replaced);
    EXPECT_EQ(to_string(KeyStatus::Replaced), "Replaced");

    // SessionStatus
    EXPECT_EQ(parse_enum<SessionStatus>("Active"), SessionStatus::Active);
    EXPECT_EQ(parse_enum<SessionStatus>("Expired"), SessionStatus::Expired);
    EXPECT_EQ(to_string(SessionStatus::Expired), "Expired");

    // AuthenticationLevel
    EXPECT_EQ(parse_enum<AuthenticationLevel>("PRIMARY_ONLY"), AuthenticationLevel::PrimaryOnly);
    EXPECT_EQ(parse_enum<AuthenticationLevel>("MFA_VERIFIED"), AuthenticationLevel::MfaVerified);
    EXPECT_EQ(to_string(AuthenticationLevel::MfaVerified), "MFA_VERIFIED");

    // TokenStatus
    EXPECT_EQ(parse_enum<TokenStatus>("Active"), TokenStatus::Active);
    EXPECT_EQ(parse_enum<TokenStatus>("Rotated"), TokenStatus::Rotated);
    EXPECT_EQ(to_string(TokenStatus::Rotated), "Rotated");

    // MfaFactorType
    EXPECT_EQ(parse_enum<MfaFactorType>("TOTP"), MfaFactorType::Totp);
    EXPECT_EQ(to_string(MfaFactorType::Totp), "TOTP");

    // MfaStatus
    EXPECT_EQ(parse_enum<MfaStatus>("Pending"), MfaStatus::Pending);
    EXPECT_EQ(parse_enum<MfaStatus>("Enabled"), MfaStatus::Enabled);
    EXPECT_EQ(to_string(MfaStatus::Enabled), "Enabled");

    // MfaChallengePurpose
    EXPECT_EQ(parse_enum<MfaChallengePurpose>("LOGIN"), MfaChallengePurpose::Login);
    EXPECT_EQ(parse_enum<MfaChallengePurpose>("STEP_UP"), MfaChallengePurpose::StepUp);
    EXPECT_EQ(to_string(MfaChallengePurpose::StepUp), "STEP_UP");

    // MfaChallengeStatus
    EXPECT_EQ(parse_enum<MfaChallengeStatus>("Pending"), MfaChallengeStatus::Pending);
    EXPECT_EQ(parse_enum<MfaChallengeStatus>("Completed"), MfaChallengeStatus::Completed);
    EXPECT_EQ(to_string(MfaChallengeStatus::Completed), "Completed");
}

// --- 3. Timestamp Tests ---

TEST(DomainEntitiesTest, TimestampUtcIso8601Conversions) {
    auto now = now_utc();
    std::string iso = to_iso8601_utc(now);
    EXPECT_FALSE(iso.empty());
    EXPECT_EQ(iso.back(), 'Z');

    auto parsed = from_iso8601_utc(iso);
    ASSERT_TRUE(parsed.has_value());

    auto orig_micros = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    auto parsed_micros = std::chrono::duration_cast<std::chrono::microseconds>(parsed->time_since_epoch()).count();
    EXPECT_EQ(orig_micros, parsed_micros);

    // Epoch ms conversion
    int64_t ms = to_epoch_ms(now);
    auto from_ms = from_epoch_ms(ms);
    EXPECT_EQ(to_epoch_ms(from_ms), ms);
}

// --- 4. Entity Defaults Tests ---

TEST(DomainEntitiesTest, EntityDefaultsInitialization) {
    UserEntity user;
    EXPECT_TRUE(user.user_id.is_nil());
    EXPECT_EQ(user.account_status, AccountStatus::Active);
    EXPECT_EQ(user.version, 1);
    EXPECT_EQ(user.password_algorithm, "argon2id");

    DeviceEntity device;
    EXPECT_TRUE(device.device_id.is_nil());
    EXPECT_EQ(device.device_status, DeviceStatus::Active);
    EXPECT_FALSE(device.revoked_at.has_value());
    EXPECT_FALSE(device.revocation_reason.has_value());

    RefreshTokenEntity token;
    EXPECT_EQ(token.token_status, TokenStatus::Active);
    EXPECT_FALSE(token.rotated_at.has_value());
    EXPECT_FALSE(token.replaced_by_token_id.has_value());

    MfaConfigurationEntity mfa;
    EXPECT_EQ(mfa.factor_type, MfaFactorType::Totp);
    EXPECT_EQ(mfa.status, MfaStatus::Pending);
    EXPECT_EQ(mfa.version, 1);

    MfaChallengeEntity challenge;
    EXPECT_EQ(challenge.challenge_purpose, MfaChallengePurpose::Login);
    EXPECT_EQ(challenge.challenge_status, MfaChallengeStatus::Pending);
    EXPECT_FALSE(challenge.completed_at.has_value());
}

} // namespace securecloud::auth::domain::test
