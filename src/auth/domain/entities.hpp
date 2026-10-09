#pragma once

#include "auth/domain/enums.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::auth::domain {

/// Represents an authoritative user account identity.
struct UserEntity {
    Uuid user_id;
    std::string credential_identifier;
    std::string password_verifier;
    std::string password_algorithm{"argon2id"};
    time_point password_updated_at;
    AccountStatus account_status{AccountStatus::Active};
    time_point created_at;
    time_point updated_at;
    uint64_t version{1};
};

/// Represents an enrolled user device endpoint.
struct DeviceEntity {
    Uuid device_id{};
    Uuid user_id{};
    DeviceStatus device_status{DeviceStatus::Active};
    time_point registered_at{};
    std::optional<time_point> revoked_at{std::nullopt};
    std::optional<std::string> revocation_reason{std::nullopt};
    time_point last_authenticated_at{};
    time_point created_at{};
    time_point updated_at{};
};

/// Represents public cryptographic material for end-to-end encryption.
struct DevicePublicKeyEntity {
    Uuid key_id{};
    Uuid device_id{};
    KeyType key_type{KeyType::IdentitySigning};
    std::vector<uint8_t> public_key{};
    KeyStatus key_status{KeyStatus::Active};
    time_point created_at{};
    std::optional<time_point> revoked_at{std::nullopt};
    std::optional<Uuid> replaced_by_key_id{std::nullopt};
    std::optional<std::vector<uint8_t>> signature{std::nullopt};
};

/// Represents an authoritative E2E prekey directory bundle for asynchronous key agreement (X3DH / PQXDH).
struct PrekeyBundle {
    Uuid device_id{};
    std::vector<uint8_t> identity_key{};
    std::string identity_key_fingerprint{};
    std::vector<uint8_t> signed_prekey{};
    std::vector<uint8_t> signed_prekey_signature{};
    std::optional<std::vector<uint8_t>> one_time_prekey{std::nullopt};
    std::optional<Uuid> one_time_prekey_id{std::nullopt};
    DeviceStatus device_status{DeviceStatus::Active};
    time_point signed_prekey_created_at{};
    int32_t remaining_one_time_prekeys{0};
};

/// Represents an authenticated session lifecycle record.
struct SessionEntity {
    Uuid session_id;
    Uuid user_id;
    Uuid device_id;
    SessionStatus session_status{SessionStatus::Active};
    AuthenticationLevel authentication_level{AuthenticationLevel::PrimaryOnly};
    time_point created_at;
    time_point expires_at;
    std::optional<time_point> revoked_at;
    time_point last_used_at;
};

/// Represents a single-use refresh token verifier record.
struct RefreshTokenEntity {
    Uuid refresh_token_id;
    Uuid session_id;
    Uuid device_id;
    std::string token_verifier;
    TokenStatus token_status{TokenStatus::Active};
    time_point issued_at;
    time_point expires_at;
    std::optional<time_point> revoked_at;
    std::optional<time_point> rotated_at;
    std::optional<Uuid> replaced_by_token_id;
};

/// Represents a multi-factor authentication enrollment configuration.
struct MfaConfigurationEntity {
    Uuid mfa_configuration_id;
    Uuid user_id;
    MfaFactorType factor_type{MfaFactorType::Totp};
    std::vector<uint8_t> encrypted_secret;
    MfaStatus status{MfaStatus::Pending};
    time_point created_at;
    std::optional<time_point> enabled_at;
    std::optional<time_point> disabled_at;
    uint64_t version{1};
};

/// Represents an in-flight MFA verification or step-up challenge.
struct MfaChallengeEntity {
    Uuid mfa_challenge_id;
    Uuid user_id;
    Uuid session_id;
    MfaChallengePurpose challenge_purpose{MfaChallengePurpose::Login};
    MfaChallengeStatus challenge_status{MfaChallengeStatus::Pending};
    time_point created_at;
    time_point expires_at;
    std::optional<time_point> completed_at;
};

} // namespace securecloud::auth::domain
