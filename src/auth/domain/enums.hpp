#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace securecloud::auth::domain {

// --- 1. AccountStatus ---
enum class AccountStatus {
    Active,
    Disabled,
};

[[nodiscard]] constexpr std::string_view to_string(AccountStatus status) noexcept {
    switch (status) {
    case AccountStatus::Active:
        return "Active";
    case AccountStatus::Disabled:
        return "Disabled";
    }
    return "Unknown";
}

template <typename T> [[nodiscard]] std::optional<T> parse_enum(std::string_view str) noexcept;

template <> [[nodiscard]] inline std::optional<AccountStatus> parse_enum<AccountStatus>(std::string_view str) noexcept {
    if (str == "Active" || str == "ACTIVE") {
        return AccountStatus::Active;
    }
    if (str == "Disabled" || str == "DISABLED") {
        return AccountStatus::Disabled;
    }
    return std::nullopt;
}

// --- 2. DeviceStatus ---
enum class DeviceStatus {
    Active,
    Revoked,
};

[[nodiscard]] constexpr std::string_view to_string(DeviceStatus status) noexcept {
    switch (status) {
    case DeviceStatus::Active:
        return "Active";
    case DeviceStatus::Revoked:
        return "Revoked";
    }
    return "Unknown";
}

template <> [[nodiscard]] inline std::optional<DeviceStatus> parse_enum<DeviceStatus>(std::string_view str) noexcept {
    if (str == "Active" || str == "ACTIVE") {
        return DeviceStatus::Active;
    }
    if (str == "Revoked" || str == "REVOKED") {
        return DeviceStatus::Revoked;
    }
    return std::nullopt;
}

// --- 3. KeyType ---
enum class KeyType {
    IdentitySigning,
    IdentityAgreement,
    SignedPrekey,
    OneTimePrekey,
};

[[nodiscard]] constexpr std::string_view to_string(KeyType type) noexcept {
    switch (type) {
    case KeyType::IdentitySigning:
        return "IDENTITY_SIGNING";
    case KeyType::IdentityAgreement:
        return "IDENTITY_AGREEMENT";
    case KeyType::SignedPrekey:
        return "SIGNED_PREKEY";
    case KeyType::OneTimePrekey:
        return "ONE_TIME_PREKEY";
    }
    return "UNKNOWN";
}

template <> [[nodiscard]] inline std::optional<KeyType> parse_enum<KeyType>(std::string_view str) noexcept {
    if (str == "IDENTITY_SIGNING" || str == "IdentitySigning") {
        return KeyType::IdentitySigning;
    }
    if (str == "IDENTITY_AGREEMENT" || str == "IdentityAgreement") {
        return KeyType::IdentityAgreement;
    }
    if (str == "SIGNED_PREKEY" || str == "SignedPrekey") {
        return KeyType::SignedPrekey;
    }
    if (str == "ONE_TIME_PREKEY" || str == "OneTimePrekey") {
        return KeyType::OneTimePrekey;
    }
    return std::nullopt;
}

// --- 4. KeyStatus ---
enum class KeyStatus {
    Active,
    Revoked,
    Replaced,
};

[[nodiscard]] constexpr std::string_view to_string(KeyStatus status) noexcept {
    switch (status) {
    case KeyStatus::Active:
        return "Active";
    case KeyStatus::Revoked:
        return "Revoked";
    case KeyStatus::Replaced:
        return "Replaced";
    }
    return "Unknown";
}

template <> [[nodiscard]] inline std::optional<KeyStatus> parse_enum<KeyStatus>(std::string_view str) noexcept {
    if (str == "Active" || str == "ACTIVE") {
        return KeyStatus::Active;
    }
    if (str == "Revoked" || str == "REVOKED") {
        return KeyStatus::Revoked;
    }
    if (str == "Replaced" || str == "REPLACED") {
        return KeyStatus::Replaced;
    }
    return std::nullopt;
}

// --- 5. SessionStatus ---
enum class SessionStatus {
    Active,
    Revoked,
    Expired,
};

[[nodiscard]] constexpr std::string_view to_string(SessionStatus status) noexcept {
    switch (status) {
    case SessionStatus::Active:
        return "Active";
    case SessionStatus::Revoked:
        return "Revoked";
    case SessionStatus::Expired:
        return "Expired";
    }
    return "Unknown";
}

[[nodiscard]] constexpr bool is_terminal(SessionStatus status) noexcept {
    switch (status) {
    case SessionStatus::Active:
        return false;
    case SessionStatus::Revoked:
    case SessionStatus::Expired:
        return true;
    }
    return false;
}

[[nodiscard]] constexpr bool can_transition(SessionStatus from, SessionStatus to) noexcept {
    if (from == to) {
        return true;
    }
    switch (from) {
    case SessionStatus::Active:
        return to == SessionStatus::Revoked || to == SessionStatus::Expired;
    case SessionStatus::Revoked:
    case SessionStatus::Expired:
        return false;
    }
    return false;
}

template <> [[nodiscard]] inline std::optional<SessionStatus> parse_enum<SessionStatus>(std::string_view str) noexcept {
    if (str == "Active" || str == "ACTIVE") {
        return SessionStatus::Active;
    }
    if (str == "Revoked" || str == "REVOKED") {
        return SessionStatus::Revoked;
    }
    if (str == "Expired" || str == "EXPIRED") {
        return SessionStatus::Expired;
    }
    return std::nullopt;
}

// --- 6. AuthenticationLevel ---
enum class AuthenticationLevel {
    PrimaryOnly,
    MfaVerified,
};

[[nodiscard]] constexpr std::string_view to_string(AuthenticationLevel level) noexcept {
    switch (level) {
    case AuthenticationLevel::PrimaryOnly:
        return "PRIMARY_ONLY";
    case AuthenticationLevel::MfaVerified:
        return "MFA_VERIFIED";
    }
    return "UNKNOWN";
}

template <>
[[nodiscard]] inline std::optional<AuthenticationLevel> parse_enum<AuthenticationLevel>(std::string_view str) noexcept {
    if (str == "PRIMARY_ONLY" || str == "PrimaryOnly") {
        return AuthenticationLevel::PrimaryOnly;
    }
    if (str == "MFA_VERIFIED" || str == "MfaVerified") {
        return AuthenticationLevel::MfaVerified;
    }
    return std::nullopt;
}

// --- 7. TokenStatus ---
enum class TokenStatus {
    Active,
    Rotated,
    Revoked,
    Expired,
};

[[nodiscard]] constexpr std::string_view to_string(TokenStatus status) noexcept {
    switch (status) {
    case TokenStatus::Active:
        return "Active";
    case TokenStatus::Rotated:
        return "Rotated";
    case TokenStatus::Revoked:
        return "Revoked";
    case TokenStatus::Expired:
        return "Expired";
    }
    return "Unknown";
}

template <> [[nodiscard]] inline std::optional<TokenStatus> parse_enum<TokenStatus>(std::string_view str) noexcept {
    if (str == "Active" || str == "ACTIVE") {
        return TokenStatus::Active;
    }
    if (str == "Rotated" || str == "ROTATED") {
        return TokenStatus::Rotated;
    }
    if (str == "Revoked" || str == "REVOKED") {
        return TokenStatus::Revoked;
    }
    if (str == "Expired" || str == "EXPIRED") {
        return TokenStatus::Expired;
    }
    return std::nullopt;
}

// --- 8. MfaFactorType ---
enum class MfaFactorType {
    Totp,
    WebAuthn,
};

[[nodiscard]] constexpr std::string_view to_string(MfaFactorType factor) noexcept {
    switch (factor) {
    case MfaFactorType::Totp:
        return "TOTP";
    case MfaFactorType::WebAuthn:
        return "WebAuthn";
    }
    return "UNKNOWN";
}

template <> [[nodiscard]] inline std::optional<MfaFactorType> parse_enum<MfaFactorType>(std::string_view str) noexcept {
    if (str == "TOTP" || str == "Totp") {
        return MfaFactorType::Totp;
    }
    if (str == "WEBAUTHN" || str == "WebAuthn" || str == "webauthn") {
        return MfaFactorType::WebAuthn;
    }
    return std::nullopt;
}

// --- 9. MfaStatus ---
enum class MfaStatus {
    Pending,
    Enabled,
    Disabled,
};

[[nodiscard]] constexpr std::string_view to_string(MfaStatus status) noexcept {
    switch (status) {
    case MfaStatus::Pending:
        return "Pending";
    case MfaStatus::Enabled:
        return "Enabled";
    case MfaStatus::Disabled:
        return "Disabled";
    }
    return "Unknown";
}

template <> [[nodiscard]] inline std::optional<MfaStatus> parse_enum<MfaStatus>(std::string_view str) noexcept {
    if (str == "Pending" || str == "PENDING") {
        return MfaStatus::Pending;
    }
    if (str == "Enabled" || str == "ENABLED") {
        return MfaStatus::Enabled;
    }
    if (str == "Disabled" || str == "DISABLED") {
        return MfaStatus::Disabled;
    }
    return std::nullopt;
}

// --- 10. MfaChallengePurpose ---
enum class MfaChallengePurpose {
    Login,
    StepUp,
};

[[nodiscard]] constexpr std::string_view to_string(MfaChallengePurpose purpose) noexcept {
    switch (purpose) {
    case MfaChallengePurpose::Login:
        return "LOGIN";
    case MfaChallengePurpose::StepUp:
        return "STEP_UP";
    }
    return "UNKNOWN";
}

template <>
[[nodiscard]] inline std::optional<MfaChallengePurpose> parse_enum<MfaChallengePurpose>(std::string_view str) noexcept {
    if (str == "LOGIN" || str == "Login") {
        return MfaChallengePurpose::Login;
    }
    if (str == "STEP_UP" || str == "StepUp") {
        return MfaChallengePurpose::StepUp;
    }
    return std::nullopt;
}

// --- 11. MfaChallengeStatus ---
enum class MfaChallengeStatus {
    Pending,
    Completed,
    Expired,
    Failed,
};

[[nodiscard]] constexpr std::string_view to_string(MfaChallengeStatus status) noexcept {
    switch (status) {
    case MfaChallengeStatus::Pending:
        return "Pending";
    case MfaChallengeStatus::Completed:
        return "Completed";
    case MfaChallengeStatus::Expired:
        return "Expired";
    case MfaChallengeStatus::Failed:
        return "Failed";
    }
    return "Unknown";
}

template <>
[[nodiscard]] inline std::optional<MfaChallengeStatus> parse_enum<MfaChallengeStatus>(std::string_view str) noexcept {
    if (str == "Pending" || str == "PENDING") {
        return MfaChallengeStatus::Pending;
    }
    if (str == "Completed" || str == "COMPLETED") {
        return MfaChallengeStatus::Completed;
    }
    if (str == "Expired" || str == "EXPIRED") {
        return MfaChallengeStatus::Expired;
    }
    if (str == "Failed" || str == "FAILED") {
        return MfaChallengeStatus::Failed;
    }
    return std::nullopt;
}

} // namespace securecloud::auth::domain
