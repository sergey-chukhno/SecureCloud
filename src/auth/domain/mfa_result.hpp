#pragma once

#include "auth/domain/enums.hpp"
#include "auth/domain/secret_mfa_string.hpp"
#include "auth/domain/uuid.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace securecloud::auth::domain {

/**
 * @brief Payload returned upon successful initiation of MFA enrollment.
 */
struct MfaEnrollmentInitiation {
    Uuid mfa_configuration_id;
    SecretMfaString base32_secret;
    std::string otpauth_uri;
};

/**
 * @brief Status codes for MFA enrollment confirmation.
 */
enum class MfaEnrollmentStatus {
    Success,
    InvalidCode,
    ConfigurationNotFound,
    AlreadyEnabled,
    Expired
};

/**
 * @brief Result of confirming an MFA enrollment attempt with the initial code.
 */
struct MfaEnrollmentConfirmationResult {
    MfaEnrollmentStatus status{MfaEnrollmentStatus::InvalidCode};
    std::vector<std::string> recovery_codes; ///< Single-use recovery codes, provided ONCE
    std::string error_message;

    [[nodiscard]] bool is_success() const noexcept { return status == MfaEnrollmentStatus::Success; }

    static MfaEnrollmentConfirmationResult success(std::vector<std::string> recovery_codes) {
        return {MfaEnrollmentStatus::Success, std::move(recovery_codes), {}};
    }

    static MfaEnrollmentConfirmationResult failure(MfaEnrollmentStatus status, std::string message) {
        return {status, {}, std::move(message)};
    }
};

/**
 * @brief Status codes for MFA challenge verification.
 */
enum class MfaChallengeVerificationStatus {
    Success,
    InvalidCode,
    ExpiredChallenge,
    MaxAttemptsExceeded,
    ChallengeFailed,
    AlreadyCompleted
};

/**
 * @brief Result of solving an MFA challenge during login or sensitive step-up.
 */
struct MfaChallengeVerificationResult {
    MfaChallengeVerificationStatus status{MfaChallengeVerificationStatus::InvalidCode};
    uint64_t matched_time_step = 0; ///< For TOTP anti-replay tracking
    std::string error_message;

    [[nodiscard]] bool is_success() const noexcept {
        return status == MfaChallengeVerificationStatus::Success;
    }

    static MfaChallengeVerificationResult success(uint64_t time_step = 0) {
        return {MfaChallengeVerificationStatus::Success, time_step, {}};
    }

    static MfaChallengeVerificationResult failure(MfaChallengeVerificationStatus status, std::string message) {
        return {status, 0, std::move(message)};
    }
};

} // namespace securecloud::auth::domain
