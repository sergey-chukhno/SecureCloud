#pragma once

#include "domain/enums.hpp"
#include "domain/timestamp.hpp"
#include "domain/uuid.hpp"

#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::auth::domain {

/// Types of security audit events emitted by primary authentication flows.
enum class AuditEventType {
    LoginSucceeded,
    LoginFailed,
    AccountDisabledAccessAttempt,
    SessionRevoked,
    SessionExpiredAttempt,
    SessionRevokedAttempt,
    TokenRefreshed,
    TokenReuseDetected,
    MfaEnrollmentInitiated,
    MfaEnrollmentConfirmed,
    MfaDisabled,
    MfaChallengeCreated,
    MfaChallengeSucceeded,
    MfaChallengeFailed,
    MfaRecoveryCodeUsed,
    DeviceEnrolled,
    DevicePairingInitiated,
    DeviceAuthorized,
    DeviceRevoked,
    PrekeysUpdated,
    SignedPrekeyRotated
};

[[nodiscard]] inline constexpr std::string_view to_string(AuditEventType type) noexcept {
    switch (type) {
    case AuditEventType::LoginSucceeded:
        return "auth.login.succeeded";
    case AuditEventType::LoginFailed:
        return "auth.login.failed";
    case AuditEventType::AccountDisabledAccessAttempt:
        return "auth.account.disabled_attempt";
    case AuditEventType::SessionRevoked:
        return "auth.session.revoked";
    case AuditEventType::SessionExpiredAttempt:
        return "auth.session.expired_attempt";
    case AuditEventType::SessionRevokedAttempt:
        return "auth.session.revoked_attempt";
    case AuditEventType::TokenRefreshed:
        return "auth.token.refreshed";
    case AuditEventType::TokenReuseDetected:
        return "auth.token.reuse_detected";
    case AuditEventType::MfaEnrollmentInitiated:
        return "auth.mfa.enrollment_initiated";
    case AuditEventType::MfaEnrollmentConfirmed:
        return "auth.mfa.enrollment_confirmed";
    case AuditEventType::MfaDisabled:
        return "auth.mfa.disabled";
    case AuditEventType::MfaChallengeCreated:
        return "auth.mfa.challenge_created";
    case AuditEventType::MfaChallengeSucceeded:
        return "auth.mfa.challenge_succeeded";
    case AuditEventType::MfaChallengeFailed:
        return "auth.mfa.challenge_failed";
    case AuditEventType::MfaRecoveryCodeUsed:
        return "auth.mfa.recovery_code_used";
    case AuditEventType::DeviceEnrolled:
        return "auth.device.enrolled";
    case AuditEventType::DevicePairingInitiated:
        return "auth.device.pairing_initiated";
    case AuditEventType::DeviceAuthorized:
        return "auth.device.authorized";
    case AuditEventType::DeviceRevoked:
        return "auth.device.revoked";
    case AuditEventType::PrekeysUpdated:
        return "auth.device.prekeys_updated";
    case AuditEventType::SignedPrekeyRotated:
        return "auth.device.signed_prekey_rotated";
    }
    return "auth.unknown";
}

/// Structured record representing an immutable security audit event.
/// Invariant: Passwords, plaintext credentials, or cryptographic keys MUST NEVER
/// be members of this struct or serialized into its JSON output.
struct AuditEvent {
    Uuid event_id;
    AuditEventType event_type;
    time_point timestamp;
    std::optional<Uuid> user_id{std::nullopt};
    std::string credential_identifier{};
    std::optional<Uuid> device_id{std::nullopt};
    std::optional<Uuid> session_id{std::nullopt};
    std::string client_ip{"unknown"};
    std::string failure_reason{};

    /// Serializes the audit event into a standardized JSON string.
    [[nodiscard]] std::string to_json() const {
        nlohmann::json j;
        j["event_id"] = event_id.to_string();
        j["event_type"] = to_string(event_type);
        j["timestamp"] = to_iso8601(timestamp);
        j["credential_identifier"] = credential_identifier;
        j["client_ip"] = client_ip;

        if (user_id.has_value()) {
            j["user_id"] = user_id->to_string();
        } else {
            j["user_id"] = nullptr;
        }

        if (device_id.has_value()) {
            j["device_id"] = device_id->to_string();
        } else {
            j["device_id"] = nullptr;
        }

        if (session_id.has_value()) {
            j["session_id"] = session_id->to_string();
        } else {
            j["session_id"] = nullptr;
        }

        if (!failure_reason.empty()) {
            j["failure_reason"] = failure_reason;
        } else {
            j["failure_reason"] = nullptr;
        }

        return j.dump();
    }

    static AuditEvent login_succeeded(const Uuid& user_id, std::string_view credential_identifier,
                                      const Uuid& device_id, const Uuid& session_id,
                                      std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::LoginSucceeded;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.credential_identifier = std::string(credential_identifier);
        ev.device_id = device_id;
        ev.session_id = session_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        ev.failure_reason = "";
        return ev;
    }

    static AuditEvent login_failed(std::string_view credential_identifier, std::string_view failure_reason,
                                   std::optional<Uuid> user_id = std::nullopt,
                                   std::optional<Uuid> device_id = std::nullopt,
                                   std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::LoginFailed;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.credential_identifier = std::string(credential_identifier);
        ev.device_id = device_id;
        ev.session_id = std::nullopt;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        ev.failure_reason = std::string(failure_reason);
        return ev;
    }

    static AuditEvent account_disabled_attempt(std::optional<Uuid> user_id, std::string_view credential_identifier,
                                               std::string_view failure_reason,
                                               std::optional<Uuid> device_id = std::nullopt,
                                               std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::AccountDisabledAccessAttempt;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.credential_identifier = std::string(credential_identifier);
        ev.device_id = device_id;
        ev.session_id = std::nullopt;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        ev.failure_reason = std::string(failure_reason);
        return ev;
    }

    static AuditEvent session_revoked(const Uuid& session_id, const Uuid& user_id, const Uuid& device_id,
                                      std::string_view reason, std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::SessionRevoked;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.credential_identifier = "";
        ev.device_id = device_id;
        ev.session_id = session_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        ev.failure_reason = std::string(reason);
        return ev;
    }

    static AuditEvent session_expired_attempt(const Uuid& session_id, std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::SessionExpiredAttempt;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = std::nullopt;
        ev.credential_identifier = "";
        ev.device_id = std::nullopt;
        ev.session_id = session_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        ev.failure_reason = "Session expired";
        return ev;
    }

    static AuditEvent session_revoked_attempt(const Uuid& session_id, std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::SessionRevokedAttempt;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = std::nullopt;
        ev.credential_identifier = "";
        ev.device_id = std::nullopt;
        ev.session_id = session_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        ev.failure_reason = "Session revoked";
        return ev;
    }

    static AuditEvent token_refreshed(const Uuid& session_id, const Uuid& user_id, const Uuid& device_id,
                                      std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::TokenRefreshed;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.credential_identifier = "";
        ev.device_id = device_id;
        ev.session_id = session_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        ev.failure_reason = "";
        return ev;
    }

    static AuditEvent token_reuse_detected(const Uuid& session_id, const Uuid& device_id,
                                           std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::TokenReuseDetected;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = std::nullopt;
        ev.credential_identifier = "";
        ev.device_id = device_id;
        ev.session_id = session_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        ev.failure_reason = "Compromised refresh token reuse detected; session revoked";
        return ev;
    }

    static AuditEvent mfa_enrollment_initiated(const Uuid& user_id, std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::MfaEnrollmentInitiated;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }

    static AuditEvent mfa_enrollment_confirmed(const Uuid& user_id, std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::MfaEnrollmentConfirmed;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }

    static AuditEvent mfa_disabled(const Uuid& user_id, std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::MfaDisabled;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }

    static AuditEvent mfa_challenge_created(const Uuid& user_id, const Uuid& session_id,
                                            std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::MfaChallengeCreated;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.session_id = session_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }

    static AuditEvent mfa_challenge_succeeded(const Uuid& user_id, const Uuid& session_id,
                                              std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::MfaChallengeSucceeded;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.session_id = session_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }

    static AuditEvent mfa_challenge_failed(const Uuid& user_id, const Uuid& session_id, std::string_view failure_reason,
                                           std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::MfaChallengeFailed;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.session_id = session_id;
        ev.failure_reason = std::string(failure_reason);
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }

    static AuditEvent mfa_recovery_code_used(const Uuid& user_id, const Uuid& session_id,
                                             std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::MfaRecoveryCodeUsed;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.session_id = session_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }

    static AuditEvent device_enrolled(const Uuid& user_id, const Uuid& device_id, bool active,
                                      std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::DeviceEnrolled;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.device_id = device_id;
        ev.failure_reason = active ? "ACTIVE" : "PENDING_AUTHORIZATION";
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }

    static AuditEvent device_pairing_initiated(const Uuid& user_id, const Uuid& device_id,
                                               std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::DevicePairingInitiated;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.device_id = device_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }

    static AuditEvent device_authorized(const Uuid& user_id, const Uuid& device_id,
                                        std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::DeviceAuthorized;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.device_id = device_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }

    static AuditEvent device_revoked(const Uuid& user_id, const Uuid& device_id, std::string_view reason,
                                     std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::DeviceRevoked;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.device_id = device_id;
        ev.failure_reason = std::string(reason);
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }

    static AuditEvent prekeys_updated(const Uuid& user_id, const Uuid& device_id, int32_t active_count,
                                      std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::PrekeysUpdated;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.device_id = device_id;
        ev.failure_reason = "ACTIVE_COUNT=" + std::to_string(active_count);
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }

    static AuditEvent signed_prekey_rotated(const Uuid& user_id, const Uuid& device_id,
                                            std::string_view client_ip = "unknown") {
        AuditEvent ev;
        ev.event_id = Uuid::generate_v7();
        ev.event_type = AuditEventType::SignedPrekeyRotated;
        ev.timestamp = std::chrono::system_clock::now();
        ev.user_id = user_id;
        ev.device_id = device_id;
        ev.client_ip = client_ip.empty() ? "unknown" : std::string(client_ip);
        return ev;
    }
};

} // namespace securecloud::auth::domain
