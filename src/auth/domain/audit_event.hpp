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
    TokenReuseDetected
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
};

} // namespace securecloud::auth::domain
