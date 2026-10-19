#pragma once

#include "domain/entities.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::auth::domain {

/// Status enumeration for session validation operations.
enum class SessionValidationStatus { Valid, NotFound, Revoked, Expired, DeviceMismatch, DeviceRevoked, InternalError };

[[nodiscard]] inline constexpr std::string_view to_string(SessionValidationStatus status) noexcept {
    switch (status) {
    case SessionValidationStatus::Valid:
        return "Valid";
    case SessionValidationStatus::NotFound:
        return "NotFound";
    case SessionValidationStatus::Revoked:
        return "Revoked";
    case SessionValidationStatus::Expired:
        return "Expired";
    case SessionValidationStatus::DeviceMismatch:
        return "DeviceMismatch";
    case SessionValidationStatus::DeviceRevoked:
        return "DeviceRevoked";
    case SessionValidationStatus::InternalError:
        return "InternalError";
    }
    return "Unknown";
}

/// Strongly-typed result model for session validation.
struct SessionValidationResult {
    SessionValidationStatus status{SessionValidationStatus::NotFound};
    std::optional<SessionEntity> session{std::nullopt};
    std::string diagnostic_message{};

    [[nodiscard]] bool is_valid() const noexcept { return status == SessionValidationStatus::Valid; }

    static SessionValidationResult valid(SessionEntity session_entity) {
        SessionValidationResult res;
        res.status = SessionValidationStatus::Valid;
        res.session = std::move(session_entity);
        res.diagnostic_message = "Session is active and valid";
        return res;
    }

    static SessionValidationResult not_found(std::string message = "Session not found") {
        SessionValidationResult res;
        res.status = SessionValidationStatus::NotFound;
        res.session = std::nullopt;
        res.diagnostic_message = std::move(message);
        return res;
    }

    static SessionValidationResult revoked(std::string message = "Session has been revoked") {
        SessionValidationResult res;
        res.status = SessionValidationStatus::Revoked;
        res.session = std::nullopt;
        res.diagnostic_message = std::move(message);
        return res;
    }

    static SessionValidationResult expired(std::string message = "Session has expired") {
        SessionValidationResult res;
        res.status = SessionValidationStatus::Expired;
        res.session = std::nullopt;
        res.diagnostic_message = std::move(message);
        return res;
    }

    static SessionValidationResult device_mismatch(std::string message = "Device does not match session") {
        SessionValidationResult res;
        res.status = SessionValidationStatus::DeviceMismatch;
        res.session = std::nullopt;
        res.diagnostic_message = std::move(message);
        return res;
    }

    static SessionValidationResult device_revoked(std::string message = "Associated device is revoked") {
        SessionValidationResult res;
        res.status = SessionValidationStatus::DeviceRevoked;
        res.session = std::nullopt;
        res.diagnostic_message = std::move(message);
        return res;
    }

    static SessionValidationResult internal_error(std::string message = "Internal error during session validation") {
        SessionValidationResult res;
        res.status = SessionValidationStatus::InternalError;
        res.session = std::nullopt;
        res.diagnostic_message = std::move(message);
        return res;
    }
};

/// Status enumeration for session revocation operations.
enum class SessionRevocationStatus { Success, NotFound, AlreadyRevoked, InternalError };

[[nodiscard]] inline constexpr std::string_view to_string(SessionRevocationStatus status) noexcept {
    switch (status) {
    case SessionRevocationStatus::Success:
        return "Success";
    case SessionRevocationStatus::NotFound:
        return "NotFound";
    case SessionRevocationStatus::AlreadyRevoked:
        return "AlreadyRevoked";
    case SessionRevocationStatus::InternalError:
        return "InternalError";
    }
    return "Unknown";
}

/// Strongly-typed result model for session revocation operations.
struct SessionRevocationResult {
    SessionRevocationStatus status{SessionRevocationStatus::NotFound};
    uint64_t revoked_count{0};
    std::string diagnostic_message{};

    [[nodiscard]] bool is_success() const noexcept { return status == SessionRevocationStatus::Success; }

    static SessionRevocationResult success(uint64_t count = 1) {
        SessionRevocationResult res;
        res.status = SessionRevocationStatus::Success;
        res.revoked_count = count;
        res.diagnostic_message = "Session(s) revoked successfully";
        return res;
    }

    static SessionRevocationResult not_found(std::string message = "Session not found") {
        SessionRevocationResult res;
        res.status = SessionRevocationStatus::NotFound;
        res.revoked_count = 0;
        res.diagnostic_message = std::move(message);
        return res;
    }

    static SessionRevocationResult already_revoked(std::string message = "Session was already revoked") {
        SessionRevocationResult res;
        res.status = SessionRevocationStatus::AlreadyRevoked;
        res.revoked_count = 0;
        res.diagnostic_message = std::move(message);
        return res;
    }

    static SessionRevocationResult internal_error(std::string message = "Internal error during session revocation") {
        SessionRevocationResult res;
        res.status = SessionRevocationStatus::InternalError;
        res.revoked_count = 0;
        res.diagnostic_message = std::move(message);
        return res;
    }
};

} // namespace securecloud::auth::domain
