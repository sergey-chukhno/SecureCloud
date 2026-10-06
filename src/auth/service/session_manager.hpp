#pragma once

#include "domain/entities.hpp"
#include "domain/enums.hpp"
#include "domain/session_result.hpp"
#include "domain/uuid.hpp"
#include "repository/device_repository.hpp"
#include "repository/session_repository.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::auth::service {

/// Status outcome of attempting to establish an authenticated session.
enum class SessionEstablishmentStatus { Success, DeviceNotFound, DeviceRevoked, InternalError };

[[nodiscard]] inline constexpr std::string_view to_string(SessionEstablishmentStatus status) noexcept {
    switch (status) {
    case SessionEstablishmentStatus::Success:
        return "Success";
    case SessionEstablishmentStatus::DeviceNotFound:
        return "DeviceNotFound";
    case SessionEstablishmentStatus::DeviceRevoked:
        return "DeviceRevoked";
    case SessionEstablishmentStatus::InternalError:
        return "InternalError";
    }
    return "Unknown";
}

/// Result payload for session establishment.
struct SessionEstablishmentResult {
    SessionEstablishmentStatus status{SessionEstablishmentStatus::InternalError};
    std::optional<domain::SessionEntity> session{std::nullopt};
    std::optional<domain::DeviceEntity> device{std::nullopt};
    std::string diagnostic_message{};

    [[nodiscard]] bool is_success() const noexcept { return status == SessionEstablishmentStatus::Success; }

    static SessionEstablishmentResult success(domain::SessionEntity session, domain::DeviceEntity device) {
        SessionEstablishmentResult res;
        res.status = SessionEstablishmentStatus::Success;
        res.session = std::move(session);
        res.device = std::move(device);
        res.diagnostic_message = "Session established successfully";
        return res;
    }

    static SessionEstablishmentResult device_not_found(std::string diagnostic) {
        SessionEstablishmentResult res;
        res.status = SessionEstablishmentStatus::DeviceNotFound;
        res.session = std::nullopt;
        res.device = std::nullopt;
        res.diagnostic_message = std::move(diagnostic);
        return res;
    }

    static SessionEstablishmentResult device_revoked(std::string diagnostic) {
        SessionEstablishmentResult res;
        res.status = SessionEstablishmentStatus::DeviceRevoked;
        res.session = std::nullopt;
        res.device = std::nullopt;
        res.diagnostic_message = std::move(diagnostic);
        return res;
    }

    static SessionEstablishmentResult internal_error(std::string diagnostic) {
        SessionEstablishmentResult res;
        res.status = SessionEstablishmentStatus::InternalError;
        res.session = std::nullopt;
        res.device = std::nullopt;
        res.diagnostic_message = std::move(diagnostic);
        return res;
    }
};

/// Abstract interface for session establishment service.
class ISessionManager {
  public:
    virtual ~ISessionManager() = default;

    /// Establishes a durable authenticated session bound to a validated user device.
    ///
    /// @param user Authenticated user entity.
    /// @param device_id Claimed device identifier.
    /// @return SessionEstablishmentResult containing active session and updated device record.
    virtual SessionEstablishmentResult establish_session(const domain::UserEntity& user,
                                                         const domain::Uuid& device_id) = 0;

    /// Validates the authenticity, lifecycle status, expiration, and device association of a session.
    /// On success, automatically refreshes the session's activity timestamp (sliding window touch).
    virtual domain::SessionValidationResult
    validate_session(const domain::Uuid& session_id, std::optional<domain::Uuid> claimed_device_id = std::nullopt) = 0;

    /// Lists all active sessions for a specific user identity.
    virtual std::vector<domain::SessionEntity> list_active_sessions_for_user(const domain::Uuid& user_id) = 0;

    /// Lists all active sessions bound to a specific device.
    virtual std::vector<domain::SessionEntity> list_active_sessions_for_device(const domain::Uuid& device_id) = 0;
};

/// Production implementation of ISessionManager.
///
/// Invariants & Rules:
/// 1. Ownership: verifies device_id exists and device.user_id == user.user_id.
/// 2. Active status: verifies device.device_status == DeviceStatus::Active.
/// 3. Assurance level: session stamped with AuthenticationLevel::PrimaryOnly.
/// 4. Durability: session persisted via ISessionRepository and device activity timestamp updated.
class SessionManager final : public ISessionManager {
  public:
    SessionManager(std::shared_ptr<repository::ISessionRepository> session_repository,
                   std::shared_ptr<repository::IDeviceRepository> device_repository,
                   std::chrono::seconds session_ttl = std::chrono::hours(24));
    ~SessionManager() override = default;

    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;
    SessionManager(SessionManager&&) noexcept = default;
    SessionManager& operator=(SessionManager&&) noexcept = default;

    SessionEstablishmentResult establish_session(const domain::UserEntity& user,
                                                 const domain::Uuid& device_id) override;

    domain::SessionValidationResult
    validate_session(const domain::Uuid& session_id,
                     std::optional<domain::Uuid> claimed_device_id = std::nullopt) override;

    std::vector<domain::SessionEntity> list_active_sessions_for_user(const domain::Uuid& user_id) override;

    std::vector<domain::SessionEntity> list_active_sessions_for_device(const domain::Uuid& device_id) override;

    [[nodiscard]] std::chrono::seconds session_ttl() const noexcept { return session_ttl_; }

  private:
    std::shared_ptr<repository::ISessionRepository> session_repo_;
    std::shared_ptr<repository::IDeviceRepository> device_repo_;
    std::chrono::seconds session_ttl_;
};

} // namespace securecloud::auth::service
