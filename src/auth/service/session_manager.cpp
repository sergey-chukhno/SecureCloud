#include "service/session_manager.hpp"

#include "domain/audit_event.hpp"
#include "service/audit_event_publisher.hpp"

#include <chrono>
#include <stdexcept>

namespace securecloud::auth::service {

SessionManager::SessionManager(std::shared_ptr<repository::ISessionRepository> session_repository,
                               std::shared_ptr<repository::IDeviceRepository> device_repository,
                               std::chrono::seconds session_ttl, std::shared_ptr<IAuditEventPublisher> audit_publisher)
    : session_repo_(std::move(session_repository)), device_repo_(std::move(device_repository)),
      session_ttl_(session_ttl), audit_publisher_(std::move(audit_publisher)) {
    if (!session_repo_) {
        throw std::invalid_argument("SessionManager: session_repository cannot be null");
    }
    if (!device_repo_) {
        throw std::invalid_argument("SessionManager: device_repository cannot be null");
    }
    if (session_ttl_ <= std::chrono::seconds::zero()) {
        throw std::invalid_argument("SessionManager: session_ttl must be positive");
    }
}

SessionEstablishmentResult SessionManager::establish_session(const domain::UserEntity& user,
                                                             const domain::Uuid& device_id) {

    std::optional<domain::DeviceEntity> device_opt;
    try {
        device_opt = device_repo_->find_by_id(device_id);
    } catch (const std::exception& ex) {
        return SessionEstablishmentResult::internal_error(std::string("Database error during device lookup: ") +
                                                          ex.what());
    } catch (...) {
        return SessionEstablishmentResult::internal_error("Unknown database error during device lookup");
    }

    if (!device_opt.has_value()) {
        return SessionEstablishmentResult::device_not_found("Device not found: " + device_id.to_string());
    }

    // Ownership boundary: enforce device belongs exclusively to authenticated user
    if (device_opt->user_id != user.user_id) {
        return SessionEstablishmentResult::device_not_found("Device does not belong to authenticated user: " +
                                                            device_id.to_string());
    }

    // Lifecycle status verification: reject revoked or suspended devices
    if (device_opt->device_status != domain::DeviceStatus::Active) {
        return SessionEstablishmentResult::device_revoked(
            "Device is not active (status: " + std::string(domain::to_string(device_opt->device_status)) + ")");
    }

    auto now = std::chrono::system_clock::now();

    // Construct primary-only session record
    domain::SessionEntity session;
    session.session_id = domain::Uuid::generate_v7();
    session.user_id = user.user_id;
    session.device_id = device_id;
    session.session_status = domain::SessionStatus::Active;
    session.authentication_level = domain::AuthenticationLevel::PrimaryOnly;
    session.created_at = now;
    session.expires_at = now + session_ttl_;
    session.last_used_at = now;
    session.revoked_at = std::nullopt;

    try {
        session_repo_->create_session(session);
    } catch (const std::exception& ex) {
        return SessionEstablishmentResult::internal_error(std::string("Database error during session persistence: ") +
                                                          ex.what());
    } catch (...) {
        return SessionEstablishmentResult::internal_error("Unknown database error during session persistence");
    }

    try {
        device_repo_->update_last_authenticated(device_id, now);
        device_opt->last_authenticated_at = now;
    } catch (const std::exception& ex) {
        return SessionEstablishmentResult::internal_error(
            std::string("Database error updating device last_authenticated timestamp: ") + ex.what());
    } catch (...) {
        return SessionEstablishmentResult::internal_error(
            "Unknown database error updating device last_authenticated timestamp");
    }

    return SessionEstablishmentResult::success(std::move(session), std::move(*device_opt));
}

domain::SessionValidationResult SessionManager::validate_session(const domain::Uuid& session_id,
                                                                 std::optional<domain::Uuid> claimed_device_id) {

    std::optional<domain::SessionEntity> session_opt;
    try {
        session_opt = session_repo_->find_by_id(session_id);
    } catch (const std::exception& ex) {
        return domain::SessionValidationResult::internal_error(std::string("Database error during session lookup: ") +
                                                               ex.what());
    } catch (...) {
        return domain::SessionValidationResult::internal_error("Unknown database error during session lookup");
    }

    if (!session_opt.has_value()) {
        return domain::SessionValidationResult::not_found("Session not found: " + session_id.to_string());
    }

    const auto& session = *session_opt;

    // Lifecycle check: Revoked sessions are immediately and irreversibly rejected
    if (session.session_status == domain::SessionStatus::Revoked) {
        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::session_revoked_attempt(session_id));
        }
        return domain::SessionValidationResult::revoked("Session has been revoked: " + session_id.to_string());
    }

    // Lifecycle check: Expired status or wall-clock expiration exceeded
    auto now = std::chrono::system_clock::now();
    if (session.session_status == domain::SessionStatus::Expired || now >= session.expires_at) {
        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::session_expired_attempt(session_id));
        }
        return domain::SessionValidationResult::expired("Session has expired: " + session_id.to_string());
    }

    // Device association check: if caller claimed a device ID, verify exact match
    if (claimed_device_id.has_value() && *claimed_device_id != session.device_id) {
        return domain::SessionValidationResult::device_mismatch("Session is not associated with claimed device: " +
                                                                claimed_device_id->to_string());
    }

    // Device status check: verify the bound physical device is still registered and active
    std::optional<domain::DeviceEntity> device_opt;
    try {
        device_opt = device_repo_->find_by_id(session.device_id);
    } catch (const std::exception& ex) {
        return domain::SessionValidationResult::internal_error(std::string("Database error during device lookup: ") +
                                                               ex.what());
    } catch (...) {
        return domain::SessionValidationResult::internal_error("Unknown database error during device lookup");
    }

    if (!device_opt.has_value()) {
        return domain::SessionValidationResult::device_mismatch("Bound device not found: " +
                                                                session.device_id.to_string());
    }

    if (device_opt->device_status != domain::DeviceStatus::Active) {
        return domain::SessionValidationResult::device_revoked("Associated device is revoked or disabled: " +
                                                               session.device_id.to_string());
    }

    // Sliding activity touch: refresh last_used_at on valid active session
    try {
        session_repo_->touch_session_activity(session_id, now);
    } catch (const std::exception& ex) {
        return domain::SessionValidationResult::internal_error(
            std::string("Database error updating session activity: ") + ex.what());
    } catch (...) {
        return domain::SessionValidationResult::internal_error("Unknown database error updating session activity");
    }

    auto valid_session = session;
    valid_session.last_used_at = now;
    return domain::SessionValidationResult::valid(std::move(valid_session));
}

std::vector<domain::SessionEntity> SessionManager::list_active_sessions_for_user(const domain::Uuid& user_id) {
    return session_repo_->list_active_by_user_id(user_id);
}

std::vector<domain::SessionEntity> SessionManager::list_active_sessions_for_device(const domain::Uuid& device_id) {
    return session_repo_->list_active_by_device_id(device_id);
}

domain::SessionRevocationResult SessionManager::revoke_session(const domain::Uuid& session_id,
                                                               std::string_view reason) {
    std::optional<domain::SessionEntity> session_opt;
    try {
        session_opt = session_repo_->find_by_id(session_id);
    } catch (const std::exception& ex) {
        return domain::SessionRevocationResult::internal_error(std::string("Database error during session lookup: ") +
                                                               ex.what());
    } catch (...) {
        return domain::SessionRevocationResult::internal_error("Unknown database error during session lookup");
    }

    if (!session_opt.has_value()) {
        return domain::SessionRevocationResult::not_found("Session not found: " + session_id.to_string());
    }

    if (session_opt->session_status == domain::SessionStatus::Revoked) {
        return domain::SessionRevocationResult::already_revoked("Session was already revoked: " +
                                                                session_id.to_string());
    }

    if (session_opt->session_status == domain::SessionStatus::Expired) {
        return domain::SessionRevocationResult::already_revoked("Session is expired and cannot be revoked: " +
                                                                session_id.to_string());
    }

    auto now = std::chrono::system_clock::now();
    bool revoked = false;
    try {
        revoked = session_repo_->revoke_session_atomic(session_id, now);
    } catch (const std::exception& ex) {
        return domain::SessionRevocationResult::internal_error(std::string("Database error revoking session: ") +
                                                               ex.what());
    } catch (...) {
        return domain::SessionRevocationResult::internal_error("Unknown database error revoking session");
    }

    if (!revoked) {
        return domain::SessionRevocationResult::already_revoked("Session already revoked by concurrent operation: " +
                                                                session_id.to_string());
    }

    if (audit_publisher_) {
        audit_publisher_->publish(
            domain::AuditEvent::session_revoked(session_id, session_opt->user_id, session_opt->device_id, reason));
    }

    return domain::SessionRevocationResult::success(1);
}

domain::SessionRevocationResult SessionManager::revoke_all_device_sessions(const domain::Uuid& device_id,
                                                                           std::string_view /*reason*/) {
    auto now = std::chrono::system_clock::now();
    uint64_t count = 0;
    try {
        count = session_repo_->revoke_all_device_sessions_atomic(device_id, now);
    } catch (const std::exception& ex) {
        return domain::SessionRevocationResult::internal_error(
            std::string("Database error revoking device sessions: ") + ex.what());
    } catch (...) {
        return domain::SessionRevocationResult::internal_error("Unknown database error revoking device sessions");
    }

    return domain::SessionRevocationResult::success(count);
}

domain::SessionRevocationResult SessionManager::revoke_all_user_sessions(const domain::Uuid& user_id,
                                                                         std::string_view /*reason*/) {
    auto now = std::chrono::system_clock::now();
    uint64_t count = 0;
    try {
        count = session_repo_->revoke_all_user_sessions_atomic(user_id, now);
    } catch (const std::exception& ex) {
        return domain::SessionRevocationResult::internal_error(std::string("Database error revoking user sessions: ") +
                                                               ex.what());
    } catch (...) {
        return domain::SessionRevocationResult::internal_error("Unknown database error revoking user sessions");
    }

    return domain::SessionRevocationResult::success(count);
}

} // namespace securecloud::auth::service
