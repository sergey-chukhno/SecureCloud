#include "service/session_manager.hpp"

#include <chrono>
#include <stdexcept>

namespace securecloud::auth::service {

SessionManager::SessionManager(std::shared_ptr<repository::ISessionRepository> session_repository,
                               std::shared_ptr<repository::IDeviceRepository> device_repository,
                               std::chrono::seconds session_ttl)
    : session_repo_(std::move(session_repository)), device_repo_(std::move(device_repository)),
      session_ttl_(session_ttl) {
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

} // namespace securecloud::auth::service
