#include "auth/service/token_manager.hpp"

#include "auth/domain/audit_event.hpp"
#include "auth/repository/exceptions.hpp"

#include <stdexcept>

namespace securecloud::auth::service {

TokenManager::TokenManager(std::shared_ptr<crypto::ITokenSigner> token_signer,
                           std::shared_ptr<repository::IRefreshTokenRepository> refresh_token_repo,
                           std::shared_ptr<repository::ISessionRepository> session_repo,
                           std::shared_ptr<repository::IDeviceRepository> device_repo,
                           std::shared_ptr<IAuditEventPublisher> audit_publisher, TokenManagerConfig config)
    : token_signer_(std::move(token_signer)), refresh_token_repo_(std::move(refresh_token_repo)),
      session_repo_(std::move(session_repo)), device_repo_(std::move(device_repo)),
      audit_publisher_(std::move(audit_publisher)), config_(std::move(config)) {
    if (!token_signer_) {
        throw std::invalid_argument("TokenManager: token_signer cannot be null");
    }
    if (!refresh_token_repo_) {
        throw std::invalid_argument("TokenManager: refresh_token_repo cannot be null");
    }
    if (!session_repo_) {
        throw std::invalid_argument("TokenManager: session_repo cannot be null");
    }
    if (!device_repo_) {
        throw std::invalid_argument("TokenManager: device_repo cannot be null");
    }
    if (config_.access_token_ttl <= std::chrono::seconds::zero()) {
        throw std::invalid_argument("TokenManager: access_token_ttl must be positive");
    }
    if (config_.refresh_token_ttl <= std::chrono::seconds::zero()) {
        throw std::invalid_argument("TokenManager: refresh_token_ttl must be positive");
    }
}

domain::TokenPair TokenManager::issue_initial_tokens(const domain::SessionEntity& session,
                                                     const std::vector<std::string>& scopes) {
    if (session.session_status != domain::SessionStatus::Active) {
        throw std::invalid_argument("Cannot issue tokens for non-active session: " + session.session_id.to_string());
    }

    const auto now = std::chrono::system_clock::now();
    if (now > session.expires_at) {
        throw std::invalid_argument("Cannot issue tokens for expired session: " + session.session_id.to_string());
    }

    // 1. Issue signed access token envelope
    domain::AccessTokenClaims claims;
    claims.issuer = config_.issuer;
    claims.audience = config_.audience;
    claims.user_id = session.user_id;
    claims.device_id = session.device_id;
    claims.session_id = session.session_id;
    claims.issued_at = now;
    claims.expires_at = now + config_.access_token_ttl;
    claims.jti = domain::Uuid::generate_v7();
    claims.scopes = scopes.empty() ? config_.default_scopes : scopes;
    claims.token_version = 1;
    claims.authentication_level = session.authentication_level;

    std::string access_token = domain::TokenEnvelopeSerializer::serialize(claims, *token_signer_);

    // 2. Generate cryptographically secure refresh token
    std::string raw_rt_secret = crypto::SecureRandomTokenGenerator::generate_refresh_token(32);
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(raw_rt_secret);

    domain::RefreshTokenEntity rt_entity;
    rt_entity.refresh_token_id = domain::Uuid::generate_v7();
    rt_entity.session_id = session.session_id;
    rt_entity.device_id = session.device_id;
    rt_entity.token_verifier = std::move(verifier_hash);
    rt_entity.token_status = domain::TokenStatus::Active;
    rt_entity.issued_at = now;
    rt_entity.expires_at = now + config_.refresh_token_ttl;
    rt_entity.revoked_at = std::nullopt;
    rt_entity.rotated_at = std::nullopt;
    rt_entity.replaced_by_token_id = std::nullopt;

    refresh_token_repo_->create_token(rt_entity);

    domain::TokenPair pair;
    pair.access_token = std::move(access_token);
    pair.refresh_token = domain::SecretTokenString(std::move(raw_rt_secret));
    pair.expires_at = claims.expires_at;

    return pair;
}

domain::TokenRefreshResult TokenManager::refresh_tokens(std::string_view refresh_token_secret,
                                                        const domain::Uuid& device_id, std::string_view client_ip) {
    if (refresh_token_secret.empty()) {
        return domain::TokenRefreshResult::invalid_token("Refresh token secret cannot be empty");
    }

    const std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(refresh_token_secret);

    try {
        auto token_opt = refresh_token_repo_->find_by_verifier(verifier_hash);
        if (!token_opt.has_value()) {
            return domain::TokenRefreshResult::invalid_token("Refresh token not found");
        }

        // Protocol for token reuse / replay attack
        if (token_opt->token_status == domain::TokenStatus::Rotated) {
            try {
                refresh_token_repo_->handle_token_reuse(verifier_hash);
            } catch (...) {
                // Best-effort persistence guarantee
            }
            if (audit_publisher_) {
                audit_publisher_->publish(
                    domain::AuditEvent::token_reuse_detected(token_opt->session_id, token_opt->device_id, client_ip));
            }
            return domain::TokenRefreshResult::compromise_detected(
                "Refresh token reuse detected: token was previously rotated; session revoked");
        }

        if (token_opt->token_status == domain::TokenStatus::Revoked) {
            return domain::TokenRefreshResult::session_revoked("Refresh token has been revoked");
        }

        if (token_opt->token_status != domain::TokenStatus::Active) {
            return domain::TokenRefreshResult::invalid_token(
                "Refresh token is not active (status: " + std::string(domain::to_string(token_opt->token_status)) +
                ")");
        }

        const auto now = std::chrono::system_clock::now();
        if (now > token_opt->expires_at) {
            return domain::TokenRefreshResult::expired_token("Refresh token has expired");
        }

        // Enforce device binding on refresh token
        if (token_opt->device_id != device_id) {
            return domain::TokenRefreshResult::device_mismatch(
                "Refresh token device binding does not match requesting device");
        }

        // Enforce active requesting device
        auto device_opt = device_repo_->find_by_id(device_id);
        if (!device_opt.has_value()) {
            return domain::TokenRefreshResult::device_mismatch("Requesting device not found");
        }
        if (device_opt->device_status != domain::DeviceStatus::Active) {
            return domain::TokenRefreshResult::device_mismatch(
                "Requesting device is not active (status: " +
                std::string(domain::to_string(device_opt->device_status)) + ")");
        }

        // Enforce active session
        auto session_opt = session_repo_->find_by_id(token_opt->session_id);
        if (!session_opt.has_value()) {
            return domain::TokenRefreshResult::invalid_token("Associated session not found");
        }
        if (session_opt->session_status != domain::SessionStatus::Active) {
            return domain::TokenRefreshResult::session_revoked("Associated session has been revoked");
        }
        if (now > session_opt->expires_at) {
            return domain::TokenRefreshResult::session_revoked("Associated session has expired");
        }
        if (session_opt->device_id != device_id) {
            return domain::TokenRefreshResult::device_mismatch("Associated session is bound to a different device");
        }
        if (device_opt->user_id != session_opt->user_id) {
            return domain::TokenRefreshResult::device_mismatch("Device ownership does not match session user");
        }

        // Generate next rotation secret and entity
        std::string new_raw_secret = crypto::SecureRandomTokenGenerator::generate_refresh_token(32);
        std::string new_verifier_hash = crypto::TokenHasher::compute_sha256_hex(new_raw_secret);

        domain::RefreshTokenEntity new_token;
        new_token.refresh_token_id = domain::Uuid::generate_v7();
        new_token.session_id = token_opt->session_id;
        new_token.device_id = device_id;
        new_token.token_verifier = std::move(new_verifier_hash);
        new_token.token_status = domain::TokenStatus::Active;
        new_token.issued_at = now;
        new_token.expires_at = now + config_.refresh_token_ttl;
        new_token.revoked_at = std::nullopt;
        new_token.rotated_at = std::nullopt;
        new_token.replaced_by_token_id = std::nullopt;

        // Atomic rotation in repository
        refresh_token_repo_->rotate_token_atomic(token_opt->refresh_token_id, new_token);

        // Slide session and device activity timestamps
        session_repo_->touch_session_activity(session_opt->session_id, now);
        device_repo_->update_last_authenticated(device_id, now);

        // Issue new signed access token
        domain::AccessTokenClaims claims;
        claims.issuer = config_.issuer;
        claims.audience = config_.audience;
        claims.user_id = session_opt->user_id;
        claims.device_id = device_id;
        claims.session_id = session_opt->session_id;
        claims.issued_at = now;
        claims.expires_at = now + config_.access_token_ttl;
        claims.jti = domain::Uuid::generate_v7();
        claims.scopes = config_.default_scopes;
        claims.token_version = 1;
        claims.authentication_level = session_opt->authentication_level;

        std::string access_token = domain::TokenEnvelopeSerializer::serialize(claims, *token_signer_);

        // Emit audit telemetry
        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::token_refreshed(session_opt->session_id, session_opt->user_id,
                                                                          device_id, client_ip));
        }

        domain::TokenPair pair;
        pair.access_token = std::move(access_token);
        pair.refresh_token = domain::SecretTokenString(std::move(new_raw_secret));
        pair.expires_at = claims.expires_at;

        return domain::TokenRefreshResult::success(std::move(pair));
    } catch (const repository::OptimisticLockException& ex) {
        return domain::TokenRefreshResult::database_error("Concurrent token rotation race detected: " +
                                                          std::string(ex.what()));
    } catch (const repository::RepositoryException& ex) {
        return domain::TokenRefreshResult::database_error("Repository error during token refresh: " +
                                                          std::string(ex.what()));
    } catch (const std::exception& ex) {
        return domain::TokenRefreshResult::database_error("Internal error during token refresh: " +
                                                          std::string(ex.what()));
    }
}

} // namespace securecloud::auth::service
