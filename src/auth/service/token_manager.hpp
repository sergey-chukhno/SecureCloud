#pragma once

#include "auth/crypto/token_crypto.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/token_claims.hpp"
#include "auth/domain/token_result.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/refresh_token_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::auth::service {

/**
 * @brief Configuration parameters for token generation and lifecycle management.
 */
struct TokenManagerConfig {
    std::chrono::seconds access_token_ttl{std::chrono::minutes(15)};
    std::chrono::seconds refresh_token_ttl{std::chrono::hours(24 * 7)};
    std::string issuer{"https://auth.securecloud.io"};
    std::string audience{"https://gateway.securecloud.io"};
    std::vector<std::string> default_scopes{"access", "files:read", "files:write"};
};

/**
 * @brief Abstract interface contract for Access and Refresh Token Management.
 */
class ITokenManager {
  public:
    virtual ~ITokenManager() = default;

    /// Issues initial access and refresh token pair for a newly established session.
    ///
    /// @param session Active session record.
    /// @param scopes Optional explicit scopes. If empty, uses default configured scopes.
    /// @return Generated TokenPair containing access token and secret refresh token.
    virtual domain::TokenPair issue_initial_tokens(const domain::SessionEntity& session,
                                                   const std::vector<std::string>& scopes = {}) = 0;

    /// Refreshes and atomically rotates a single-use refresh token.
    ///
    /// @param refresh_token_secret Plaintext secret presented by client.
    /// @param device_id Claimed device endpoint identifier.
    /// @param client_ip Optional client IP address for security audit telemetry.
    /// @return TokenRefreshResult containing the newly issued TokenPair or failure reason.
    virtual domain::TokenRefreshResult refresh_tokens(std::string_view refresh_token_secret,
                                                      const domain::Uuid& device_id,
                                                      std::string_view client_ip = "unknown") = 0;
};

/**
 * @brief Core engine managing token issuance, validation, and single-use rotation.
 *
 * Enforces Zero-Trust token lifecycle invariants:
 * 1. Refresh tokens are single-use and rotated atomically in PostgreSQL.
 * 2. Access tokens are short-lived, signed with Ed25519, and cryptographically bound to session & device.
 * 3. Plaintext refresh token secrets are never stored; only deterministic SHA-256 verifiers are persisted.
 * 4. Device and session bindings are rigorously verified before every rotation.
 * 5. Replay of previously rotated refresh tokens triggers automatic session revocation and audit telemetry.
 */
class TokenManager final : public ITokenManager {
  public:
    TokenManager(std::shared_ptr<crypto::ITokenSigner> token_signer,
                 std::shared_ptr<repository::IRefreshTokenRepository> refresh_token_repo,
                 std::shared_ptr<repository::ISessionRepository> session_repo,
                 std::shared_ptr<repository::IDeviceRepository> device_repo,
                 std::shared_ptr<IAuditEventPublisher> audit_publisher = nullptr, TokenManagerConfig config = {});

    ~TokenManager() override = default;

    TokenManager(const TokenManager&) = delete;
    TokenManager& operator=(const TokenManager&) = delete;
    TokenManager(TokenManager&&) noexcept = default;
    TokenManager& operator=(TokenManager&&) noexcept = default;

    domain::TokenPair issue_initial_tokens(const domain::SessionEntity& session,
                                           const std::vector<std::string>& scopes = {}) override;

    domain::TokenRefreshResult refresh_tokens(std::string_view refresh_token_secret, const domain::Uuid& device_id,
                                              std::string_view client_ip = "unknown") override;

    [[nodiscard]] const TokenManagerConfig& config() const noexcept { return config_; }
    [[nodiscard]] std::shared_ptr<crypto::ITokenSigner> signer() const noexcept { return token_signer_; }

  private:
    std::shared_ptr<crypto::ITokenSigner> token_signer_;
    std::shared_ptr<repository::IRefreshTokenRepository> refresh_token_repo_;
    std::shared_ptr<repository::ISessionRepository> session_repo_;
    std::shared_ptr<repository::IDeviceRepository> device_repo_;
    std::shared_ptr<IAuditEventPublisher> audit_publisher_;
    TokenManagerConfig config_;
};

} // namespace securecloud::auth::service
