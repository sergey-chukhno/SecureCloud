#pragma once

#include "auth/crypto/token_crypto.hpp"
#include "auth/domain/token_claims.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/auth/token_validation_result.hpp"
#include "http/auth/token_validator_interface.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::gateway::http {

/**
 * @brief Configuration parameters for local cryptographic token verification.
 */
struct LocalTokenVerifierOptions {
    std::string expected_issuer{"https://auth.securecloud.io"};
    std::string expected_audience{"https://gateway.securecloud.io"};
    std::chrono::seconds clock_skew_tolerance{30};
};

/**
 * @brief Perimeter token validator performing offline asymmetric cryptographic validation.
 *
 * Implements ITokenValidator at the Gateway perimeter:
 * - Employs Ed25519 public key verification to validate access tokens offline without network I/O.
 * - Zero RPC overhead: requests do not block on synchronous calls to AuthService.
 * - Zero database connectivity: Gateway requires no database credentials or connection pool.
 * - Zero private key exposure: Gateway is provisioned only with Auth's public verification key.
 * - Enforces standard claims (issuer, audience, expiration, device & session binding).
 * - Maps valid tokens directly to AuthenticatedContext.
 */
class LocalTokenVerifier : public ITokenValidator {
  public:
    explicit LocalTokenVerifier(std::shared_ptr<securecloud::auth::crypto::ITokenVerifier> verifier,
                                LocalTokenVerifierOptions options = {});

    ~LocalTokenVerifier() override = default;

    // Non-copyable, movable
    LocalTokenVerifier(const LocalTokenVerifier&) = delete;
    LocalTokenVerifier& operator=(const LocalTokenVerifier&) = delete;
    LocalTokenVerifier(LocalTokenVerifier&&) noexcept = default;
    LocalTokenVerifier& operator=(LocalTokenVerifier&&) noexcept = default;

    /// Factory method to construct LocalTokenVerifier from a PEM-encoded Ed25519 public key.
    static std::unique_ptr<LocalTokenVerifier> from_public_key_pem(std::string_view pem_public_key,
                                                                   std::string key_id = "sc-auth-v1",
                                                                   LocalTokenVerifierOptions options = {});

    /// Factory method to construct LocalTokenVerifier from raw 32-byte Ed25519 public key bytes.
    static std::unique_ptr<LocalTokenVerifier> from_public_key_raw(const std::vector<uint8_t>& raw_public_key,
                                                                   std::string key_id = "sc-auth-v1",
                                                                   LocalTokenVerifierOptions options = {});

    AuthenticatedResult validate(const std::string& token, const std::string& session_id = "",
                                 const std::string& request_id = "") override;

    [[nodiscard]] const LocalTokenVerifierOptions& options() const noexcept { return options_; }
    [[nodiscard]] std::shared_ptr<securecloud::auth::crypto::ITokenVerifier> verifier() const noexcept {
        return verifier_;
    }

  private:
    std::shared_ptr<securecloud::auth::crypto::ITokenVerifier> verifier_;
    LocalTokenVerifierOptions options_;
};

} // namespace securecloud::gateway::http
