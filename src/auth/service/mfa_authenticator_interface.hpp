#pragma once

#include "auth/crypto/mfa_secret_protector.hpp"
#include "auth/crypto/totp_engine.hpp"
#include "auth/domain/enums.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace securecloud::auth::service {

/**
 * @brief Result of evaluating an authenticator factor credential.
 */
struct MfaFactorVerificationResult {
    bool success = false;
    uint64_t matched_time_step = 0; ///< Non-zero for TOTP replay prevention, 0 for WebAuthn
    std::string error_message{};

    static MfaFactorVerificationResult ok(uint64_t time_step = 0) {
        return {true, time_step, {}};
    }

    static MfaFactorVerificationResult fail(std::string message) {
        return {false, 0, std::move(message)};
    }
};

/**
 * @brief Abstract interface contract for multi-factor authenticators.
 *
 * Decouples the Auth Service and Challenge workflows from specific second-factor mechanics.
 * Concrete implementations: TotpAuthenticator (MVP), WebAuthnAuthenticator (future).
 */
class IMfaAuthenticator {
  public:
    virtual ~IMfaAuthenticator() = default;

    [[nodiscard]] virtual domain::MfaFactorType factor_type() const noexcept = 0;

    /**
     * @brief Verifies a presented credential against stored encrypted secret bytes.
     * @param encrypted_secret Encrypted factor secret from PostgreSQL mfa_configurations.
     * @param credential User-presented credential (6-digit TOTP, WebAuthn assertion JSON, etc.).
     * @param timestamp_seconds Current Unix epoch seconds.
     * @param aad Optional Additional Authenticated Data (e.g. user_id string) for decryption.
     * @return Verification outcome including matched time step.
     */
    [[nodiscard]] virtual MfaFactorVerificationResult verify_factor(
        std::span<const uint8_t> encrypted_secret,
        std::string_view credential,
        uint64_t timestamp_seconds,
        std::string_view aad = "") const = 0;
};

/**
 * @brief Concrete RFC 6238 TOTP authenticator.
 */
class TotpAuthenticator : public IMfaAuthenticator {
  public:
    TotpAuthenticator(std::shared_ptr<crypto::TotpEngine> totp_engine,
                      std::shared_ptr<crypto::MfaSecretProtector> secret_protector);

    [[nodiscard]] domain::MfaFactorType factor_type() const noexcept override {
        return domain::MfaFactorType::Totp;
    }

    [[nodiscard]] MfaFactorVerificationResult verify_factor(
        std::span<const uint8_t> encrypted_secret,
        std::string_view credential,
        uint64_t timestamp_seconds,
        std::string_view aad = "") const override;

  private:
    std::shared_ptr<crypto::TotpEngine> totp_engine_;
    std::shared_ptr<crypto::MfaSecretProtector> secret_protector_;
};

} // namespace securecloud::auth::service
