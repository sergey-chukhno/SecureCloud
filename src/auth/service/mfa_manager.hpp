#pragma once

#include "auth/crypto/mfa_secret_protector.hpp"
#include "auth/crypto/totp_engine.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/mfa_result.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/mfa_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/repository/user_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/mfa_authenticator_interface.hpp"

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace securecloud::auth::service {

/**
 * @brief Abstract interface contract for multi-factor authentication lifecycle management.
 */
class IMfaManager {
  public:
    virtual ~IMfaManager() = default;

    /**
     * @brief Checks if a user has an active, enabled MFA configuration.
     */
    [[nodiscard]] virtual bool is_mfa_enabled_for_user(const domain::Uuid& user_id) = 0;

    /**
     * @brief Initiates enrollment: generates a fresh secret, stores pending config, and returns setup URI.
     */
    [[nodiscard]] virtual domain::MfaEnrollmentInitiation initiate_enrollment(
        const domain::Uuid& user_id,
        std::string_view issuer = "SecureCloud",
        std::string_view account_name = "") = 0;

    /**
     * @brief Confirms enrollment with the initial TOTP code and generates single-use backup recovery codes.
     */
    [[nodiscard]] virtual domain::MfaEnrollmentConfirmationResult confirm_enrollment(
        const domain::Uuid& user_id,
        std::string_view code,
        const std::string& client_ip = "unknown") = 0;

    /**
     * @brief Disables MFA for a user upon presenting a valid active code or recovery code.
     */
    [[nodiscard]] virtual bool disable_mfa(
        const domain::Uuid& user_id,
        std::string_view code_or_recovery,
        const std::string& client_ip = "unknown") = 0;

    /**
     * @brief Creates a new pending MFA challenge with a default 5-minute TTL.
     */
    [[nodiscard]] virtual domain::MfaChallengeEntity create_challenge(
        const domain::Uuid& user_id,
        const domain::Uuid& session_id,
        domain::MfaChallengePurpose purpose,
        std::chrono::seconds ttl = std::chrono::minutes(5)) = 0;

    /**
     * @brief Solves an MFA challenge with TOTP or backup code, promoting the session to MFA_VERIFIED.
     */
    [[nodiscard]] virtual domain::MfaChallengeVerificationResult verify_challenge(
        const domain::Uuid& challenge_id,
        std::string_view credential,
        const std::string& client_ip = "unknown") = 0;
};

/**
 * @brief Stateful Multi-Factor Authentication management engine.
 *
 * Implements RFC 6238 TOTP lifecycle, anti-replay time step tracking,
 * 3-attempt brute-force challenge lockout, disaster recovery code fallbacks,
 * and session assurance level promotion to AuthenticationLevel::MfaVerified.
 */
class MfaManager : public IMfaManager {
  public:
    static constexpr uint32_t kMaxChallengeAttempts = 3;

    MfaManager(std::shared_ptr<repository::IMfaRepository> mfa_repository,
               std::shared_ptr<repository::ISessionRepository> session_repository,
               std::shared_ptr<repository::IUserRepository> user_repository,
               std::shared_ptr<IMfaAuthenticator> authenticator,
               std::shared_ptr<crypto::TotpEngine> totp_engine,
               std::shared_ptr<crypto::MfaSecretProtector> secret_protector,
               std::shared_ptr<IAuditEventPublisher> audit_publisher);

    [[nodiscard]] bool is_mfa_enabled_for_user(const domain::Uuid& user_id) override;

    [[nodiscard]] domain::MfaEnrollmentInitiation initiate_enrollment(
        const domain::Uuid& user_id,
        std::string_view issuer = "SecureCloud",
        std::string_view account_name = "") override;

    [[nodiscard]] domain::MfaEnrollmentConfirmationResult confirm_enrollment(
        const domain::Uuid& user_id,
        std::string_view code,
        const std::string& client_ip = "unknown") override;

    [[nodiscard]] bool disable_mfa(
        const domain::Uuid& user_id,
        std::string_view code_or_recovery,
        const std::string& client_ip = "unknown") override;

    [[nodiscard]] domain::MfaChallengeEntity create_challenge(
        const domain::Uuid& user_id,
        const domain::Uuid& session_id,
        domain::MfaChallengePurpose purpose,
        std::chrono::seconds ttl = std::chrono::minutes(5)) override;

    [[nodiscard]] domain::MfaChallengeVerificationResult verify_challenge(
        const domain::Uuid& challenge_id,
        std::string_view credential,
        const std::string& client_ip = "unknown") override;

  private:
    std::shared_ptr<repository::IMfaRepository> mfa_repository_;
    std::shared_ptr<repository::ISessionRepository> session_repository_;
    std::shared_ptr<repository::IUserRepository> user_repository_;
    std::shared_ptr<IMfaAuthenticator> authenticator_;
    std::shared_ptr<crypto::TotpEngine> totp_engine_;
    std::shared_ptr<crypto::MfaSecretProtector> secret_protector_;
    std::shared_ptr<IAuditEventPublisher> audit_publisher_;

    // Anti-replay time step tracking: user_id -> last_used_step
    mutable std::mutex replay_mutex_;
    std::unordered_map<std::string, uint64_t> last_used_time_steps_;

    // Brute-force challenge attempt tracking: challenge_id -> attempt_count
    mutable std::mutex attempts_mutex_;
    std::unordered_map<std::string, uint32_t> challenge_attempts_;

    // Active single-use disaster recovery codes: user_id -> vector<hashed_code>
    mutable std::mutex recovery_mutex_;
    std::unordered_map<std::string, std::vector<std::string>> user_recovery_codes_;
};

} // namespace securecloud::auth::service
