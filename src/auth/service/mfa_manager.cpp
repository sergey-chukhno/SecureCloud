#include "auth/service/mfa_manager.hpp"

#include "auth/crypto/base32.hpp"
#include "auth/crypto/recovery_code_generator.hpp"

#include <chrono>
#include <openssl/crypto.h>
#include <stdexcept>

namespace securecloud::auth::service {

MfaManager::MfaManager(std::shared_ptr<repository::IMfaRepository> mfa_repository,
                       std::shared_ptr<repository::ISessionRepository> session_repository,
                       std::shared_ptr<repository::IUserRepository> user_repository,
                       std::shared_ptr<IMfaAuthenticator> authenticator,
                       std::shared_ptr<crypto::TotpEngine> totp_engine,
                       std::shared_ptr<crypto::MfaSecretProtector> secret_protector,
                       std::shared_ptr<IAuditEventPublisher> audit_publisher)
    : mfa_repository_(std::move(mfa_repository)),
      session_repository_(std::move(session_repository)),
      user_repository_(std::move(user_repository)),
      authenticator_(std::move(authenticator)),
      totp_engine_(std::move(totp_engine)),
      secret_protector_(std::move(secret_protector)),
      audit_publisher_(std::move(audit_publisher)) {
    if (!mfa_repository_) {
        throw std::invalid_argument("MfaManager: mfa_repository cannot be null");
    }
    if (!session_repository_) {
        throw std::invalid_argument("MfaManager: session_repository cannot be null");
    }
    if (!user_repository_) {
        throw std::invalid_argument("MfaManager: user_repository cannot be null");
    }
    if (!authenticator_) {
        throw std::invalid_argument("MfaManager: authenticator cannot be null");
    }
    if (!totp_engine_) {
        throw std::invalid_argument("MfaManager: totp_engine cannot be null");
    }
    if (!secret_protector_) {
        throw std::invalid_argument("MfaManager: secret_protector cannot be null");
    }
    if (!audit_publisher_) {
        throw std::invalid_argument("MfaManager: audit_publisher cannot be null");
    }
}

bool MfaManager::is_mfa_enabled_for_user(const domain::Uuid& user_id) {
    auto config = mfa_repository_->find_mfa_config_by_user_id(user_id);
    return config.has_value() && config->status == domain::MfaStatus::Enabled;
}

domain::MfaEnrollmentInitiation MfaManager::initiate_enrollment(const domain::Uuid& user_id,
                                                               std::string_view issuer,
                                                               std::string_view account_name) {
    auto user = user_repository_->find_by_id(user_id);
    if (!user.has_value()) {
        throw std::invalid_argument("MfaManager: user not found: " + user_id.to_string());
    }

    std::string account = account_name.empty() ? user->credential_identifier : std::string(account_name);

    // Reject if user already has an active Enabled MFA config
    auto existing = mfa_repository_->find_mfa_config_by_user_id(user_id);
    if (existing.has_value() && existing->status == domain::MfaStatus::Enabled) {
        throw std::runtime_error("MfaManager: MFA is already enabled for user: " + user_id.to_string());
    }

    // Generate fresh 20-byte random secret
    auto secret_bytes = crypto::TotpEngine::generate_secret_bytes(20);
    auto encrypted_secret = secret_protector_->encrypt(secret_bytes, user_id.to_string());

    const std::string base32_secret = crypto::Base32::encode(secret_bytes, false);
    const std::string otpauth_uri = totp_engine_->generate_otpauth_uri(issuer, account, base32_secret);

    domain::MfaConfigurationEntity config;
    config.mfa_configuration_id = domain::Uuid::generate_v7();
    config.user_id = user_id;
    config.factor_type = domain::MfaFactorType::Totp;
    config.encrypted_secret = std::move(encrypted_secret);
    config.status = domain::MfaStatus::Pending;
    config.created_at = std::chrono::system_clock::now();
    config.version = 1;

    mfa_repository_->store_mfa_configuration(config);
    audit_publisher_->publish(domain::AuditEvent::mfa_enrollment_initiated(user_id));

    // Zeroize plaintext secret from memory
    OPENSSL_cleanse(secret_bytes.data(), secret_bytes.size());

    return {config.mfa_configuration_id, domain::SecretMfaString(base32_secret), otpauth_uri};
}

domain::MfaEnrollmentConfirmationResult MfaManager::confirm_enrollment(const domain::Uuid& user_id,
                                                                       std::string_view code,
                                                                       const std::string& client_ip) {
    auto config_opt = mfa_repository_->find_mfa_config_by_user_id(user_id);
    if (!config_opt.has_value()) {
        return domain::MfaEnrollmentConfirmationResult::failure(
            domain::MfaEnrollmentStatus::ConfigurationNotFound, "No MFA configuration found for user");
    }

    auto& config = *config_opt;
    if (config.status == domain::MfaStatus::Enabled) {
        return domain::MfaEnrollmentConfirmationResult::failure(
            domain::MfaEnrollmentStatus::AlreadyEnabled, "MFA is already enabled for this account");
    }
    if (config.status != domain::MfaStatus::Pending) {
        return domain::MfaEnrollmentConfirmationResult::failure(
            domain::MfaEnrollmentStatus::ConfigurationNotFound, "MFA configuration is not in pending status");
    }

    const auto now = std::chrono::system_clock::now();
    const auto now_epoch = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());

    auto ver_res = authenticator_->verify_factor(config.encrypted_secret, code, now_epoch, user_id.to_string());
    if (!ver_res.success) {
        return domain::MfaEnrollmentConfirmationResult::failure(
            domain::MfaEnrollmentStatus::InvalidCode,
            ver_res.error_message.empty() ? "Invalid TOTP verification code" : ver_res.error_message);
    }

    // Activate MFA in database
    mfa_repository_->enable_mfa(config.mfa_configuration_id, now, config.version);

    // Generate single-use recovery codes
    auto batch = crypto::RecoveryCodeGenerator::generate_batch(crypto::RecoveryCodeGenerator::kDefaultCodeCount);
    {
        std::lock_guard<std::mutex> lock(recovery_mutex_);
        user_recovery_codes_[user_id.to_string()] = batch.hashed_codes;
    }

    audit_publisher_->publish(domain::AuditEvent::mfa_enrollment_confirmed(user_id, client_ip));

    return domain::MfaEnrollmentConfirmationResult::success(std::move(batch.plaintext_codes));
}

bool MfaManager::disable_mfa(const domain::Uuid& user_id, std::string_view code_or_recovery,
                             const std::string& client_ip) {
    auto config_opt = mfa_repository_->find_mfa_config_by_user_id(user_id);
    if (!config_opt.has_value() || config_opt->status != domain::MfaStatus::Enabled) {
        return false;
    }

    const auto now = std::chrono::system_clock::now();
    const auto now_epoch = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());

    bool verified = false;

    // Check TOTP code
    auto ver_res = authenticator_->verify_factor(config_opt->encrypted_secret, code_or_recovery, now_epoch,
                                                 user_id.to_string());
    if (ver_res.success) {
        verified = true;
    } else {
        // Check recovery code
        std::lock_guard<std::mutex> lock(recovery_mutex_);
        auto it = user_recovery_codes_.find(user_id.to_string());
        if (it != user_recovery_codes_.end()) {
            auto match_idx = crypto::RecoveryCodeGenerator::verify_and_consume(code_or_recovery, it->second);
            if (match_idx.has_value()) {
                verified = true;
            }
        }
    }

    if (!verified) {
        return false;
    }

    mfa_repository_->disable_mfa(config_opt->mfa_configuration_id, now, config_opt->version);

    // Clear user's recovery codes and replay tracker
    {
        std::lock_guard<std::mutex> lock(recovery_mutex_);
        user_recovery_codes_.erase(user_id.to_string());
    }
    {
        std::lock_guard<std::mutex> lock(replay_mutex_);
        last_used_time_steps_.erase(user_id.to_string());
    }

    audit_publisher_->publish(domain::AuditEvent::mfa_disabled(user_id, client_ip));
    return true;
}

domain::MfaChallengeEntity MfaManager::create_challenge(const domain::Uuid& user_id,
                                                        const domain::Uuid& session_id,
                                                        domain::MfaChallengePurpose purpose,
                                                        std::chrono::seconds ttl) {
    const auto now = std::chrono::system_clock::now();

    domain::MfaChallengeEntity challenge;
    challenge.mfa_challenge_id = domain::Uuid::generate_v7();
    challenge.user_id = user_id;
    challenge.session_id = session_id;
    challenge.challenge_purpose = purpose;
    challenge.challenge_status = domain::MfaChallengeStatus::Pending;
    challenge.created_at = now;
    challenge.expires_at = now + ttl;

    mfa_repository_->create_challenge(challenge);
    audit_publisher_->publish(domain::AuditEvent::mfa_challenge_created(user_id, session_id));

    return challenge;
}

domain::MfaChallengeVerificationResult MfaManager::verify_challenge(const domain::Uuid& challenge_id,
                                                                    std::string_view credential,
                                                                    const std::string& client_ip) {
    auto challenge_opt = mfa_repository_->find_challenge_by_id(challenge_id);
    if (!challenge_opt.has_value()) {
        return domain::MfaChallengeVerificationResult::failure(
            domain::MfaChallengeVerificationStatus::InvalidCode, "Challenge not found");
    }

    auto& challenge = *challenge_opt;
    if (challenge.challenge_status == domain::MfaChallengeStatus::Completed) {
        return domain::MfaChallengeVerificationResult::failure(
            domain::MfaChallengeVerificationStatus::AlreadyCompleted, "Challenge already completed");
    }
    if (challenge.challenge_status == domain::MfaChallengeStatus::Failed) {
        return domain::MfaChallengeVerificationResult::failure(
            domain::MfaChallengeVerificationStatus::ChallengeFailed, "Challenge has failed");
    }

    const auto now = std::chrono::system_clock::now();
    if (challenge.challenge_status == domain::MfaChallengeStatus::Expired || now > challenge.expires_at) {
        mfa_repository_->fail_challenge(challenge_id);
        audit_publisher_->publish(domain::AuditEvent::mfa_challenge_failed(
            challenge.user_id, challenge.session_id, "Challenge expired", client_ip));
        return domain::MfaChallengeVerificationResult::failure(
            domain::MfaChallengeVerificationStatus::ExpiredChallenge, "Challenge has expired");
    }

    // Check brute-force attempts
    uint32_t current_attempts = 0;
    {
        std::lock_guard<std::mutex> lock(attempts_mutex_);
        current_attempts = ++challenge_attempts_[challenge_id.to_string()];
    }

    if (current_attempts > kMaxChallengeAttempts) {
        mfa_repository_->fail_challenge(challenge_id);
        audit_publisher_->publish(domain::AuditEvent::mfa_challenge_failed(
            challenge.user_id, challenge.session_id, "Max verification attempts exceeded", client_ip));
        return domain::MfaChallengeVerificationResult::failure(
            domain::MfaChallengeVerificationStatus::MaxAttemptsExceeded, "Max verification attempts exceeded");
    }

    auto config_opt = mfa_repository_->find_mfa_config_by_user_id(challenge.user_id);
    if (!config_opt.has_value() || config_opt->status != domain::MfaStatus::Enabled) {
        return domain::MfaChallengeVerificationResult::failure(
            domain::MfaChallengeVerificationStatus::ChallengeFailed, "MFA is not enabled for user");
    }

    const auto now_epoch = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());

    bool verified = false;
    bool is_recovery = false;
    uint64_t matched_step = 0;

    // 1. Try TOTP verification
    auto ver_res = authenticator_->verify_factor(config_opt->encrypted_secret, credential, now_epoch,
                                                 challenge.user_id.to_string());
    if (ver_res.success) {
        matched_step = ver_res.matched_time_step;

        // Anti-replay check: prevent same time step reuse
        {
            std::lock_guard<std::mutex> lock(replay_mutex_);
            auto it = last_used_time_steps_.find(challenge.user_id.to_string());
            if (it != last_used_time_steps_.end() && it->second == matched_step) {
                if (current_attempts >= kMaxChallengeAttempts) {
                    mfa_repository_->fail_challenge(challenge_id);
                }
                audit_publisher_->publish(domain::AuditEvent::mfa_challenge_failed(
                    challenge.user_id, challenge.session_id, "TOTP code replay detected", client_ip));
                return domain::MfaChallengeVerificationResult::failure(
                    domain::MfaChallengeVerificationStatus::InvalidCode,
                    "TOTP code replay detected; code has already been used");
            }
            last_used_time_steps_[challenge.user_id.to_string()] = matched_step;
        }
        verified = true;
    } else {
        // 2. Try single-use recovery code
        std::lock_guard<std::mutex> lock(recovery_mutex_);
        auto it = user_recovery_codes_.find(challenge.user_id.to_string());
        if (it != user_recovery_codes_.end()) {
            auto match_idx = crypto::RecoveryCodeGenerator::verify_and_consume(credential, it->second);
            if (match_idx.has_value()) {
                // Burn the recovery code immediately
                it->second.erase(it->second.begin() + static_cast<std::ptrdiff_t>(*match_idx));
                verified = true;
                is_recovery = true;
            }
        }
    }

    if (!verified) {
        if (current_attempts >= kMaxChallengeAttempts) {
            mfa_repository_->fail_challenge(challenge_id);
            audit_publisher_->publish(domain::AuditEvent::mfa_challenge_failed(
                challenge.user_id, challenge.session_id, "Max verification attempts exceeded", client_ip));
            return domain::MfaChallengeVerificationResult::failure(
                domain::MfaChallengeVerificationStatus::MaxAttemptsExceeded,
                "Invalid code; max verification attempts exceeded");
        }
        audit_publisher_->publish(domain::AuditEvent::mfa_challenge_failed(
            challenge.user_id, challenge.session_id, "Invalid verification code", client_ip));
        return domain::MfaChallengeVerificationResult::failure(
            domain::MfaChallengeVerificationStatus::InvalidCode, "Invalid verification code");
    }

    // Verification succeeded! Complete challenge in repository
    mfa_repository_->complete_challenge(challenge_id, now);

    // Promote session assurance level to MfaVerified
    session_repository_->update_authentication_level(challenge.session_id, domain::AuthenticationLevel::MfaVerified);
    session_repository_->touch_session_activity(challenge.session_id, now);

    if (is_recovery) {
        audit_publisher_->publish(domain::AuditEvent::mfa_recovery_code_used(
            challenge.user_id, challenge.session_id, client_ip));
    }
    audit_publisher_->publish(domain::AuditEvent::mfa_challenge_succeeded(
        challenge.user_id, challenge.session_id, client_ip));

    // Clear challenge attempts
    {
        std::lock_guard<std::mutex> lock(attempts_mutex_);
        challenge_attempts_.erase(challenge_id.to_string());
    }

    return domain::MfaChallengeVerificationResult::success(matched_step, challenge.session_id, challenge.user_id);
}

} // namespace securecloud::auth::service
