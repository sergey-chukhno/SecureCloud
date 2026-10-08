#include "auth/service/device_manager.hpp"

#include "auth/crypto/device_key_validator.hpp"
#include "auth/domain/audit_event.hpp"
#include "auth/service/session_manager.hpp"

#include <algorithm>
#include <cctype>
#include <openssl/rand.h>
#include <stdexcept>

namespace securecloud::auth::service {

namespace {

constexpr std::string_view kPairingAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // 32 chars
constexpr std::size_t kPairingCodeLength = 8;

} // namespace

DeviceManager::DeviceManager(std::shared_ptr<repository::IDeviceRepository> device_repo,
                             std::shared_ptr<repository::IDevicePublicKeyRepository> public_key_repo,
                             std::shared_ptr<ISessionManager> session_manager,
                             std::shared_ptr<IAuditEventPublisher> audit_publisher, std::chrono::seconds pairing_ttl)
    : device_repo_(std::move(device_repo)), public_key_repo_(std::move(public_key_repo)),
      session_manager_(std::move(session_manager)), audit_publisher_(std::move(audit_publisher)),
      pairing_ttl_(pairing_ttl) {
    if (!device_repo_) {
        throw std::invalid_argument("DeviceManager requires non-null IDeviceRepository");
    }
    if (!public_key_repo_) {
        throw std::invalid_argument("DeviceManager requires non-null IDevicePublicKeyRepository");
    }
    if (!session_manager_) {
        throw std::invalid_argument("DeviceManager requires non-null ISessionManager");
    }
}

std::string DeviceManager::normalize_code(std::string_view code) {
    std::string result;
    result.reserve(code.size());
    for (char c : code) {
        if (c != '-' && c != ' ' && !std::isspace(static_cast<unsigned char>(c))) {
            result.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }
    }
    return result;
}

std::string DeviceManager::generate_pairing_code_internal() {
    std::string code;
    code.reserve(kPairingCodeLength);
    std::vector<uint8_t> rand_bytes(kPairingCodeLength);

    if (RAND_bytes(rand_bytes.data(), static_cast<int>(kPairingCodeLength)) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed to generate pairing code entropy");
    }

    for (std::size_t i = 0; i < kPairingCodeLength; ++i) {
        code.push_back(kPairingAlphabet[rand_bytes[i] % kPairingAlphabet.size()]);
    }

    return code;
}

DeviceEnrollmentResult DeviceManager::enroll_device(const domain::Uuid& user_id, std::span<const uint8_t> identity_key,
                                                    std::span<const uint8_t> signed_prekey,
                                                    std::span<const uint8_t> signature,
                                                    const std::vector<std::vector<uint8_t>>& one_time_prekeys,
                                                    domain::AuthenticationLevel caller_auth_level,
                                                    std::string_view client_ip) {
    // 1. Cryptographic Key Bundle Validation
    std::string validation_error;
    if (!crypto::DeviceKeyValidator::validate_registration_bundle(identity_key, signed_prekey, signature,
                                                                  one_time_prekeys, &validation_error)) {
        return DeviceEnrollmentResult{
            .success = false,
            .error_message = validation_error,
        };
    }

    // 2. Strong Authorization Determination:
    // If registered by an MFA_VERIFIED caller, device is Active immediately.
    // Otherwise, caller receives PendingAuthorization requiring pairing PIN verification.
    const auto now = std::chrono::system_clock::now();
    const bool is_mfa = (caller_auth_level == domain::AuthenticationLevel::MfaVerified);
    const domain::DeviceStatus initial_status =
        is_mfa ? domain::DeviceStatus::Active : domain::DeviceStatus::PendingAuthorization;

    const auto device_id = domain::Uuid::generate_v7();

    // 3. Persist Device Entity
    domain::DeviceEntity device{
        .device_id = device_id,
        .user_id = user_id,
        .device_status = initial_status,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    device_repo_->register_device(device);

    // 4. Persist Public Key Directory
    domain::DevicePublicKeyEntity id_key_entity{
        .key_id = domain::Uuid::generate_v7(),
        .device_id = device_id,
        .key_type = domain::KeyType::IdentitySigning,
        .public_key = std::vector<uint8_t>(identity_key.begin(), identity_key.end()),
        .key_status = domain::KeyStatus::Active,
        .created_at = now,
        .revoked_at = std::nullopt,
        .replaced_by_key_id = std::nullopt,
    };
    public_key_repo_->store_public_key(id_key_entity);

    domain::DevicePublicKeyEntity spk_entity{
        .key_id = domain::Uuid::generate_v7(),
        .device_id = device_id,
        .key_type = domain::KeyType::SignedPrekey,
        .public_key = std::vector<uint8_t>(signed_prekey.begin(), signed_prekey.end()),
        .key_status = domain::KeyStatus::Active,
        .created_at = now,
        .revoked_at = std::nullopt,
        .replaced_by_key_id = std::nullopt,
    };
    public_key_repo_->store_public_key(spk_entity);

    for (const auto& otk : one_time_prekeys) {
        domain::DevicePublicKeyEntity otk_entity{
            .key_id = domain::Uuid::generate_v7(),
            .device_id = device_id,
            .key_type = domain::KeyType::OneTimePrekey,
            .public_key = otk,
            .key_status = domain::KeyStatus::Active,
            .created_at = now,
            .revoked_at = std::nullopt,
            .replaced_by_key_id = std::nullopt,
        };
        public_key_repo_->store_public_key(otk_entity);
    }

    // 5. Handle Pending vs Active Return
    if (initial_status == domain::DeviceStatus::PendingAuthorization) {
        const std::string raw_code = generate_pairing_code_internal();
        const std::string formatted_code = raw_code.substr(0, 4) + "-" + raw_code.substr(4, 4);
        const auto expires_at = now + pairing_ttl_;

        {
            std::lock_guard<std::mutex> lock(challenge_mutex_);
            pairing_challenges_[device_id] = DevicePairingChallenge{
                .device_id = device_id,
                .user_id = user_id,
                .pairing_code = raw_code,
                .created_at = now,
                .expires_at = expires_at,
                .failed_attempts = 0,
                .is_consumed = false,
                .is_locked_out = false,
            };
        }

        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::device_enrolled(user_id, device_id, false, client_ip));
            audit_publisher_->publish(domain::AuditEvent::device_pairing_initiated(user_id, device_id, client_ip));
        }

        return DeviceEnrollmentResult{
            .success = true,
            .device_id = device_id,
            .status = domain::DeviceStatus::PendingAuthorization,
            .pairing_code = formatted_code,
            .pairing_code_expires_at = expires_at,
        };
    }

    if (audit_publisher_) {
        audit_publisher_->publish(domain::AuditEvent::device_enrolled(user_id, device_id, true, client_ip));
        audit_publisher_->publish(domain::AuditEvent::device_authorized(user_id, device_id, client_ip));
    }

    return DeviceEnrollmentResult{
        .success = true,
        .device_id = device_id,
        .status = domain::DeviceStatus::Active,
    };
}

std::optional<DevicePairingChallenge> DeviceManager::initiate_device_pairing(const domain::Uuid& user_id,
                                                                             const domain::Uuid& pending_device_id,
                                                                             std::string_view client_ip) {
    auto dev = device_repo_->find_by_id(pending_device_id);
    if (!dev.has_value() || dev->user_id != user_id) {
        return std::nullopt;
    }

    if (dev->device_status != domain::DeviceStatus::PendingAuthorization) {
        return std::nullopt;
    }

    const auto now = std::chrono::system_clock::now();
    const std::string raw_code = generate_pairing_code_internal();
    const auto expires_at = now + pairing_ttl_;

    DevicePairingChallenge challenge{
        .device_id = pending_device_id,
        .user_id = user_id,
        .pairing_code = raw_code,
        .created_at = now,
        .expires_at = expires_at,
        .failed_attempts = 0,
        .is_consumed = false,
        .is_locked_out = false,
    };

    {
        std::lock_guard<std::mutex> lock(challenge_mutex_);
        pairing_challenges_[pending_device_id] = challenge;
    }

    if (audit_publisher_) {
        audit_publisher_->publish(domain::AuditEvent::device_pairing_initiated(user_id, pending_device_id, client_ip));
    }

    // Return with formatted code
    challenge.pairing_code = raw_code.substr(0, 4) + "-" + raw_code.substr(4, 4);
    return challenge;
}

DeviceAuthorizationResult DeviceManager::authorize_device(const domain::Uuid& user_id, const domain::Uuid& device_id,
                                                          std::string_view pairing_code,
                                                          domain::AuthenticationLevel caller_auth_level,
                                                          std::string_view client_ip) {
    auto dev = device_repo_->find_by_id(device_id);
    if (!dev.has_value()) {
        return DeviceAuthorizationResult{
            .success = false,
            .error_message = "Device not found: " + device_id.to_string(),
        };
    }

    if (dev->user_id != user_id) {
        return DeviceAuthorizationResult{
            .success = false,
            .error_message = "Device does not belong to user: " + user_id.to_string(),
        };
    }

    if (dev->device_status == domain::DeviceStatus::Revoked) {
        return DeviceAuthorizationResult{
            .success = false,
            .status = domain::DeviceStatus::Revoked,
            .error_message = "Cannot authorize a revoked device",
        };
    }

    if (dev->device_status == domain::DeviceStatus::Active) {
        return DeviceAuthorizationResult{
            .success = false,
            .status = domain::DeviceStatus::Active,
            .error_message = "Device is already active",
        };
    }

    const auto now = std::chrono::system_clock::now();

    // 1. Direct MFA Step-Up bypasses pairing code verification
    if (caller_auth_level == domain::AuthenticationLevel::MfaVerified) {
        {
            std::lock_guard<std::mutex> lock(challenge_mutex_);
            auto it = pairing_challenges_.find(device_id);
            if (it != pairing_challenges_.end()) {
                it->second.is_consumed = true;
            }
        }

        try {
            device_repo_->authorize_device(device_id, now);
        } catch (const repository::RepositoryException& ex) {
            return DeviceAuthorizationResult{
                .success = false,
                .status = domain::DeviceStatus::Revoked,
                .error_message = ex.what(),
            };
        }

        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::device_authorized(user_id, device_id, client_ip));
        }

        return DeviceAuthorizationResult{
            .success = true,
            .device_id = device_id,
            .status = domain::DeviceStatus::Active,
        };
    }

    // 2. Cross-Device Pairing Code Verification
    std::lock_guard<std::mutex> lock(challenge_mutex_);
    auto it = pairing_challenges_.find(device_id);
    if (it == pairing_challenges_.end() || it->second.is_consumed) {
        return DeviceAuthorizationResult{
            .success = false,
            .error_message = "Pairing challenge not found or already consumed",
        };
    }

    auto& challenge = it->second;

    // Check expiration
    if (now > challenge.expires_at) {
        return DeviceAuthorizationResult{
            .success = false,
            .error_message = "Pairing challenge has expired",
        };
    }

    // Check lockout
    if (challenge.is_locked_out || challenge.failed_attempts >= kMaxFailedPairingAttempts) {
        challenge.is_locked_out = true;
        return DeviceAuthorizationResult{
            .success = false,
            .error_message = "Pairing challenge locked out due to too many failed attempts",
            .is_locked_out = true,
        };
    }

    // Verify code
    const std::string submitted_normalized = normalize_code(pairing_code);
    if (submitted_normalized != challenge.pairing_code) {
        challenge.failed_attempts++;
        if (challenge.failed_attempts >= kMaxFailedPairingAttempts) {
            challenge.is_locked_out = true;
        }
        return DeviceAuthorizationResult{
            .success = false,
            .error_message = "Invalid pairing code",
            .is_locked_out = challenge.is_locked_out,
        };
    }

    // Code matched!
    challenge.is_consumed = true;
    try {
        device_repo_->authorize_device(device_id, now);
    } catch (const repository::RepositoryException& ex) {
        return DeviceAuthorizationResult{
            .success = false,
            .status = domain::DeviceStatus::Revoked,
            .error_message = ex.what(),
        };
    }

    if (audit_publisher_) {
        audit_publisher_->publish(domain::AuditEvent::device_authorized(user_id, device_id, client_ip));
    }

    return DeviceAuthorizationResult{
        .success = true,
        .device_id = device_id,
        .status = domain::DeviceStatus::Active,
    };
}

DeviceRevocationResult DeviceManager::revoke_device(const domain::Uuid& user_id, const domain::Uuid& device_id,
                                                    std::string_view reason,
                                                    domain::AuthenticationLevel caller_auth_level,
                                                    std::string_view client_ip) {
    // 1. Enforce MFA verification requirement
    if (caller_auth_level != domain::AuthenticationLevel::MfaVerified) {
        return DeviceRevocationResult{
            .success = false,
            .device_id = device_id,
            .is_permission_denied = true,
            .error_message = "Device revocation requires multi-factor authentication (MFA_VERIFIED)",
        };
    }

    // 2. Fetch device record
    auto dev_opt = device_repo_->find_by_id(device_id);
    if (!dev_opt.has_value()) {
        return DeviceRevocationResult{
            .success = false,
            .device_id = device_id,
            .is_not_found = true,
            .error_message = "Device not found",
        };
    }

    // 3. Verify user ownership
    if (dev_opt->user_id != user_id) {
        return DeviceRevocationResult{
            .success = false,
            .device_id = device_id,
            .is_permission_denied = true,
            .error_message = "Device belongs to another user",
        };
    }

    // 4. Idempotency check: if already revoked, return success immediately
    if (dev_opt->device_status == domain::DeviceStatus::Revoked) {
        return DeviceRevocationResult{
            .success = true,
            .device_id = device_id,
        };
    }

    const auto now = std::chrono::system_clock::now();
    const std::string effective_reason = reason.empty() ? "Device revoked by user" : std::string(reason);

    // 5. Update device repository status to Revoked
    device_repo_->revoke_device(device_id, effective_reason, now);

    // 6. Cascade revocation to active sessions and refresh tokens
    session_manager_->revoke_all_device_sessions(device_id, effective_reason);

    // 7. Revoke all active public cryptographic keys bound to this device
    public_key_repo_->revoke_all_device_keys(device_id, now);

    // 8. Evict any pending pairing challenges for this device
    {
        std::lock_guard<std::mutex> lock(challenge_mutex_);
        pairing_challenges_.erase(device_id);
    }

    // 9. Emit audit event
    if (audit_publisher_) {
        audit_publisher_->publish(domain::AuditEvent::device_revoked(user_id, device_id, effective_reason, client_ip));
    }

    return DeviceRevocationResult{
        .success = true,
        .device_id = device_id,
    };
}

std::optional<domain::DeviceEntity> DeviceManager::get_device(const domain::Uuid& device_id) {
    return device_repo_->find_by_id(device_id);
}

std::vector<domain::DeviceEntity> DeviceManager::list_user_devices(const domain::Uuid& user_id, bool include_revoked) {
    return device_repo_->list_all_by_user_id(user_id, include_revoked);
}

} // namespace securecloud::auth::service
