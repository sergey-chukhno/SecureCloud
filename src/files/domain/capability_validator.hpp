#pragma once

#include "auth/crypto/token_crypto.hpp"
#include "files/domain/file_capability_entity.hpp"
#include "files/domain/metadata_validator.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <string>

namespace securecloud::files {

/// Input bundle encapsulating presented capability and runtime request context
struct CapabilityValidationInput {
    std::string presented_token;
    std::string caller_user_id;
    std::string caller_device_id;
    std::string target_file_id;
    int32_t requested_version{0}; // 0 = any/active version
    FileCapabilityOperation requested_operation{FileCapabilityOperation::Read};
    bool is_device_revoked{false};
    std::chrono::system_clock::time_point current_time{std::chrono::system_clock::now()};
    std::chrono::seconds clock_skew_tolerance{30};
};

/// Result of capability validation
struct CapabilityValidationResult {
    bool is_valid{false};
    std::string error_message;
    std::optional<FileAccessCapabilityClaims> verified_claims{std::nullopt};

    [[nodiscard]] explicit operator bool() const noexcept { return is_valid; }

    static CapabilityValidationResult success(FileAccessCapabilityClaims claims) noexcept {
        return {true, "", std::move(claims)};
    }

    static CapabilityValidationResult failure(std::string message) { return {false, std::move(message), std::nullopt}; }
};

/**
 * @brief Authoritative capability validation engine enforcing all 6 security invariants:
 * 1. Cryptographic Ed25519 signature validity.
 * 2. Temporal validity: not expired and not premature (anti-replay).
 * 3. Authenticated user binding (User A != User B).
 * 4. Authenticated device binding (Device A != Device B).
 * 5. Specific file scoping (File 1 != File 2).
 * 6. Authorized operation scoping (Read, Write, Delete).
 * 7. Pinned version enforcement (if version > 0).
 * 8. Active device status enforcement (revoked device rejection).
 */
class CapabilityValidator {
  public:
    explicit CapabilityValidator(std::shared_ptr<auth::crypto::ITokenVerifier> verifier);

    [[nodiscard]] CapabilityValidationResult validate(const CapabilityValidationInput& input) const;

  private:
    std::shared_ptr<auth::crypto::ITokenVerifier> verifier_;
};

} // namespace securecloud::files
