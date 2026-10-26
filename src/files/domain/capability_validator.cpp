#include "files/domain/capability_validator.hpp"
#include "files/domain/file_capability_serializer.hpp"

namespace securecloud::files {

CapabilityValidator::CapabilityValidator(std::shared_ptr<auth::crypto::ITokenVerifier> verifier)
    : verifier_(std::move(verifier)) {
    if (!verifier_) {
        throw std::invalid_argument("CapabilityValidator: token verifier cannot be null");
    }
}

CapabilityValidationResult CapabilityValidator::validate(const CapabilityValidationInput& input) const {
    // 1. Check presented token presence
    if (input.presented_token.empty()) {
        return CapabilityValidationResult::failure("Missing file-access capability token");
    }

    // 2. Validate caller identity parameters
    if (input.caller_user_id.empty() || !is_valid_uuid(input.caller_user_id)) {
        return CapabilityValidationResult::failure("Invalid or missing authenticated caller user_id");
    }
    if (input.caller_device_id.empty() || !is_valid_uuid(input.caller_device_id)) {
        return CapabilityValidationResult::failure("Invalid or missing authenticated caller device_id");
    }

    // 3. Validate target file parameter
    if (input.target_file_id.empty() || !is_valid_uuid(input.target_file_id)) {
        return CapabilityValidationResult::failure("Invalid or missing target file_id");
    }

    // 4. Instant revocation check: revoked devices cannot exercise capabilities
    if (input.is_device_revoked) {
        return CapabilityValidationResult::failure("Caller device has been revoked");
    }

    // 5. Cryptographic signature and structural parsing
    std::string deserialize_error;
    auto claims_opt = FileCapabilitySerializer::deserialize_and_verify(
        input.presented_token, *verifier_, &deserialize_error);

    if (!claims_opt.has_value()) {
        return CapabilityValidationResult::failure(
            deserialize_error.empty() ? "Invalid capability token" : deserialize_error);
    }

    const auto& claims = *claims_opt;

    // 6. Temporal lifetime verification (expiration and anti-replay)
    if (claims.is_expired(input.current_time, input.clock_skew_tolerance)) {
        return CapabilityValidationResult::failure("Capability token has expired");
    }

    if (claims.is_premature(input.current_time, input.clock_skew_tolerance)) {
        return CapabilityValidationResult::failure("Capability token is not yet valid (premature timestamp)");
    }

    // 7. Strict User Binding (User A != User B)
    if (claims.user_id != input.caller_user_id) {
        return CapabilityValidationResult::failure(
            "Capability user mismatch: token was not issued for caller user");
    }

    // 8. Strict Device Binding (Device A != Device B)
    if (claims.device_id != input.caller_device_id) {
        return CapabilityValidationResult::failure(
            "Capability device mismatch: token was not issued for caller device");
    }

    // 9. Strict File Scoping (File 1 != File 2)
    if (claims.file_id != input.target_file_id) {
        return CapabilityValidationResult::failure(
            "Capability file mismatch: token was not issued for requested file");
    }

    // 10. Operation Authorization Scoping
    if (claims.operation != input.requested_operation) {
        return CapabilityValidationResult::failure(
            "Capability operation mismatch: requested operation is not permitted by capability");
    }

    // 11. Pinned Version Scoping
    if (claims.file_version > 0 && input.requested_version > 0 && claims.file_version != input.requested_version) {
        return CapabilityValidationResult::failure(
            "Capability version mismatch: token is pinned to a different file version");
    }

    return CapabilityValidationResult::success(claims);
}

} // namespace securecloud::files
