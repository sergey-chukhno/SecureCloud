#include "files/service/file_capability_manager.hpp"

#include "files/domain/metadata_validator.hpp"

#include <stdexcept>

namespace securecloud::files {

namespace {

FilePermission to_required_permission(FileCapabilityOperation op) {
    switch (op) {
    case FileCapabilityOperation::Read:
    case FileCapabilityOperation::Metadata:
        return FilePermission::Read;
    case FileCapabilityOperation::Write:
        return FilePermission::Write;
    case FileCapabilityOperation::Delete:
        return FilePermission::Admin;
    }
    return FilePermission::Read;
}

} // namespace

FileCapabilityManager::FileCapabilityManager(std::shared_ptr<db::FilesDbConnectionPool> pool,
                                             std::shared_ptr<auth::crypto::ITokenSigner> signer,
                                             std::shared_ptr<auth::crypto::ITokenVerifier> verifier,
                                             std::shared_ptr<IDeviceRevocationProvider> revocation_provider,
                                             std::shared_ptr<FileAccessRepository> access_repo)
    : pool_(std::move(pool)), signer_(std::move(signer)), verifier_(std::move(verifier)),
      revocation_provider_(std::move(revocation_provider)), access_repo_(std::move(access_repo)) {
    if (!signer_) {
        throw std::invalid_argument("FileCapabilityManager: signer cannot be null");
    }
    if (!verifier_) {
        throw std::invalid_argument("FileCapabilityManager: verifier cannot be null");
    }
    if (!revocation_provider_) {
        revocation_provider_ = std::make_shared<DeviceRevocationProvider>(pool_);
    }
    if (!access_repo_) {
        access_repo_ = std::make_shared<FileAccessRepository>(pool_);
    }

    validator_ = std::make_unique<CapabilityValidator>(verifier_);
}

std::string FileCapabilityManager::issue_capability(const std::string& grantee_user_id,
                                                    const std::string& grantee_device_id, const std::string& file_id,
                                                    FileCapabilityOperation operation, int32_t file_version,
                                                    std::chrono::seconds ttl) {
    // 1. Parameter format validation
    if (!is_valid_uuid(grantee_user_id)) {
        throw std::invalid_argument("Invalid grantee_user_id format: " + grantee_user_id);
    }
    if (!is_valid_uuid(grantee_device_id)) {
        throw std::invalid_argument("Invalid grantee_device_id format: " + grantee_device_id);
    }
    if (!is_valid_uuid(file_id)) {
        throw std::invalid_argument("Invalid file_id format: " + file_id);
    }

    // 2. Check if device is revoked
    if (revocation_provider_->is_device_revoked(grantee_device_id)) {
        throw UnauthorizedFileAccessException("Grantee device has been revoked: " + grantee_device_id);
    }

    // 3. Check database permissions if DB pool and repository are available
    if (pool_ && access_repo_) {
        const auto req_perm = to_required_permission(operation);
        bool has_access = access_repo_->check_access(file_id, grantee_user_id, req_perm);
        if (!has_access) {
            throw UnauthorizedFileAccessException("User '" + grantee_user_id +
                                                  "' lacks required permission for file '" + file_id + "'");
        }
    }

    // 4. Construct claims
    auto now = std::chrono::system_clock::now();
    FileAccessCapabilityClaims claims{.capability_id = generate_uuid_v7(),
                                      .user_id = grantee_user_id,
                                      .device_id = grantee_device_id,
                                      .file_id = file_id,
                                      .file_version = file_version,
                                      .operation = operation,
                                      .issued_at = std::chrono::time_point_cast<std::chrono::seconds>(now),
                                      .expires_at = std::chrono::time_point_cast<std::chrono::seconds>(now + ttl),
                                      .issuer = "securecloud-files"};

    // 5. Serialize and cryptographically sign
    return FileCapabilitySerializer::serialize(claims, *signer_);
}

FileAccessCapabilityClaims
FileCapabilityManager::authorize_capability(std::string_view token, const std::string& caller_user_id,
                                            const std::string& caller_device_id, const std::string& target_file_id,
                                            FileCapabilityOperation requested_operation, int32_t requested_version) {
    if (token.empty()) {
        throw InvalidCapabilityException("Missing required file-access capability token");
    }

    bool is_revoked = revocation_provider_->is_device_revoked(caller_device_id);

    CapabilityValidationInput input{.presented_token = std::string(token),
                                    .caller_user_id = caller_user_id,
                                    .caller_device_id = caller_device_id,
                                    .target_file_id = target_file_id,
                                    .requested_version = requested_version,
                                    .requested_operation = requested_operation,
                                    .is_device_revoked = is_revoked};

    auto result = validator_->validate(input);
    if (!result.is_valid) {
        // Map to appropriate exception hierarchy
        if (result.error_message.find("signature") != std::string::npos ||
            result.error_message.find("Malformed") != std::string::npos ||
            result.error_message.find("Unsupported") != std::string::npos) {
            throw InvalidCapabilityException(result.error_message);
        }
        throw UnauthorizedFileAccessException(result.error_message);
    }

    return *result.verified_claims;
}

} // namespace securecloud::files
