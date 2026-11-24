#include "files/service/file_capability_manager.hpp"

#include "files/domain/metadata_validator.hpp"
#include "files/repository/files_outbox_repository.hpp"
#include "files/service/files_caller_context.hpp"

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

[[nodiscard]] std::string resolve_capability_correlation_id() {
    if (const auto ctx = service::current_files_caller_context(); ctx && !ctx->correlation_id.empty()) {
        return ctx->correlation_id;
    }
    return generate_uuid_v7();
}

[[nodiscard]] std::string classify_rejection_reason(std::string_view err, bool is_revoked) {
    if (is_revoked || err.find("revoked") != std::string_view::npos || err.find("Revoked") != std::string_view::npos) {
        return "device_revoked";
    }
    if (err.find("expired") != std::string_view::npos || err.find("Expired") != std::string_view::npos) {
        return "expired";
    }
    if (err.find("signature") != std::string_view::npos || err.find("Malformed") != std::string_view::npos ||
        err.find("Unsupported") != std::string_view::npos) {
        return "invalid_signature";
    }
    if (err.find("mismatch") != std::string_view::npos || err.find("scope") != std::string_view::npos ||
        err.find("file") != std::string_view::npos || err.find("device") != std::string_view::npos ||
        err.find("user") != std::string_view::npos || err.find("operation") != std::string_view::npos ||
        err.find("version") != std::string_view::npos) {
        return "scope_mismatch";
    }
    return "invalid_capability";
}

void emit_capability_rejected(const std::shared_ptr<service::FilesAuditEventPublisher>& publisher,
                              const std::string& caller_user_id, const std::string& caller_device_id,
                              const std::string& target_file_id, FileCapabilityOperation op,
                              std::string_view reason) noexcept {
    if (!publisher) {
        return;
    }
    service::FilesAuditRecord record;
    record.event_type = "file.capability.rejected";
    record.severity = "SECURITY";
    record.actor_type = caller_user_id.empty() || caller_user_id == "system" ? "SYSTEM" : "USER";
    record.actor_id = caller_user_id.empty() ? "unknown" : caller_user_id;
    record.target_type = target_file_id.empty() ? "SERVICE" : "FILE";
    record.target_id = target_file_id.empty() ? "files" : target_file_id;
    record.correlation_id = resolve_capability_correlation_id();
    record.metadata = {{"reason", std::string(reason)},
                       {"requested_operation", std::string(to_string(op))},
                       {"device_id", caller_device_id.empty() ? "unknown" : caller_device_id}};
    publisher->publish_autonomous(record);
}

} // namespace

FileCapabilityManager::FileCapabilityManager(std::shared_ptr<db::FilesDbConnectionPool> pool,
                                             std::shared_ptr<auth::crypto::ITokenSigner> signer,
                                             std::shared_ptr<auth::crypto::ITokenVerifier> verifier,
                                             std::shared_ptr<IDeviceRevocationProvider> revocation_provider,
                                             std::shared_ptr<FileAccessRepository> access_repo,
                                             std::shared_ptr<service::FilesAuditEventPublisher> audit_publisher)
    : pool_(std::move(pool)), signer_(std::move(signer)), verifier_(std::move(verifier)),
      revocation_provider_(std::move(revocation_provider)), access_repo_(std::move(access_repo)),
      audit_publisher_(std::move(audit_publisher)) {
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
    if (!audit_publisher_ && pool_) {
        audit_publisher_ =
            std::make_shared<service::FilesAuditEventPublisher>(std::make_shared<FilesOutboxRepository>(pool_));
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
        emit_capability_rejected(audit_publisher_, grantee_user_id, grantee_device_id, file_id, operation,
                                 "device_revoked");
        throw UnauthorizedFileAccessException("Grantee device has been revoked: " + grantee_device_id);
    }

    // 3. Check database permissions if DB pool and repository are available
    if (pool_ && access_repo_) {
        const auto req_perm = to_required_permission(operation);
        bool has_access = access_repo_->check_access(file_id, grantee_user_id, req_perm);
        if (!has_access) {
            if (audit_publisher_) {
                service::FilesAuditRecord denied;
                denied.event_type = "file.access.denied";
                denied.severity = "SECURITY";
                denied.actor_type = "USER";
                denied.actor_id = grantee_user_id;
                denied.target_type = "FILE";
                denied.target_id = file_id;
                denied.correlation_id = resolve_capability_correlation_id();
                denied.metadata = {{"operation", "IssueCapability"},
                                   {"reason", "missing_permission"},
                                   {"device_id", grantee_device_id}};
                audit_publisher_->publish_autonomous(denied);
            }
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

    // 5. Serialize and cryptographically sign (never audit the serialized token string)
    std::string serialized_token = FileCapabilitySerializer::serialize(claims, *signer_);

    if (audit_publisher_) {
        service::FilesAuditRecord issued;
        issued.event_type = "file.capability.issued";
        issued.severity = "INFO";
        issued.actor_type = "USER";
        issued.actor_id = grantee_user_id;
        issued.target_type = "FILE";
        issued.target_id = file_id;
        issued.correlation_id = resolve_capability_correlation_id();
        issued.metadata = {{"capability_id", claims.capability_id},
                           {"grantee_device_id", grantee_device_id},
                           {"operation", std::string(to_string(operation))},
                           {"file_version", std::to_string(file_version)},
                           {"ttl_seconds", std::to_string(ttl.count())}};
        audit_publisher_->publish_autonomous(issued);
    }

    return serialized_token;
}

FileAccessCapabilityClaims
FileCapabilityManager::authorize_capability(std::string_view token, const std::string& caller_user_id,
                                            const std::string& caller_device_id, const std::string& target_file_id,
                                            FileCapabilityOperation requested_operation, int32_t requested_version) {
    if (token.empty()) {
        emit_capability_rejected(audit_publisher_, caller_user_id, caller_device_id, target_file_id,
                                 requested_operation, "missing");
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
        emit_capability_rejected(audit_publisher_, caller_user_id, caller_device_id, target_file_id,
                                 requested_operation, classify_rejection_reason(result.error_message, is_revoked));
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
