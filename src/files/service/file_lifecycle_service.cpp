#include "files/service/file_lifecycle_service.hpp"

#include "files/db/files_connection_pool.hpp"
#include "files/db/pqxx_mappers.hpp"
#include "files/service/files_caller_context.hpp"

#include <algorithm>
#include <utility>

namespace securecloud::files {

namespace {

[[nodiscard]] std::string resolve_correlation_id() {
    if (const auto ctx = service::current_files_caller_context(); ctx && !ctx->correlation_id.empty()) {
        return ctx->correlation_id;
    }
    return generate_uuid_v7();
}

[[nodiscard]] std::string resolve_actor_type(std::string_view actor_id) noexcept {
    if (actor_id.empty() || actor_id == "system") {
        return "SYSTEM";
    }
    if (actor_id == "gateway" || actor_id == "files" || actor_id == "auth" || actor_id == "messaging" ||
        actor_id == "audit" || actor_id == "authenticated_peer") {
        return "SERVICE";
    }
    return "USER";
}

[[nodiscard]] std::string canonical_event_type_for_status(FileStatus status) {
    switch (status) {
    case FileStatus::Available:
        return "file.upload.completed";
    case FileStatus::Failed:
        return "file.finalization.failed";
    case FileStatus::Expired:
        return "file.expired";
    case FileStatus::Deleted:
        return "file.deleted";
    case FileStatus::Uploading:
        return "file.upload.initiated";
    case FileStatus::Finalizing:
        return "file.upload.finalizing";
    case FileStatus::Created:
        return "file.created";
    }
    return "file.status_changed";
}

[[nodiscard]] std::string severity_for_status(FileStatus status) {
    if (status == FileStatus::Failed) {
        return "WARNING";
    }
    return "INFO";
}

} // namespace

FileLifecycleService::FileLifecycleService(std::shared_ptr<db::FilesDbConnectionPool> pool,
                                           std::shared_ptr<FileRepository> file_repo,
                                           std::shared_ptr<FileVersionRepository> version_repo,
                                           std::shared_ptr<FileAccessRepository> access_repo,
                                           std::shared_ptr<FilesOutboxRepository> outbox_repo,
                                           std::shared_ptr<service::FilesAuditEventPublisher> audit_publisher)
    : pool_(std::move(pool)), file_repo_(file_repo ? std::move(file_repo) : std::make_shared<FileRepository>(pool_)),
      version_repo_(version_repo ? std::move(version_repo) : std::make_shared<FileVersionRepository>(pool_)),
      access_repo_(access_repo ? std::move(access_repo) : std::make_shared<FileAccessRepository>(pool_)),
      outbox_repo_(outbox_repo ? std::move(outbox_repo) : std::make_shared<FilesOutboxRepository>(pool_)),
      audit_publisher_(audit_publisher ? std::move(audit_publisher)
                                       : std::make_shared<service::FilesAuditEventPublisher>(outbox_repo_)) {}

std::string FileLifecycleService::create_file(const CreateFileRequestDto& dto,
                                              std::chrono::system_clock::time_point now) {
    auto val_res = validate_create_file_request(dto, now);
    if (!val_res) {
        throw FileLifecycleValidationException("Validation failed for CreateFileRequest: " + val_res.error_message);
    }

    if (!pool_) {
        return dto.file_id;
    }

    auto conn = pool_->acquire();

    auto& default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*conn);
    pqxx::work tx(default_conn.native_handle());

    auto existing = file_repo_->find_by_id(dto.file_id, tx);
    if (existing.has_value()) {
        throw FileLifecycleValidationException("File with id '" + dto.file_id + "' already exists");
    }

    FileEntity file{
        .file_id = dto.file_id,
        .owner_user_id = dto.owner_user_id,
        .owner_device_id = dto.owner_device_id,
        .conversation_id = dto.conversation_id,
        .encrypted_size = static_cast<int64_t>(dto.encrypted_size_bytes),
        .content_type = std::nullopt,
        .encryption_algorithm = dto.encryption_algorithm,
        .status = FileStatus::Created,
        .retention_until = dto.retention_until,
        .created_at = now,
        .updated_at = now,
    };

    EncryptedFileMetadataEntity meta{
        .file_id = dto.file_id,
        .encrypted_filename = dto.encrypted_filename,
        .encrypted_mime_type = dto.encrypted_mime_type,
        .metadata_nonce = dto.metadata_nonce,
        .metadata_tag = dto.metadata_tag,
        .client_encryption_metadata_json = dto.client_encryption_metadata_json,
        .updated_at = now,
    };

    file_repo_->create_file(file, meta, tx);

    if (audit_publisher_) {
        service::FilesAuditRecord record;
        record.event_type = "file.created";
        record.severity = "INFO";
        record.actor_type = resolve_actor_type(dto.owner_user_id);
        record.actor_id = dto.owner_user_id.empty() ? "system" : dto.owner_user_id;
        record.target_type = "FILE";
        record.target_id = dto.file_id;
        record.correlation_id = resolve_correlation_id();
        record.metadata = {{"owner_device_id", dto.owner_device_id},
                           {"encrypted_size_bytes", std::to_string(dto.encrypted_size_bytes)},
                           {"chunk_count", std::to_string(dto.expected_chunk_count)},
                           {"encryption_algorithm", dto.encryption_algorithm}};
        if (dto.conversation_id.has_value() && !dto.conversation_id->empty()) {
            record.metadata.emplace("conversation_id", *dto.conversation_id);
        }
        audit_publisher_->publish_in_tx(record, tx);
    }

    tx.commit();
    if (audit_publisher_) {
        audit_publisher_->notify_relay();
    }
    return dto.file_id;
}

FileVersionEntity FileLifecycleService::create_file_version(const CreateFileVersionRequestDto& dto,
                                                            const std::string& caller_user_id) {
    auto val_res = validate_create_version_request(dto);
    if (!val_res) {
        throw FileLifecycleValidationException("Validation failed for CreateFileVersionRequest: " +
                                               val_res.error_message);
    }

    if (!pool_) {
        return FileVersionEntity{
            .version_id = generate_uuid_v7(),
            .file_id = dto.file_id,
            .version_number = dto.version_number,
            .encrypted_size = static_cast<int64_t>(dto.encrypted_size_bytes),
            .minio_object_key = dto.minio_object_key,
            .checksum_sha256 = dto.checksum_sha256,
            .created_at = std::chrono::system_clock::now(),
            .is_active = true,
        };
    }

    bool unauthorized = false;
    std::optional<FileVersionEntity> created_version;
    {
        auto conn = pool_->acquire();

        auto& default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*conn);
        pqxx::work tx(default_conn.native_handle());

        auto file_opt = file_repo_->find_by_id(dto.file_id, tx);
        if (!file_opt.has_value()) {
            throw FileNotFoundException("File not found: " + dto.file_id);
        }

        if (!check_ownership_or_access(*file_opt, caller_user_id, "WRITE", tx)) {
            tx.abort();
            unauthorized = true;
        } else {
            // Enforce Immutable Completed Versions Invariant:
            // Once a version is created and active, its object key and checksum must never be modified.
            // New versions strictly receive an incremented version number.
            auto existing_versions = version_repo_->list_versions(dto.file_id, tx);
            int32_t max_ver = 0;
            for (const auto& v : existing_versions) {
                if (v.version_number > max_ver) {
                    max_ver = v.version_number;
                }
                if (v.minio_object_key == dto.minio_object_key && v.checksum_sha256 != dto.checksum_sha256) {
                    throw ImmutableVersionException("Attempted mutation of existing completed version object key '" +
                                                    dto.minio_object_key + "'");
                }
            }

            int32_t assigned_version = (dto.version_number > max_ver) ? dto.version_number : (max_ver + 1);

            auto now = std::chrono::system_clock::now();
            FileVersionEntity version{
                .version_id = generate_uuid_v7(),
                .file_id = dto.file_id,
                .version_number = assigned_version,
                .encrypted_size = static_cast<int64_t>(dto.encrypted_size_bytes),
                .minio_object_key = dto.minio_object_key,
                .checksum_sha256 = dto.checksum_sha256,
                .created_at = now,
                .is_active = true,
            };

            version_repo_->create_version(version, tx);

            if (audit_publisher_) {
                const std::string effective_actor = caller_user_id.empty() ? file_opt->owner_user_id : caller_user_id;
                service::FilesAuditRecord record;
                record.event_type = "file.version.created";
                record.severity = "INFO";
                record.actor_type = resolve_actor_type(effective_actor);
                record.actor_id = effective_actor.empty() ? "system" : effective_actor;
                record.target_type = "FILE";
                record.target_id = dto.file_id;
                record.correlation_id = resolve_correlation_id();
                record.metadata = {{"version_id", version.version_id},
                                   {"version_number", std::to_string(version.version_number)},
                                   {"encrypted_size_bytes", std::to_string(version.encrypted_size)}};
                audit_publisher_->publish_in_tx(record, tx);
            }

            tx.commit();
            created_version = std::move(version);
        }
    }

    if (unauthorized) {
        if (audit_publisher_ && !service::current_files_caller_context().has_value()) {
            service::FilesAuditRecord denied;
            denied.event_type = "file.access.denied";
            denied.severity = "SECURITY";
            denied.actor_type = resolve_actor_type(caller_user_id);
            denied.actor_id = caller_user_id.empty() ? "unknown" : caller_user_id;
            denied.target_type = "FILE";
            denied.target_id = dto.file_id;
            denied.correlation_id = resolve_correlation_id();
            denied.metadata = {{"operation", "create_file_version"}, {"reason", "unauthorized_write"}};
            audit_publisher_->publish_autonomous(denied);
        }
        throw UnauthorizedFileAccessException("Caller '" + caller_user_id +
                                              "' is not authorized to create versions for file '" + dto.file_id + "'");
    }

    if (audit_publisher_) {
        audit_publisher_->notify_relay();
    }
    return *created_version;
}

bool FileLifecycleService::transition_lifecycle(const std::string& file_id, FileStatus expected_current,
                                                FileStatus new_status, const std::string& caller_user_id,
                                                const std::string& reason) {
    assert_valid_state_transition(expected_current, new_status);

    if (!pool_) {
        return true;
    }

    bool unauthorized = false;
    bool updated = false;
    {
        auto conn = pool_->acquire();

        auto& default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*conn);
        pqxx::work tx(default_conn.native_handle());

        auto file_opt = file_repo_->find_by_id(file_id, tx);
        if (!file_opt.has_value()) {
            throw FileNotFoundException("File not found for lifecycle transition: " + file_id);
        }

        if (!check_ownership_or_access(*file_opt, caller_user_id, "WRITE", tx)) {
            tx.abort();
            unauthorized = true;
        } else {
            updated = file_repo_->update_status(file_id, expected_current, new_status, tx);
            if (updated) {
                if (audit_publisher_) {
                    const std::string effective_actor =
                        caller_user_id.empty() ? file_opt->owner_user_id : caller_user_id;
                    service::FilesAuditRecord record;
                    record.event_type = canonical_event_type_for_status(new_status);
                    record.severity = severity_for_status(new_status);
                    record.actor_type = resolve_actor_type(effective_actor);
                    record.actor_id = effective_actor.empty() ? "system" : effective_actor;
                    record.target_type = "FILE";
                    record.target_id = file_id;
                    record.correlation_id = resolve_correlation_id();
                    record.metadata = {{"old_status", db::to_string(expected_current)},
                                       {"new_status", db::to_string(new_status)}};
                    if (!reason.empty()) {
                        record.metadata.emplace("reason", reason);
                    }
                    audit_publisher_->publish_in_tx(record, tx);
                }

                tx.commit();
            }
        }
    }

    if (unauthorized) {
        if (audit_publisher_ && !service::current_files_caller_context().has_value()) {
            service::FilesAuditRecord denied;
            denied.event_type = "file.access.denied";
            denied.severity = "SECURITY";
            denied.actor_type = resolve_actor_type(caller_user_id);
            denied.actor_id = caller_user_id.empty() ? "unknown" : caller_user_id;
            denied.target_type = "FILE";
            denied.target_id = file_id;
            denied.correlation_id = resolve_correlation_id();
            denied.metadata = {{"operation", "transition_lifecycle"}, {"reason", "unauthorized_write"}};
            audit_publisher_->publish_autonomous(denied);
        }
        throw UnauthorizedFileAccessException("Caller '" + caller_user_id + "' is not authorized to transition file '" +
                                              file_id + "'");
    }

    if (!updated) {
        return false;
    }

    if (audit_publisher_) {
        audit_publisher_->notify_relay();
    }
    return true;
}

std::optional<FileMetadataSummary> FileLifecycleService::get_file_metadata(const std::string& file_id,
                                                                           const std::string& caller_user_id) {
    if (!pool_) {
        return std::nullopt;
    }

    bool unauthorized = false;
    std::optional<FileMetadataSummary> summary;
    {
        auto conn = pool_->acquire();

        auto& default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*conn);
        pqxx::work tx(default_conn.native_handle());

        auto file_opt = file_repo_->find_by_id(file_id, tx);
        if (file_opt.has_value()) {
            if (!check_ownership_or_access(*file_opt, caller_user_id, "READ", tx)) {
                tx.abort();
                unauthorized = true;
            } else {
                auto meta_opt = file_repo_->find_encrypted_metadata(file_id, tx);
                auto active_version = version_repo_->find_active_version(file_id, tx);
                auto all_versions = version_repo_->list_versions(file_id, tx);
                uint32_t chunk_count = calculate_expected_chunk_count(static_cast<uint64_t>(file_opt->encrypted_size));

                summary = FileMetadataSummary{
                    .file = *file_opt,
                    .encrypted_meta = meta_opt.value_or(EncryptedFileMetadataEntity{}),
                    .active_version = active_version,
                    .all_versions = std::move(all_versions),
                    .expected_chunk_count = chunk_count,
                };
            }
        }
    }

    if (unauthorized) {
        if (audit_publisher_ && !service::current_files_caller_context().has_value()) {
            service::FilesAuditRecord denied;
            denied.event_type = "file.access.denied";
            denied.severity = "SECURITY";
            denied.actor_type = resolve_actor_type(caller_user_id);
            denied.actor_id = caller_user_id.empty() ? "unknown" : caller_user_id;
            denied.target_type = "FILE";
            denied.target_id = file_id;
            denied.correlation_id = resolve_correlation_id();
            denied.metadata = {{"operation", "get_file_metadata"}, {"reason", "unauthorized_read"}};
            audit_publisher_->publish_autonomous(denied);
        }
        throw UnauthorizedFileAccessException("Caller '" + caller_user_id +
                                              "' is not authorized to read metadata for file '" + file_id + "'");
    }

    return summary;
}

bool FileLifecycleService::check_ownership_or_access(const FileEntity& file, const std::string& caller_user_id,
                                                     std::string_view permission, pqxx::work& tx) {
    if (caller_user_id.empty() || caller_user_id == "system" || caller_user_id == "authenticated_peer" ||
        caller_user_id == "gateway") {
        return true;
    }
    if (file.owner_user_id == caller_user_id) {
        return true;
    }
    FilePermission perm =
        (permission == "WRITE" || permission == "ADMIN") ? FilePermission::Write : FilePermission::Read;
    return access_repo_->check_access(file.file_id, caller_user_id, perm, tx);
}

bool FileLifecycleService::delete_file(const std::string& file_id, const std::string& caller_user_id,
                                       const std::string& reason) {
    if (!pool_) {
        return true;
    }

    bool unauthorized = false;
    bool already_deleted = false;
    bool updated = false;
    {
        auto conn = pool_->acquire();

        auto& default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*conn);
        pqxx::work tx(default_conn.native_handle());

        auto file_opt = file_repo_->find_by_id(file_id, tx);
        if (!file_opt.has_value()) {
            throw FileNotFoundException("File not found for deletion: " + file_id);
        }

        if (!check_ownership_or_access(*file_opt, caller_user_id, "WRITE", tx)) {
            tx.abort();
            unauthorized = true;
        } else if (file_opt->status == FileStatus::Deleted) {
            already_deleted = true;
        } else {
            assert_valid_state_transition(file_opt->status, FileStatus::Deleted);

            updated = file_repo_->update_status(file_id, file_opt->status, FileStatus::Deleted, tx);
            if (updated) {
                if (audit_publisher_) {
                    const std::string effective_actor =
                        caller_user_id.empty() ? file_opt->owner_user_id : caller_user_id;
                    service::FilesAuditRecord record;
                    record.event_type = "file.deleted";
                    record.severity = "INFO";
                    record.actor_type = resolve_actor_type(effective_actor);
                    record.actor_id = effective_actor.empty() ? "system" : effective_actor;
                    record.target_type = "FILE";
                    record.target_id = file_id;
                    record.correlation_id = resolve_correlation_id();
                    record.metadata = {{"previous_status", db::to_string(file_opt->status)}};
                    if (!reason.empty()) {
                        record.metadata.emplace("reason", reason);
                    }
                    audit_publisher_->publish_in_tx(record, tx);
                }

                tx.commit();
            }
        }
    }

    if (unauthorized) {
        if (audit_publisher_ && !service::current_files_caller_context().has_value()) {
            service::FilesAuditRecord denied;
            denied.event_type = "file.access.denied";
            denied.severity = "SECURITY";
            denied.actor_type = resolve_actor_type(caller_user_id);
            denied.actor_id = caller_user_id.empty() ? "unknown" : caller_user_id;
            denied.target_type = "FILE";
            denied.target_id = file_id;
            denied.correlation_id = resolve_correlation_id();
            denied.metadata = {{"operation", "delete_file"}, {"reason", "unauthorized_delete"}};
            audit_publisher_->publish_autonomous(denied);
        }
        throw UnauthorizedFileAccessException("Caller '" + caller_user_id + "' is not authorized to delete file '" +
                                              file_id + "'");
    }

    if (already_deleted) {
        return true; // Idempotent success
    }
    if (!updated) {
        return false;
    }

    if (audit_publisher_) {
        audit_publisher_->notify_relay();
    }
    return true;
}

void FileLifecycleService::grant_file_access(const FileAccessEntity& grant, const std::string& reason) {
    if (!pool_) {
        return;
    }

    auto conn = pool_->acquire();
    auto& default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*conn);
    pqxx::work tx(default_conn.native_handle());

    access_repo_->grant_access(grant, tx);

    if (audit_publisher_) {
        service::FilesAuditRecord record;
        record.event_type = "file.access.granted";
        record.severity = "INFO";
        record.actor_type = resolve_actor_type(grant.granted_by);
        record.actor_id = grant.granted_by.empty() ? "system" : grant.granted_by;
        record.target_type = "FILE";
        record.target_id = grant.file_id;
        record.correlation_id = resolve_correlation_id();
        record.metadata = {{"grantee_user_id", grant.grantee_user_id}, {"permission", db::to_string(grant.permission)}};
        if (grant.grantee_device_id.has_value() && !grant.grantee_device_id->empty()) {
            record.metadata.emplace("grantee_device_id", *grant.grantee_device_id);
        }
        if (!reason.empty()) {
            record.metadata.emplace("reason", reason);
        }
        audit_publisher_->publish_in_tx(record, tx);
    }

    tx.commit();
    if (audit_publisher_) {
        audit_publisher_->notify_relay();
    }
}

bool FileLifecycleService::revoke_file_access(const std::string& file_id, const std::string& grantee_user_id,
                                              const std::string& caller_user_id, const std::string& reason) {
    if (!pool_) {
        return false;
    }

    auto conn = pool_->acquire();
    auto& default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*conn);
    pqxx::work tx(default_conn.native_handle());

    const bool revoked = access_repo_->revoke_access(file_id, grantee_user_id, tx);
    if (!revoked) {
        return false;
    }

    if (audit_publisher_) {
        service::FilesAuditRecord record;
        record.event_type = "file.access.revoked";
        record.severity = "SECURITY";
        record.actor_type = resolve_actor_type(caller_user_id);
        record.actor_id = caller_user_id.empty() ? "system" : caller_user_id;
        record.target_type = "FILE";
        record.target_id = file_id;
        record.correlation_id = resolve_correlation_id();
        record.metadata = {{"grantee_user_id", grantee_user_id}};
        if (!reason.empty()) {
            record.metadata.emplace("reason", reason);
        }
        audit_publisher_->publish_in_tx(record, tx);
    }

    tx.commit();
    if (audit_publisher_) {
        audit_publisher_->notify_relay();
    }
    return true;
}

size_t FileLifecycleService::evaluate_and_expire_files(std::chrono::system_clock::time_point now, size_t batch_size) {
    if (!pool_) {
        return 0;
    }

    auto conn = pool_->acquire();

    auto& default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*conn);
    pqxx::work tx(default_conn.native_handle());

    auto expired_files = file_repo_->find_expired_files(now, batch_size, tx);
    size_t count = 0;
    const auto expired_at_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    const std::string corr_id = resolve_correlation_id();

    for (const auto& file : expired_files) {
        if (is_valid_state_transition(file.status, FileStatus::Expired)) {
            if (file_repo_->update_status(file.file_id, file.status, FileStatus::Expired, tx)) {
                if (audit_publisher_) {
                    service::FilesAuditRecord record;
                    record.event_type = "file.expired";
                    record.severity = "INFO";
                    record.actor_type = "SYSTEM";
                    record.actor_id = "files";
                    record.target_type = "FILE";
                    record.target_id = file.file_id;
                    record.correlation_id = corr_id;
                    record.metadata = {{"expired_at_ms", std::to_string(expired_at_ms)}};
                    if (file.retention_until.has_value()) {
                        const auto ret_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                file.retention_until->time_since_epoch())
                                                .count();
                        record.metadata.emplace("retention_until_ms", std::to_string(ret_ms));
                    }
                    audit_publisher_->publish_in_tx(record, tx);
                }
                ++count;
            }
        }
    }

    tx.commit();
    if (count > 0 && audit_publisher_) {
        audit_publisher_->notify_relay();
    }
    return count;
}

} // namespace securecloud::files
