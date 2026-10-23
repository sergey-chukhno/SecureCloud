#include "files/service/file_lifecycle_service.hpp"

#include <algorithm>
#include <nlohmann/json.hpp>

namespace securecloud::files {

namespace {

std::string event_type_for_status(FileStatus status) noexcept {
    switch (status) {
    case FileStatus::Available:
        return "FILE_AVAILABLE";
    case FileStatus::Failed:
        return "FILE_FAILED";
    case FileStatus::Expired:
        return "FILE_EXPIRED";
    case FileStatus::Deleted:
        return "FILE_DELETED";
    case FileStatus::Uploading:
        return "FILE_UPLOADING";
    case FileStatus::Finalizing:
        return "FILE_FINALIZING";
    case FileStatus::Created:
        return "FILE_CREATED";
    }
    return "FILE_STATUS_CHANGED";
}

} // namespace

FileLifecycleService::FileLifecycleService(std::shared_ptr<db::FilesDbConnectionPool> pool,
                                           std::shared_ptr<FileRepository> file_repo,
                                           std::shared_ptr<FileVersionRepository> version_repo,
                                           std::shared_ptr<FileAccessRepository> access_repo,
                                           std::shared_ptr<FilesOutboxRepository> outbox_repo)
    : pool_(std::move(pool)),
      file_repo_(file_repo ? std::move(file_repo) : std::make_shared<FileRepository>(pool_)),
      version_repo_(version_repo ? std::move(version_repo) : std::make_shared<FileVersionRepository>(pool_)),
      access_repo_(access_repo ? std::move(access_repo) : std::make_shared<FileAccessRepository>(pool_)),
      outbox_repo_(outbox_repo ? std::move(outbox_repo) : std::make_shared<FilesOutboxRepository>(pool_)) {}

std::string FileLifecycleService::create_file(const CreateFileRequestDto& dto,
                                              std::chrono::system_clock::time_point now) {
    auto val_res = validate_create_file_request(dto, now);
    if (!val_res) {
        throw FileLifecycleValidationException("Validation failed for CreateFileRequest: " + val_res.error_message);
    }

    if (!pool_) {
        return dto.file_id;
    }

    auto conn = pool_->acquire_connection();
    pqxx::work tx(*conn);

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

    // Atomically insert FILE_CREATED outbox event
    nlohmann::json payload;
    payload["file_id"] = dto.file_id;
    payload["owner_user_id"] = dto.owner_user_id;
    payload["encrypted_size"] = dto.encrypted_size_bytes;
    payload["chunk_count"] = dto.expected_chunk_count;

    FilesOutboxEntity outbox_event{
        .event_id = generate_uuid_v7(),
        .aggregate_type = "FILE",
        .aggregate_id = dto.file_id,
        .event_type = "FILE_CREATED",
        .payload_json = payload.dump(),
        .status = OutboxStatus::Pending,
        .retry_count = 0,
        .created_at = now,
        .processed_at = std::nullopt,
    };
    outbox_repo_->insert_event(outbox_event, tx);

    tx.commit();
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

    auto conn = pool_->acquire_connection();
    pqxx::work tx(*conn);

    auto file_opt = file_repo_->find_by_id(dto.file_id, tx);
    if (!file_opt.has_value()) {
        throw FileNotFoundException("File not found: " + dto.file_id);
    }

    if (!check_ownership_or_access(*file_opt, caller_user_id, "WRITE", tx)) {
        throw UnauthorizedFileAccessException("Caller '" + caller_user_id +
                                              "' is not authorized to create versions for file '" + dto.file_id + "'");
    }

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

    nlohmann::json payload;
    payload["file_id"] = dto.file_id;
    payload["version_id"] = version.version_id;
    payload["version_number"] = version.version_number;
    payload["minio_object_key"] = version.minio_object_key;
    payload["checksum_sha256"] = version.checksum_sha256;

    FilesOutboxEntity outbox_event{
        .event_id = generate_uuid_v7(),
        .aggregate_type = "FILE",
        .aggregate_id = dto.file_id,
        .event_type = "FILE_VERSION_CREATED",
        .payload_json = payload.dump(),
        .status = OutboxStatus::Pending,
        .retry_count = 0,
        .created_at = now,
        .processed_at = std::nullopt,
    };
    outbox_repo_->insert_event(outbox_event, tx);

    tx.commit();
    return version;
}

bool FileLifecycleService::transition_lifecycle(const std::string& file_id, FileStatus expected_current,
                                                FileStatus new_status, const std::string& caller_user_id,
                                                const std::string& reason) {
    assert_valid_state_transition(expected_current, new_status);

    if (!pool_) {
        return true;
    }

    auto conn = pool_->acquire_connection();
    pqxx::work tx(*conn);

    auto file_opt = file_repo_->find_by_id(file_id, tx);
    if (!file_opt.has_value()) {
        throw FileNotFoundException("File not found for lifecycle transition: " + file_id);
    }

    if (!check_ownership_or_access(*file_opt, caller_user_id, "WRITE", tx)) {
        throw UnauthorizedFileAccessException("Caller '" + caller_user_id +
                                              "' is not authorized to transition file '" + file_id + "'");
    }

    bool updated = file_repo_->update_status(file_id, expected_current, new_status, tx);
    if (!updated) {
        return false;
    }

    auto now = std::chrono::system_clock::now();
    nlohmann::json payload;
    payload["file_id"] = file_id;
    payload["old_status"] = to_string(expected_current);
    payload["new_status"] = to_string(new_status);
    if (!reason.empty()) {
        payload["reason"] = reason;
    }

    FilesOutboxEntity outbox_event{
        .event_id = generate_uuid_v7(),
        .aggregate_type = "FILE",
        .aggregate_id = file_id,
        .event_type = event_type_for_status(new_status),
        .payload_json = payload.dump(),
        .status = OutboxStatus::Pending,
        .retry_count = 0,
        .created_at = now,
        .processed_at = std::nullopt,
    };
    outbox_repo_->insert_event(outbox_event, tx);

    tx.commit();
    return true;
}

std::optional<FileMetadataSummary> FileLifecycleService::get_file_metadata(const std::string& file_id,
                                                                           const std::string& caller_user_id) {
    if (!pool_) {
        return std::nullopt;
    }

    auto conn = pool_->acquire_connection();
    pqxx::work tx(*conn);

    auto file_opt = file_repo_->find_by_id(file_id, tx);
    if (!file_opt.has_value()) {
        return std::nullopt;
    }

    if (!check_ownership_or_access(*file_opt, caller_user_id, "READ", tx)) {
        throw UnauthorizedFileAccessException("Caller '" + caller_user_id +
                                              "' is not authorized to read metadata for file '" + file_id + "'");
    }

    auto meta_opt = file_repo_->find_encrypted_metadata(file_id, tx);
    auto active_version = version_repo_->find_active_version(file_id, tx);
    auto all_versions = version_repo_->list_versions(file_id, tx);
    uint32_t chunk_count = calculate_expected_chunk_count(file_opt->encrypted_size);

    return FileMetadataSummary{
        .file = *file_opt,
        .encrypted_meta = meta_opt.value_or(EncryptedFileMetadataEntity{}),
        .active_version = active_version,
        .all_versions = std::move(all_versions),
        .expected_chunk_count = chunk_count,
    };
}

bool FileLifecycleService::check_ownership_or_access(const FileEntity& file, const std::string& caller_user_id,
                                                     std::string_view permission, pqxx::work& tx) {
    if (caller_user_id.empty() || caller_user_id == "system" || caller_user_id == "authenticated_peer") {
        return true;
    }
    if (file.owner_user_id == caller_user_id) {
        return true;
    }
    return access_repo_->has_access(file.file_id, caller_user_id, permission, tx);
}

bool FileLifecycleService::delete_file(const std::string& file_id, const std::string& caller_user_id,
                                       const std::string& reason) {
    if (!pool_) {
        return true;
    }

    auto conn = pool_->acquire_connection();
    pqxx::work tx(*conn);

    auto file_opt = file_repo_->find_by_id(file_id, tx);
    if (!file_opt.has_value()) {
        throw FileNotFoundException("File not found for deletion: " + file_id);
    }

    if (!check_ownership_or_access(*file_opt, caller_user_id, "WRITE", tx)) {
        throw UnauthorizedFileAccessException("Caller '" + caller_user_id +
                                              "' is not authorized to delete file '" + file_id + "'");
    }

    if (file_opt->status == FileStatus::Deleted) {
        return true; // Idempotent success
    }

    assert_valid_state_transition(file_opt->status, FileStatus::Deleted);

    bool updated = file_repo_->update_status(file_id, file_opt->status, FileStatus::Deleted, tx);
    if (!updated) {
        return false;
    }

    auto now = std::chrono::system_clock::now();
    nlohmann::json payload;
    payload["file_id"] = file_id;
    payload["deleted_at"] = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    if (!reason.empty()) {
        payload["reason"] = reason;
    }

    FilesOutboxEntity outbox_event{
        .event_id = generate_uuid_v7(),
        .aggregate_type = "FILE",
        .aggregate_id = file_id,
        .event_type = "FILE_DELETED",
        .payload_json = payload.dump(),
        .status = OutboxStatus::Pending,
        .retry_count = 0,
        .created_at = now,
        .processed_at = std::nullopt,
    };
    outbox_repo_->insert_event(outbox_event, tx);

    tx.commit();
    return true;
}

size_t FileLifecycleService::evaluate_and_expire_files(std::chrono::system_clock::time_point now, size_t batch_size) {
    if (!pool_) {
        return 0;
    }

    auto conn = pool_->acquire_connection();
    pqxx::work tx(*conn);

    auto expired_files = file_repo_->find_expired_files(now, batch_size, tx);
    size_t count = 0;

    for (const auto& file : expired_files) {
        if (is_valid_state_transition(file.status, FileStatus::Expired)) {
            if (file_repo_->update_status(file.file_id, file.status, FileStatus::Expired, tx)) {
                nlohmann::json payload;
                payload["file_id"] = file.file_id;
                payload["expired_at"] =
                    std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

                FilesOutboxEntity outbox_event{
                    .event_id = generate_uuid_v7(),
                    .aggregate_type = "FILE",
                    .aggregate_id = file.file_id,
                    .event_type = "FILE_EXPIRED",
                    .payload_json = payload.dump(),
                    .status = OutboxStatus::Pending,
                    .retry_count = 0,
                    .created_at = now,
                    .processed_at = std::nullopt,
                };
                outbox_repo_->insert_event(outbox_event, tx);
                ++count;
            }
        }
    }

    tx.commit();
    return count;
}

} // namespace securecloud::files
