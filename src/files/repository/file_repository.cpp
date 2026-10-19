#include "files/repository/file_repository.hpp"

#include <chrono>

namespace securecloud::files {

bool is_valid_state_transition(FileStatus from, FileStatus to) noexcept {
    switch (from) {
    case FileStatus::Created:
        return to == FileStatus::Uploading || to == FileStatus::Failed;
    case FileStatus::Uploading:
        return to == FileStatus::Finalizing || to == FileStatus::Failed;
    case FileStatus::Finalizing:
        return to == FileStatus::Available || to == FileStatus::Failed;
    case FileStatus::Available:
        return to == FileStatus::Expired || to == FileStatus::Deleted;
    case FileStatus::Expired:
        return to == FileStatus::Deleted;
    case FileStatus::Deleted:
    case FileStatus::Failed:
        return false;
    }
    return false;
}

FileRepository::FileRepository(std::shared_ptr<db::FilesDbConnectionPool> pool) : pool_(std::move(pool)) {}

void FileRepository::create_file(const FileEntity& file, const EncryptedFileMetadataEntity& metadata, pqxx::work& tx) {
    if (file.file_id.empty()) {
        throw RepositoryException("File ID cannot be empty");
    }
    if (file.file_id != metadata.file_id) {
        throw RepositoryException("File ID mismatch between file entity and metadata entity: " + file.file_id + " vs " +
                                  metadata.file_id);
    }

    // 1. Insert master file catalog entry
    tx.exec_params("INSERT INTO files (file_id, owner_user_id, owner_device_id, conversation_id, encrypted_size, "
                   "content_type, encryption_algorithm, status, retention_until, created_at, updated_at) "
                   "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                   file.file_id, file.owner_user_id, file.owner_device_id,
                   file.conversation_id ? std::make_optional(*file.conversation_id) : std::nullopt, file.encrypted_size,
                   file.content_type ? std::make_optional(*file.content_type) : std::nullopt, file.encryption_algorithm,
                   db::to_string(file.status),
                   file.retention_until ? std::make_optional(db::to_iso8601(*file.retention_until)) : std::nullopt,
                   db::to_iso8601(file.created_at), db::to_iso8601(file.updated_at));

    // 2. Insert client-side encrypted metadata entry (Zero-Plaintext Invariant)
    tx.exec_params("INSERT INTO encrypted_file_metadata (file_id, encrypted_filename, encrypted_mime_type, "
                   "metadata_nonce, metadata_tag, client_encryption_metadata, updated_at) "
                   "VALUES ($1, $2, $3, $4, $5, $6, $7)",
                   metadata.file_id, db::to_bytea_hex(metadata.encrypted_filename),
                   metadata.encrypted_mime_type ? std::make_optional(db::to_bytea_hex(*metadata.encrypted_mime_type))
                                                : std::nullopt,
                   db::to_bytea_hex(metadata.metadata_nonce), db::to_bytea_hex(metadata.metadata_tag),
                   metadata.client_encryption_metadata_json, db::to_iso8601(metadata.updated_at));
}

std::optional<FileEntity> FileRepository::find_by_id(const std::string& file_id, pqxx::work& tx) {
    if (file_id.empty()) {
        return std::nullopt;
    }

    auto res = tx.exec_params("SELECT file_id, owner_user_id, owner_device_id, conversation_id, encrypted_size, "
                              "content_type, encryption_algorithm, status, retention_until, created_at, updated_at "
                              "FROM files WHERE file_id = $1",
                              file_id);

    if (res.empty()) {
        return std::nullopt;
    }

    return db::file_from_row(res[0]);
}

std::optional<FileEntity> FileRepository::find_by_id(const std::string& file_id) {
    pqxx::work tx;
    return find_by_id(file_id, tx);
}

std::optional<EncryptedFileMetadataEntity> FileRepository::find_encrypted_metadata(const std::string& file_id,
                                                                                   pqxx::work& tx) {
    if (file_id.empty()) {
        return std::nullopt;
    }

    auto res = tx.exec_params("SELECT file_id, encrypted_filename, encrypted_mime_type, metadata_nonce, metadata_tag, "
                              "client_encryption_metadata, updated_at "
                              "FROM encrypted_file_metadata WHERE file_id = $1",
                              file_id);

    if (res.empty()) {
        return std::nullopt;
    }

    return db::encrypted_metadata_from_row(res[0]);
}

std::optional<EncryptedFileMetadataEntity> FileRepository::find_encrypted_metadata(const std::string& file_id) {
    pqxx::work tx;
    return find_encrypted_metadata(file_id, tx);
}

bool FileRepository::update_status(const std::string& file_id, FileStatus expected_current, FileStatus new_status,
                                   pqxx::work& tx) {
    if (!is_valid_state_transition(expected_current, new_status)) {
        throw InvalidStateTransitionException("Illegal state transition from " + db::to_string(expected_current) +
                                              " to " + db::to_string(new_status));
    }

    auto now_str = db::to_iso8601(std::chrono::system_clock::now());
    auto res = tx.exec_params("UPDATE files SET status = $1, updated_at = $2 WHERE file_id = $3 AND status = $4",
                              db::to_string(new_status), now_str, file_id, db::to_string(expected_current));

    return res.affected_rows() > 0;
}

bool FileRepository::delete_file_logical(const std::string& file_id, pqxx::work& tx) {
    auto now_str = db::to_iso8601(std::chrono::system_clock::now());
    auto res =
        tx.exec_params("UPDATE files SET status = 'DELETED', updated_at = $1 WHERE file_id = $2", now_str, file_id);

    return res.affected_rows() > 0;
}

std::vector<FileEntity> FileRepository::find_expired_files(std::chrono::system_clock::time_point now, size_t limit,
                                                           pqxx::work& tx) {
    auto now_str = db::to_iso8601(now);
    auto res = tx.exec_params("SELECT file_id, owner_user_id, owner_device_id, conversation_id, encrypted_size, "
                              "content_type, encryption_algorithm, status, retention_until, created_at, updated_at "
                              "FROM files "
                              "WHERE retention_until IS NOT NULL AND retention_until <= $1 AND status != 'DELETED' "
                              "ORDER BY retention_until ASC LIMIT $2",
                              now_str, limit);

    std::vector<FileEntity> files;
    files.reserve(res.size());
    for (size_t i = 0; i < res.size(); ++i) {
        files.push_back(db::file_from_row(res[i]));
    }
    return files;
}

std::vector<FileEntity> FileRepository::find_expired_files(std::chrono::system_clock::time_point now, size_t limit) {
    pqxx::work tx;
    return find_expired_files(now, limit, tx);
}

} // namespace securecloud::files
