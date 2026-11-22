#include "files/repository/file_repository.hpp"

#include <chrono>

namespace securecloud::files {

FileRepository::FileRepository(std::shared_ptr<db::FilesDbConnectionPool> pool)
#if defined(SECURECLOUD_FILES_TEST_PQXX)
    : pool_(pool ? std::move(pool) : db::test_files_db_connection_pool()){}
#else
    : pool_(std::move(pool)) {
}
#endif

      void FileRepository::create_file(const FileEntity& file, const EncryptedFileMetadataEntity& metadata,
                                       pqxx::work& tx) {
    if (file.file_id.empty()) {
        throw RepositoryException("File ID cannot be empty");
    }
    if (file.file_id != metadata.file_id) {
        throw RepositoryException("File ID mismatch between file entity and metadata entity: " + file.file_id + " vs " +
                                  metadata.file_id);
    }

    // 1. Insert master file catalog entry
    tx.exec(
        "INSERT INTO files (file_id, owner_user_id, owner_device_id, conversation_id, encrypted_size, "
        "content_type, encryption_algorithm, status, retention_until, created_at, updated_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        pqxx::params{file.file_id, file.owner_user_id, file.owner_device_id,
                     file.conversation_id ? std::make_optional(*file.conversation_id) : std::nullopt,
                     file.encrypted_size, file.content_type ? std::make_optional(*file.content_type) : std::nullopt,
                     file.encryption_algorithm, db::to_string(file.status),
                     file.retention_until ? std::make_optional(db::to_iso8601(*file.retention_until)) : std::nullopt,
                     db::to_iso8601(file.created_at), db::to_iso8601(file.updated_at)});

    // 2. Insert client-side encrypted metadata entry (Zero-Plaintext Invariant)
    tx.exec("INSERT INTO encrypted_file_metadata (file_id, encrypted_filename, encrypted_mime_type, "
            "metadata_nonce, metadata_tag, client_encryption_metadata, updated_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7)",
            pqxx::params{metadata.file_id, db::to_bytea_hex(metadata.encrypted_filename),
                         metadata.encrypted_mime_type
                             ? std::make_optional(db::to_bytea_hex(*metadata.encrypted_mime_type))
                             : std::nullopt,
                         db::to_bytea_hex(metadata.metadata_nonce), db::to_bytea_hex(metadata.metadata_tag),
                         metadata.client_encryption_metadata_json, db::to_iso8601(metadata.updated_at)});
}

std::optional<FileEntity> FileRepository::find_by_id(const std::string& file_id, pqxx::work& tx) {
    if (file_id.empty()) {
        return std::nullopt;
    }

    auto res = tx.exec("SELECT file_id, owner_user_id, owner_device_id, conversation_id, encrypted_size, "
                       "content_type, encryption_algorithm, status, retention_until, created_at, updated_at "
                       "FROM files WHERE file_id = $1",
                       pqxx::params{file_id});

    if (res.empty()) {
        return std::nullopt;
    }

    return db::file_from_row(res[0]);
}

std::optional<FileEntity> FileRepository::find_by_id(const std::string& file_id) {
    if (!pool_)
        throw RepositoryException("Connection pool not initialized");
    auto lease = pool_->acquire();
    auto* pg_conn = dynamic_cast<db::DefaultDbConnection*>(lease.get());
    if (!pg_conn) {
        throw RepositoryException("Database connection is not a PostgreSQL connection");
    }
    pqxx::work tx(pg_conn->native_handle());

    auto result = find_by_id(file_id, tx);
    tx.commit();
    return result;
}

std::optional<EncryptedFileMetadataEntity> FileRepository::find_encrypted_metadata(const std::string& file_id,
                                                                                   pqxx::work& tx) {
    if (file_id.empty()) {
        return std::nullopt;
    }

    auto res = tx.exec("SELECT file_id, encrypted_filename, encrypted_mime_type, metadata_nonce, metadata_tag, "
                       "client_encryption_metadata, updated_at "
                       "FROM encrypted_file_metadata WHERE file_id = $1",
                       pqxx::params{file_id});

    if (res.empty()) {
        return std::nullopt;
    }

    return db::encrypted_metadata_from_row(res[0]);
}

std::optional<EncryptedFileMetadataEntity> FileRepository::find_encrypted_metadata(const std::string& file_id) {
    if (!pool_)
        throw RepositoryException("Connection pool not initialized");
    auto lease = pool_->acquire();
    auto* pg_conn = dynamic_cast<db::DefaultDbConnection*>(lease.get());
    if (!pg_conn) {
        throw RepositoryException("Database connection is not a PostgreSQL connection");
    }
    pqxx::work tx(pg_conn->native_handle());

    auto result = find_encrypted_metadata(file_id, tx);
    tx.commit();
    return result;
}

bool FileRepository::update_status(const std::string& file_id, FileStatus expected_current, FileStatus new_status,
                                   pqxx::work& tx) {
    if (!is_valid_state_transition(expected_current, new_status)) {
        throw InvalidStateTransitionException("Illegal state transition from " + db::to_string(expected_current) +
                                              " to " + db::to_string(new_status));
    }

    auto now_str = db::to_iso8601(std::chrono::system_clock::now());
    auto res = tx.exec("UPDATE files SET status = $1, updated_at = $2 WHERE file_id = $3 AND status = $4",
                       pqxx::params{db::to_string(new_status), now_str, file_id, db::to_string(expected_current)});

    return res.affected_rows() > 0;
}

bool FileRepository::update_status(const std::string& file_id, FileStatus expected_current, FileStatus new_status) {
    if (!pool_)
        throw RepositoryException("Connection pool not initialized");
    auto lease = pool_->acquire();
    auto* pg_conn = dynamic_cast<db::DefaultDbConnection*>(lease.get());
    if (!pg_conn) {
        throw RepositoryException("Database connection is not a PostgreSQL connection");
    }
    pqxx::work tx(pg_conn->native_handle());

    bool updated = update_status(file_id, expected_current, new_status, tx);
    if (updated) {
        tx.commit();
    }
    return updated;
}

bool FileRepository::delete_file_logical(const std::string& file_id, pqxx::work& tx) {
    auto now_str = db::to_iso8601(std::chrono::system_clock::now());
    auto res = tx.exec("UPDATE files SET status = 'DELETED', updated_at = $1 WHERE file_id = $2",
                       pqxx::params{now_str, file_id});

    return res.affected_rows() > 0;
}

std::vector<FileEntity> FileRepository::find_expired_files(std::chrono::system_clock::time_point now, size_t limit,
                                                           pqxx::work& tx) {
    auto now_str = db::to_iso8601(now);
    auto res = tx.exec("SELECT file_id, owner_user_id, owner_device_id, conversation_id, encrypted_size, "
                       "content_type, encryption_algorithm, status, retention_until, created_at, updated_at "
                       "FROM files "
                       "WHERE retention_until IS NOT NULL AND retention_until <= $1 AND status != 'DELETED' "
                       "ORDER BY retention_until ASC LIMIT $2",
                       pqxx::params{now_str, limit});

    std::vector<FileEntity> files;
    files.reserve(res.size());
    for (int i = 0; i < static_cast<int>(res.size()); ++i) {
        files.push_back(db::file_from_row(res[i]));
    }
    return files;
}

std::vector<FileEntity> FileRepository::find_expired_files(std::chrono::system_clock::time_point now, size_t limit) {
    if (!pool_)
        throw RepositoryException("Connection pool not initialized");
    auto lease = pool_->acquire();
    auto* pg_conn = dynamic_cast<db::DefaultDbConnection*>(lease.get());
    if (!pg_conn) {
        throw RepositoryException("Database connection is not a PostgreSQL connection");
    }
    pqxx::work tx(pg_conn->native_handle());

    auto result = find_expired_files(now, limit, tx);
    tx.commit();
    return result;
}

} // namespace securecloud::files
