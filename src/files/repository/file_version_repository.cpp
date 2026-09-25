#include "files/repository/file_version_repository.hpp"

#include <chrono>

namespace securecloud::files {

FileVersionRepository::FileVersionRepository(std::shared_ptr<db::FilesDbConnectionPool> pool)
    : pool_(std::move(pool)) {}

void FileVersionRepository::create_version(const FileVersionEntity& version, pqxx::work& tx) {
    if (version.version_id.empty() || version.file_id.empty()) {
        throw RepositoryException("Version ID and File ID must not be empty");
    }
    if (version.version_number <= 0) {
        throw RepositoryException("Version number must be positive");
    }

    try {
        tx.exec_params(
            "INSERT INTO file_versions (version_id, file_id, version_number, encrypted_size, minio_object_key, checksum_sha256, created_at, is_active) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            version.version_id,
            version.file_id,
            version.version_number,
            version.encrypted_size,
            version.minio_object_key,
            version.checksum_sha256,
            db::to_iso8601(version.created_at),
            version.is_active
        );
    } catch (const std::exception& e) {
        std::string msg = e.what();
        if (msg.find("unique") != std::string::npos || msg.find("UNIQUE") != std::string::npos ||
            msg.find("uq_file_version") != std::string::npos) {
            throw UniqueConstraintViolationException(
                "Version " + std::to_string(version.version_number) + " already exists for file " + version.file_id);
        }
        throw;
    }

    if (version.is_active) {
        tx.exec_params(
            "UPDATE file_versions SET is_active = FALSE WHERE file_id = $1 AND version_number != $2",
            version.file_id,
            version.version_number
        );
    }
}

std::optional<FileVersionEntity> FileVersionRepository::find_active_version(const std::string& file_id, pqxx::work& tx) {
    if (file_id.empty()) {
        return std::nullopt;
    }

    auto res = tx.exec_params(
        "SELECT version_id, file_id, version_number, encrypted_size, minio_object_key, checksum_sha256, created_at, is_active "
        "FROM file_versions WHERE file_id = $1 AND is_active = TRUE ORDER BY version_number DESC LIMIT 1",
        file_id
    );

    if (res.empty()) {
        return std::nullopt;
    }

    return db::file_version_from_row(res[0]);
}

std::optional<FileVersionEntity> FileVersionRepository::find_active_version(const std::string& file_id) {
    pqxx::work tx;
    return find_active_version(file_id, tx);
}

std::vector<FileVersionEntity> FileVersionRepository::list_versions(const std::string& file_id, pqxx::work& tx) {
    if (file_id.empty()) {
        return {};
    }

    auto res = tx.exec_params(
        "SELECT version_id, file_id, version_number, encrypted_size, minio_object_key, checksum_sha256, created_at, is_active "
        "FROM file_versions WHERE file_id = $1 ORDER BY version_number ASC",
        file_id
    );

    std::vector<FileVersionEntity> versions;
    versions.reserve(res.size());
    for (size_t i = 0; i < res.size(); ++i) {
        versions.push_back(db::file_version_from_row(res[i]));
    }
    return versions;
}

std::vector<FileVersionEntity> FileVersionRepository::list_versions(const std::string& file_id) {
    pqxx::work tx;
    return list_versions(file_id, tx);
}

} // namespace securecloud::files
