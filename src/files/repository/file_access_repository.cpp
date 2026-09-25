#include "files/repository/file_access_repository.hpp"

#include <chrono>

namespace securecloud::files {

FileAccessRepository::FileAccessRepository(std::shared_ptr<db::FilesDbConnectionPool> pool)
    : pool_(std::move(pool)) {}

void FileAccessRepository::grant_access(const FileAccessEntity& grant, pqxx::work& tx) {
    if (grant.access_id.empty()) {
        throw RepositoryException("Access ID cannot be empty");
    }
    if (grant.file_id.empty()) {
        throw RepositoryException("File ID cannot be empty");
    }
    if (grant.grantee_user_id.empty()) {
        throw RepositoryException("Grantee user ID cannot be empty");
    }
    if (grant.granted_by.empty()) {
        throw RepositoryException("Granted by cannot be empty");
    }

    std::optional<std::string> revoked_str;
    if (grant.revoked_at.has_value()) {
        revoked_str = db::to_iso8601(*grant.revoked_at);
    }

    tx.exec_params(
        "INSERT INTO file_access (access_id, file_id, grantee_user_id, grantee_device_id, permission, granted_by, granted_at, revoked_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "
        "ON CONFLICT (file_id, grantee_user_id) DO UPDATE SET "
        "permission = EXCLUDED.permission, "
        "grantee_device_id = EXCLUDED.grantee_device_id, "
        "granted_by = EXCLUDED.granted_by, "
        "granted_at = EXCLUDED.granted_at, "
        "revoked_at = EXCLUDED.revoked_at",
        grant.access_id,
        grant.file_id,
        grant.grantee_user_id,
        grant.grantee_device_id,
        db::to_string(grant.permission),
        grant.granted_by,
        db::to_iso8601(grant.granted_at),
        revoked_str
    );
}

void FileAccessRepository::grant_access(const FileAccessEntity& grant) {
    pqxx::work tx;
    grant_access(grant, tx);
    tx.commit();
}

bool FileAccessRepository::check_access(const std::string& file_id,
                                        const std::string& user_id,
                                        FilePermission required,
                                        pqxx::work& tx) {
    if (file_id.empty() || user_id.empty()) {
        return false;
    }

    // 1. Ownership invariant (ADR-005, Files Design 6.15):
    // The file creator/owner implicitly possesses full ADMIN permission without needing a file_access row.
    auto owner_res = tx.exec_params(
        "SELECT owner_user_id FROM files WHERE file_id = $1",
        file_id
    );

    if (owner_res.empty()) {
        return false;
    }

    if (owner_res[0]["owner_user_id"].as<std::string>() == user_id) {
        return true;
    }

    // 2. Non-owner authorization: check active, unrevoked grant
    auto grant_res = tx.exec_params(
        "SELECT access_id, file_id, grantee_user_id, grantee_device_id, permission, granted_by, granted_at, revoked_at "
        "FROM file_access WHERE file_id = $1 AND grantee_user_id = $2 AND revoked_at IS NULL",
        file_id,
        user_id
    );

    if (grant_res.empty()) {
        return false;
    }

    auto grant = db::file_access_from_row(grant_res[0]);

    if (grant.permission == FilePermission::Admin) {
        return true; // Admin satisfies Admin, Write, Read
    }
    if (grant.permission == FilePermission::Write) {
        return required == FilePermission::Write || required == FilePermission::Read;
    }
    if (grant.permission == FilePermission::Read) {
        return required == FilePermission::Read;
    }

    return false;
}

bool FileAccessRepository::check_access(const std::string& file_id,
                                        const std::string& user_id,
                                        FilePermission required) {
    pqxx::work tx;
    return check_access(file_id, user_id, required, tx);
}

bool FileAccessRepository::revoke_access(const std::string& file_id, const std::string& user_id, pqxx::work& tx) {
    if (file_id.empty() || user_id.empty()) {
        return false;
    }

    auto now_iso = db::to_iso8601(std::chrono::system_clock::now());
    auto res = tx.exec_params(
        "UPDATE file_access SET revoked_at = $1 WHERE file_id = $2 AND grantee_user_id = $3 AND revoked_at IS NULL",
        now_iso,
        file_id,
        user_id
    );

    return res.affected_rows() > 0;
}

bool FileAccessRepository::revoke_access(const std::string& file_id, const std::string& user_id) {
    pqxx::work tx;
    bool revoked = revoke_access(file_id, user_id, tx);
    if (revoked) {
        tx.commit();
    }
    return revoked;
}

std::vector<FileAccessEntity> FileAccessRepository::list_grantees(const std::string& file_id, pqxx::work& tx) {
    if (file_id.empty()) {
        return {};
    }

    auto res = tx.exec_params(
        "SELECT access_id, file_id, grantee_user_id, grantee_device_id, permission, granted_by, granted_at, revoked_at "
        "FROM file_access WHERE file_id = $1 AND revoked_at IS NULL ORDER BY granted_at ASC",
        file_id
    );

    std::vector<FileAccessEntity> grantees;
    grantees.reserve(res.size());
    for (const auto& row : res) {
        grantees.push_back(db::file_access_from_row(row));
    }
    return grantees;
}

std::vector<FileAccessEntity> FileAccessRepository::list_grantees(const std::string& file_id) {
    pqxx::work tx;
    return list_grantees(file_id, tx);
}

std::optional<FileAccessEntity> FileAccessRepository::find_grant(const std::string& file_id,
                                                                const std::string& user_id,
                                                                pqxx::work& tx) {
    if (file_id.empty() || user_id.empty()) {
        return std::nullopt;
    }

    auto res = tx.exec_params(
        "SELECT access_id, file_id, grantee_user_id, grantee_device_id, permission, granted_by, granted_at, revoked_at "
        "FROM file_access WHERE file_id = $1 AND grantee_user_id = $2",
        file_id,
        user_id
    );

    if (res.empty()) {
        return std::nullopt;
    }

    return db::file_access_from_row(res[0]);
}

std::optional<FileAccessEntity> FileAccessRepository::find_grant(const std::string& file_id,
                                                                const std::string& user_id) {
    pqxx::work tx;
    return find_grant(file_id, user_id, tx);
}

} // namespace securecloud::files
