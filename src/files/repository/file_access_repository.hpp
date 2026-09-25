#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/db/pqxx_compat.hpp"
#include "files/db/pqxx_mappers.hpp"
#include "files/domain/file_access_entity.hpp"
#include "files/repository/file_repository.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::files {

/// Authoritative repository managing granular file-level access grants and ownership hierarchy.
/// Maps 1:1 to the `file_access` PostgreSQL table (Files Design 6.15, 6.18, 6.19).
class FileAccessRepository {
public:
    explicit FileAccessRepository(std::shared_ptr<db::FilesDbConnectionPool> pool = nullptr);

    /// Grants or updates access permissions for a user on a file within transaction `tx`.
    /// Conflict on (file_id, grantee_user_id) updates existing permission and clears any revocation.
    void grant_access(const FileAccessEntity& grant, pqxx::work& tx);

    /// Grants or updates access permissions for a user (creates autonomous work session).
    void grant_access(const FileAccessEntity& grant);

    /// Validates whether a user has the required permission level on a file within transaction `tx`.
    /// Enforces the ownership invariant: file owner is implicitly granted full ADMIN permission.
    /// For non-owners, checks active, unrevoked grants where grant.permission >= required.
    [[nodiscard]] bool check_access(const std::string& file_id,
                                    const std::string& user_id,
                                    FilePermission required,
                                    pqxx::work& tx);

    /// Validates access permissions (creates autonomous work session).
    [[nodiscard]] bool check_access(const std::string& file_id,
                                    const std::string& user_id,
                                    FilePermission required);

    /// Revokes a user's access grant to a file by setting revoked_at = NOW() within transaction `tx`.
    /// Returns true if an active grant was revoked; returns false if no active grant was found.
    bool revoke_access(const std::string& file_id, const std::string& user_id, pqxx::work& tx);

    /// Revokes a user's access grant (creates autonomous work session).
    bool revoke_access(const std::string& file_id, const std::string& user_id);

    /// Lists all active (unrevoked) grants for a file within transaction `tx`.
    [[nodiscard]] std::vector<FileAccessEntity> list_grantees(const std::string& file_id, pqxx::work& tx);

    /// Lists all active (unrevoked) grants for a file (creates autonomous work session).
    [[nodiscard]] std::vector<FileAccessEntity> list_grantees(const std::string& file_id);

    /// Finds a specific access grant by file_id and grantee_user_id within transaction `tx`.
    [[nodiscard]] std::optional<FileAccessEntity> find_grant(const std::string& file_id,
                                                            const std::string& user_id,
                                                            pqxx::work& tx);

    /// Finds a specific access grant (creates autonomous work session).
    [[nodiscard]] std::optional<FileAccessEntity> find_grant(const std::string& file_id,
                                                            const std::string& user_id);

private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
};

} // namespace securecloud::files
