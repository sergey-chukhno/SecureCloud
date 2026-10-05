#include "auth/repository/user_repository.hpp"

#include "auth/domain/mappers.hpp"
#include "auth/domain/timestamp.hpp"

#include <chrono>

namespace securecloud::auth::repository {

namespace {

constexpr std::string_view kInsertUserSql = "INSERT INTO users ("
                                            "    user_id, credential_identifier, password_verifier, password_algorithm,"
                                            "    password_updated_at, account_status, created_at, updated_at, version"
                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);";

constexpr std::string_view kFindUserByIdSql =
    "SELECT user_id, credential_identifier, password_verifier, password_algorithm,"
    "       password_updated_at, account_status, created_at, updated_at, version "
    "FROM users WHERE user_id = $1;";

constexpr std::string_view kFindUserByCredentialSql =
    "SELECT user_id, credential_identifier, password_verifier, password_algorithm,"
    "       password_updated_at, account_status, created_at, updated_at, version "
    "FROM users WHERE credential_identifier = $1;";

constexpr std::string_view kUpdateUserSql =
    "UPDATE users "
    "SET credential_identifier = $1, password_verifier = $2, password_algorithm = $3,"
    "    password_updated_at = $4, account_status = $5, updated_at = $6, version = version + 1 "
    "WHERE user_id = $7 AND version = $8;";

constexpr std::string_view kSetAccountStatusSql = "UPDATE users "
                                                  "SET account_status = $1, updated_at = $2, version = version + 1 "
                                                  "WHERE user_id = $3 AND version = $4;";

constexpr std::string_view kCheckUserExistsSql = "SELECT 1 FROM users WHERE user_id = $1;";

} // namespace

PostgresUserRepository::PostgresUserRepository(db::PostgresConnectionPool& pool) : pool_(pool) {}

void PostgresUserRepository::create_user(const domain::UserEntity& user) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    create_user(user, tx);
    tx.commit();
}

void PostgresUserRepository::create_user(const domain::UserEntity& user, pqxx::transaction_base& tx) {
    try {
        const uint64_t initial_version = (user.version == 0) ? 1 : user.version;
        db::exec_sql(tx, kInsertUserSql,
                     pqxx::params{user.user_id.to_string(), user.credential_identifier, user.password_verifier,
                                  user.password_algorithm, domain::to_iso8601(user.password_updated_at),
                                  domain::to_string(user.account_status), domain::to_iso8601(user.created_at),
                                  domain::to_iso8601(user.updated_at), initial_version});
    } catch (const pqxx::unique_violation&) {
        throw DuplicateEntityException("Credential identifier already registered: " + user.credential_identifier);
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to insert user: " + std::string(ex.what()));
    }
}

std::optional<domain::UserEntity> PostgresUserRepository::find_by_id(const domain::Uuid& user_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = find_by_id(user_id, tx);
    tx.commit();
    return res;
}

std::optional<domain::UserEntity> PostgresUserRepository::find_by_id(const domain::Uuid& user_id,
                                                                     pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kFindUserByIdSql, pqxx::params{user_id.to_string()});
        if (res.empty()) {
            return std::nullopt;
        }
        return domain::user_from_row(pqxx::row(res[0]));
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to query user by id: " + std::string(ex.what()));
    }
}

std::optional<domain::UserEntity>
PostgresUserRepository::find_by_credential_identifier(std::string_view credential_identifier) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = find_by_credential_identifier(credential_identifier, tx);
    tx.commit();
    return res;
}

std::optional<domain::UserEntity>
PostgresUserRepository::find_by_credential_identifier(std::string_view credential_identifier,
                                                      pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kFindUserByCredentialSql, pqxx::params{credential_identifier});
        if (res.empty()) {
            return std::nullopt;
        }
        return domain::user_from_row(pqxx::row(res[0]));
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to query user by credential identifier: " + std::string(ex.what()));
    }
}

void PostgresUserRepository::update_user(const domain::UserEntity& user) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    update_user(user, tx);
    tx.commit();
}

void PostgresUserRepository::update_user(const domain::UserEntity& user, pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(
            tx, kUpdateUserSql,
            pqxx::params{user.credential_identifier, user.password_verifier, user.password_algorithm,
                         domain::to_iso8601(user.password_updated_at), domain::to_string(user.account_status),
                         domain::to_iso8601(user.updated_at), user.user_id.to_string(), user.version});

        if (res.affected_rows() == 0) {
            auto check = db::exec_sql(tx, kCheckUserExistsSql, pqxx::params{user.user_id.to_string()});
            if (!check.empty()) {
                throw OptimisticLockException("Concurrent modification detected for user " + user.user_id.to_string());
            }
            throw EntityNotFoundException("User not found: " + user.user_id.to_string());
        }
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::unique_violation&) {
        throw DuplicateEntityException("Credential identifier already registered: " + user.credential_identifier);
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to update user: " + std::string(ex.what()));
    }
}

void PostgresUserRepository::set_account_status(const domain::Uuid& user_id, domain::AccountStatus status,
                                                uint64_t expected_version) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    set_account_status(user_id, status, expected_version, tx);
    tx.commit();
}

void PostgresUserRepository::set_account_status(const domain::Uuid& user_id, domain::AccountStatus status,
                                                uint64_t expected_version, pqxx::transaction_base& tx) {
    try {
        const auto now = std::chrono::system_clock::now();
        auto res = db::exec_sql(
            tx, kSetAccountStatusSql,
            pqxx::params{domain::to_string(status), domain::to_iso8601(now), user_id.to_string(), expected_version});

        if (res.affected_rows() == 0) {
            auto check = db::exec_sql(tx, kCheckUserExistsSql, pqxx::params{user_id.to_string()});
            if (!check.empty()) {
                throw OptimisticLockException("Concurrent modification detected for user " + user_id.to_string());
            }
            throw EntityNotFoundException("User not found: " + user_id.to_string());
        }
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to set account status: " + std::string(ex.what()));
    }
}

} // namespace securecloud::auth::repository
