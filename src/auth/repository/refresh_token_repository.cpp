#include "auth/repository/refresh_token_repository.hpp"

#include "auth/domain/mappers.hpp"
#include "auth/domain/timestamp.hpp"

#include <chrono>

namespace securecloud::auth::repository {

namespace {

constexpr std::string_view kInsertTokenSql = "INSERT INTO refresh_tokens ("
                                             "    refresh_token_id, session_id, device_id, token_verifier,"
                                             "    token_status, issued_at, expires_at, revoked_at,"
                                             "    rotated_at, replaced_by_token_id"
                                             ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);";

constexpr std::string_view kFindTokenByIdSql = "SELECT refresh_token_id, session_id, device_id, token_verifier,"
                                               "       token_status, issued_at, expires_at, revoked_at,"
                                               "       rotated_at, replaced_by_token_id "
                                               "FROM refresh_tokens WHERE refresh_token_id = $1;";

constexpr std::string_view kFindTokenByIdForUpdateSql =
    "SELECT refresh_token_id, session_id, device_id, token_verifier,"
    "       token_status, issued_at, expires_at, revoked_at,"
    "       rotated_at, replaced_by_token_id "
    "FROM refresh_tokens WHERE refresh_token_id = $1 FOR UPDATE;";

constexpr std::string_view kFindTokenByVerifierSql = "SELECT refresh_token_id, session_id, device_id, token_verifier,"
                                                     "       token_status, issued_at, expires_at, revoked_at,"
                                                     "       rotated_at, replaced_by_token_id "
                                                     "FROM refresh_tokens WHERE token_verifier = $1;";

constexpr std::string_view kUpdateTokenRotatedSql =
    "UPDATE refresh_tokens "
    "SET token_status = 'Rotated', rotated_at = $1, replaced_by_token_id = $2 "
    "WHERE refresh_token_id = $3 AND token_status = 'Active';";

constexpr std::string_view kRevokeSessionByReuseSql = "UPDATE sessions "
                                                      "SET session_status = 'Revoked', revoked_at = $1 "
                                                      "WHERE session_id = $2;";

constexpr std::string_view kRevokeSiblingTokensSql = "UPDATE refresh_tokens "
                                                     "SET token_status = 'Revoked', revoked_at = $1 "
                                                     "WHERE session_id = $2 AND token_status = 'Active';";

} // namespace

PostgresRefreshTokenRepository::PostgresRefreshTokenRepository(db::PostgresConnectionPool& pool) : pool_(pool) {}

void PostgresRefreshTokenRepository::create_token(const domain::RefreshTokenEntity& token) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    create_token(token, tx);
    tx.commit();
}

void PostgresRefreshTokenRepository::create_token(const domain::RefreshTokenEntity& token, pqxx::transaction_base& tx) {
    try {
        const std::optional<std::string> revoked_at_str =
            token.revoked_at.has_value() ? std::optional<std::string>{domain::to_iso8601(*token.revoked_at)}
                                         : std::nullopt;

        const std::optional<std::string> rotated_at_str =
            token.rotated_at.has_value() ? std::optional<std::string>{domain::to_iso8601(*token.rotated_at)}
                                         : std::nullopt;

        const std::optional<std::string> replaced_by_str =
            token.replaced_by_token_id.has_value() ? std::optional<std::string>{token.replaced_by_token_id->to_string()}
                                                   : std::nullopt;

        db::exec_sql(tx, kInsertTokenSql,
                     pqxx::params{token.refresh_token_id.to_string(), token.session_id.to_string(),
                                  token.device_id.to_string(), token.token_verifier,
                                  domain::to_string(token.token_status), domain::to_iso8601(token.issued_at),
                                  domain::to_iso8601(token.expires_at), revoked_at_str, rotated_at_str,
                                  replaced_by_str});
    } catch (const pqxx::unique_violation&) {
        throw DuplicateEntityException("Refresh token already exists: " + token.refresh_token_id.to_string());
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to insert refresh token: " + std::string(ex.what()));
    }
}

std::optional<domain::RefreshTokenEntity>
PostgresRefreshTokenRepository::find_by_id(const domain::Uuid& refresh_token_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = find_by_id(refresh_token_id, tx);
    tx.commit();
    return res;
}

std::optional<domain::RefreshTokenEntity>
PostgresRefreshTokenRepository::find_by_id(const domain::Uuid& refresh_token_id, pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kFindTokenByIdSql, pqxx::params{refresh_token_id.to_string()});
        if (res.empty()) {
            return std::nullopt;
        }
        return domain::refresh_token_from_row(pqxx::row(res[0]));
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to find refresh token by id: " + std::string(ex.what()));
    }
}

std::optional<domain::RefreshTokenEntity>
PostgresRefreshTokenRepository::find_by_verifier(std::string_view verifier_hash) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = find_by_verifier(verifier_hash, tx);
    tx.commit();
    return res;
}

std::optional<domain::RefreshTokenEntity>
PostgresRefreshTokenRepository::find_by_verifier(std::string_view verifier_hash, pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kFindTokenByVerifierSql, pqxx::params{verifier_hash});
        if (res.empty()) {
            return std::nullopt;
        }
        return domain::refresh_token_from_row(pqxx::row(res[0]));
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to find refresh token by verifier: " + std::string(ex.what()));
    }
}

TokenRotationResult PostgresRefreshTokenRepository::rotate_token_atomic(const domain::Uuid& old_token_id,
                                                                        const domain::RefreshTokenEntity& new_token) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto result = rotate_token_atomic(old_token_id, new_token, tx);
    tx.commit();
    return result;
}

TokenRotationResult PostgresRefreshTokenRepository::rotate_token_atomic(const domain::Uuid& old_token_id,
                                                                        const domain::RefreshTokenEntity& new_token,
                                                                        pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kFindTokenByIdForUpdateSql, pqxx::params{old_token_id.to_string()});
        if (res.empty()) {
            throw EntityNotFoundException("Refresh token not found: " + old_token_id.to_string());
        }

        domain::RefreshTokenEntity old_token = domain::refresh_token_from_row(pqxx::row(res[0]));

        if (old_token.token_status != domain::TokenStatus::Active) {
            throw InvalidEntityStateException("Cannot rotate non-active refresh token (" +
                                              std::string(domain::to_string(old_token.token_status)) +
                                              "): " + old_token_id.to_string());
        }

        const auto now = std::chrono::system_clock::now();
        if (now > old_token.expires_at) {
            throw InvalidEntityStateException("Cannot rotate expired refresh token: " + old_token_id.to_string());
        }

        // 1. Insert new token
        create_token(new_token, tx);

        // 2. Mark old token as rotated
        auto update_res = db::exec_sql(
            tx, kUpdateTokenRotatedSql,
            pqxx::params{domain::to_iso8601(now), new_token.refresh_token_id.to_string(), old_token_id.to_string()});

        if (update_res.affected_rows() == 0) {
            throw OptimisticLockException("Concurrent token rotation race detected for token: " +
                                          old_token_id.to_string());
        }

        old_token.token_status = domain::TokenStatus::Rotated;
        old_token.rotated_at = now;
        old_token.replaced_by_token_id = new_token.refresh_token_id;

        return TokenRotationResult{
            .old_token = std::move(old_token),
            .new_token = new_token,
        };
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to rotate refresh token atomically: " + std::string(ex.what()));
    }
}

TokenReuseDetectedResult PostgresRefreshTokenRepository::handle_token_reuse(std::string_view verifier_hash) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto result = handle_token_reuse(verifier_hash, tx);
    tx.commit();
    return result;
}

TokenReuseDetectedResult PostgresRefreshTokenRepository::handle_token_reuse(std::string_view verifier_hash,
                                                                            pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kFindTokenByVerifierSql, pqxx::params{verifier_hash});
        if (res.empty()) {
            throw EntityNotFoundException("Token verifier not found for reuse handling");
        }

        domain::RefreshTokenEntity token = domain::refresh_token_from_row(pqxx::row(res[0]));
        if (token.token_status != domain::TokenStatus::Rotated) {
            throw InvalidEntityStateException("Token reuse handling triggered on non-rotated token: " +
                                              std::string(domain::to_string(token.token_status)));
        }

        const auto now = std::chrono::system_clock::now();
        const std::string now_str = domain::to_iso8601(now);

        // 1. Revoke the entire compromised session
        db::exec_sql(tx, kRevokeSessionByReuseSql, pqxx::params{now_str, token.session_id.to_string()});

        // 2. Revoke all active sibling tokens in that session family
        db::exec_sql(tx, kRevokeSiblingTokensSql, pqxx::params{now_str, token.session_id.to_string()});

        return TokenReuseDetectedResult{
            .session_id = token.session_id,
            .device_id = token.device_id,
            .revoked_at = now,
        };
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to handle token reuse: " + std::string(ex.what()));
    }
}

} // namespace securecloud::auth::repository
