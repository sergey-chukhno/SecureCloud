#include "auth/repository/session_repository.hpp"

#include "auth/domain/mappers.hpp"
#include "auth/domain/timestamp.hpp"

#include <chrono>

namespace securecloud::auth::repository {

namespace {

constexpr std::string_view kInsertSessionSql = "INSERT INTO sessions ("
                                               "    session_id, user_id, device_id, session_status,"
                                               "    authentication_level, created_at, expires_at,"
                                               "    revoked_at, last_used_at"
                                               ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);";

constexpr std::string_view kFindSessionByIdSql = "SELECT session_id, user_id, device_id, session_status,"
                                                 "       authentication_level, created_at, expires_at,"
                                                 "       revoked_at, last_used_at "
                                                 "FROM sessions WHERE session_id = $1;";

constexpr std::string_view kListActiveSessionsByUserSql = "SELECT session_id, user_id, device_id, session_status,"
                                                          "       authentication_level, created_at, expires_at,"
                                                          "       revoked_at, last_used_at "
                                                          "FROM sessions "
                                                          "WHERE user_id = $1 AND session_status = 'Active' "
                                                          "ORDER BY created_at DESC;";

constexpr std::string_view kListActiveSessionsByDeviceSql = "SELECT session_id, user_id, device_id, session_status,"
                                                            "       authentication_level, created_at, expires_at,"
                                                            "       revoked_at, last_used_at "
                                                            "FROM sessions "
                                                            "WHERE device_id = $1 AND session_status = 'Active' "
                                                            "ORDER BY created_at DESC;";

constexpr std::string_view kUpdateAuthLevelSql = "UPDATE sessions "
                                                 "SET authentication_level = $1 "
                                                 "WHERE session_id = $2 AND session_status = 'Active';";

constexpr std::string_view kRevokeSessionSql = "UPDATE sessions "
                                               "SET session_status = 'Revoked', revoked_at = $1 "
                                               "WHERE session_id = $2 AND session_status = 'Active';";

constexpr std::string_view kRevokeAllUserSessionsSql = "UPDATE sessions "
                                                       "SET session_status = 'Revoked', revoked_at = $1 "
                                                       "WHERE user_id = $2 AND session_status = 'Active';";

constexpr std::string_view kRevokeAllDeviceSessionsSql = "UPDATE sessions "
                                                         "SET session_status = 'Revoked', revoked_at = $1 "
                                                         "WHERE device_id = $2 AND session_status = 'Active';";

constexpr std::string_view kGetSessionStatusSql = "SELECT session_status FROM sessions WHERE session_id = $1;";

constexpr std::string_view kTouchSessionActivitySql = "UPDATE sessions "
                                                      "SET last_used_at = $1 "
                                                      "WHERE session_id = $2 AND session_status = 'Active' AND "
                                                      "expires_at > $1;";

constexpr std::string_view kExpireStaleSessionsSql = "UPDATE sessions "
                                                     "SET session_status = 'Expired' "
                                                     "WHERE session_status = 'Active' AND expires_at <= $1;";

constexpr std::string_view kRevokeSessionAtomicSql = "UPDATE sessions "
                                                     "SET session_status = 'Revoked', revoked_at = $1 "
                                                     "WHERE session_id = $2 AND session_status = 'Active';";

constexpr std::string_view kRevokeAllDeviceSessionsAtomicSql = "UPDATE sessions "
                                                               "SET session_status = 'Revoked', revoked_at = $1 "
                                                               "WHERE device_id = $2 AND session_status = 'Active';";

constexpr std::string_view kRevokeAllUserSessionsAtomicSql = "UPDATE sessions "
                                                             "SET session_status = 'Revoked', revoked_at = $1 "
                                                             "WHERE user_id = $2 AND session_status = 'Active';";

} // namespace

PostgresSessionRepository::PostgresSessionRepository(db::PostgresConnectionPool& pool) : pool_(pool) {}

void PostgresSessionRepository::create_session(const domain::SessionEntity& session) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    create_session(session, tx);
    tx.commit();
}

void PostgresSessionRepository::create_session(const domain::SessionEntity& session, pqxx::transaction_base& tx) {
    try {
        const std::optional<std::string> revoked_at_str =
            session.revoked_at.has_value() ? std::optional<std::string>{domain::to_iso8601(*session.revoked_at)}
                                           : std::nullopt;

        db::exec_sql(tx, kInsertSessionSql,
                     pqxx::params{session.session_id.to_string(), session.user_id.to_string(),
                                  session.device_id.to_string(), domain::to_string(session.session_status),
                                  domain::to_string(session.authentication_level),
                                  domain::to_iso8601(session.created_at), domain::to_iso8601(session.expires_at),
                                  revoked_at_str, domain::to_iso8601(session.last_used_at)});
    } catch (const pqxx::unique_violation&) {
        throw DuplicateEntityException("Session already exists: " + session.session_id.to_string());
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to insert session: " + std::string(ex.what()));
    }
}

std::optional<domain::SessionEntity> PostgresSessionRepository::find_by_id(const domain::Uuid& session_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = find_by_id(session_id, tx);
    tx.commit();
    return res;
}

std::optional<domain::SessionEntity> PostgresSessionRepository::find_by_id(const domain::Uuid& session_id,
                                                                           pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kFindSessionByIdSql, pqxx::params{session_id.to_string()});
        if (res.empty()) {
            return std::nullopt;
        }
        return domain::session_from_row(pqxx::row(res[0]));
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to find session by id: " + std::string(ex.what()));
    }
}

std::vector<domain::SessionEntity> PostgresSessionRepository::list_active_by_user_id(const domain::Uuid& user_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = list_active_by_user_id(user_id, tx);
    tx.commit();
    return res;
}

std::vector<domain::SessionEntity> PostgresSessionRepository::list_active_by_user_id(const domain::Uuid& user_id,
                                                                                     pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kListActiveSessionsByUserSql, pqxx::params{user_id.to_string()});
        std::vector<domain::SessionEntity> sessions;
        sessions.reserve(static_cast<std::size_t>(res.size()));
        for (const auto& row : res) {
            sessions.push_back(domain::session_from_row(pqxx::row(row)));
        }
        return sessions;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to list active sessions by user: " + std::string(ex.what()));
    }
}

std::vector<domain::SessionEntity> PostgresSessionRepository::list_active_by_device_id(const domain::Uuid& device_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = list_active_by_device_id(device_id, tx);
    tx.commit();
    return res;
}

std::vector<domain::SessionEntity> PostgresSessionRepository::list_active_by_device_id(const domain::Uuid& device_id,
                                                                                       pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kListActiveSessionsByDeviceSql, pqxx::params{device_id.to_string()});
        std::vector<domain::SessionEntity> sessions;
        sessions.reserve(static_cast<std::size_t>(res.size()));
        for (const auto& row : res) {
            sessions.push_back(domain::session_from_row(pqxx::row(row)));
        }
        return sessions;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to list active sessions by device: " + std::string(ex.what()));
    }
}

void PostgresSessionRepository::update_authentication_level(const domain::Uuid& session_id,
                                                            domain::AuthenticationLevel level) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    update_authentication_level(session_id, level, tx);
    tx.commit();
}

void PostgresSessionRepository::update_authentication_level(const domain::Uuid& session_id,
                                                            domain::AuthenticationLevel level,
                                                            pqxx::transaction_base& tx) {
    try {
        auto res =
            db::exec_sql(tx, kUpdateAuthLevelSql, pqxx::params{domain::to_string(level), session_id.to_string()});

        if (res.affected_rows() == 0) {
            auto check = db::exec_sql(tx, kGetSessionStatusSql, pqxx::params{session_id.to_string()});
            if (check.empty()) {
                throw EntityNotFoundException("Session not found: " + session_id.to_string());
            }
            throw InvalidEntityStateException("Cannot update authentication level on non-active session: " +
                                              session_id.to_string());
        }
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to update session authentication level: " + std::string(ex.what()));
    }
}

void PostgresSessionRepository::revoke_session(const domain::Uuid& session_id, domain::time_point revoked_at) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    revoke_session(session_id, revoked_at, tx);
    tx.commit();
}

void PostgresSessionRepository::revoke_session(const domain::Uuid& session_id, domain::time_point revoked_at,
                                               pqxx::transaction_base& tx) {
    try {
        auto res =
            db::exec_sql(tx, kRevokeSessionSql, pqxx::params{domain::to_iso8601(revoked_at), session_id.to_string()});

        if (res.affected_rows() == 0) {
            auto check = db::exec_sql(tx, kGetSessionStatusSql, pqxx::params{session_id.to_string()});
            if (check.empty()) {
                throw EntityNotFoundException("Session not found: " + session_id.to_string());
            }
            // If already revoked, operation is idempotent
        }
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to revoke session: " + std::string(ex.what()));
    }
}

void PostgresSessionRepository::revoke_all_user_sessions(const domain::Uuid& user_id, domain::time_point revoked_at) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    revoke_all_user_sessions(user_id, revoked_at, tx);
    tx.commit();
}

void PostgresSessionRepository::revoke_all_user_sessions(const domain::Uuid& user_id, domain::time_point revoked_at,
                                                         pqxx::transaction_base& tx) {
    try {
        db::exec_sql(tx, kRevokeAllUserSessionsSql, pqxx::params{domain::to_iso8601(revoked_at), user_id.to_string()});
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to revoke user sessions: " + std::string(ex.what()));
    }
}

void PostgresSessionRepository::revoke_all_device_sessions(const domain::Uuid& device_id,
                                                           domain::time_point revoked_at) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    revoke_all_device_sessions(device_id, revoked_at, tx);
    tx.commit();
}

void PostgresSessionRepository::revoke_all_device_sessions(const domain::Uuid& device_id, domain::time_point revoked_at,
                                                           pqxx::transaction_base& tx) {
    try {
        db::exec_sql(tx, kRevokeAllDeviceSessionsSql,
                     pqxx::params{domain::to_iso8601(revoked_at), device_id.to_string()});
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to revoke device sessions: " + std::string(ex.what()));
    }
}

bool PostgresSessionRepository::touch_session_activity(const domain::Uuid& session_id, domain::time_point now) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    bool result = touch_session_activity(session_id, now, tx);
    tx.commit();
    return result;
}

bool PostgresSessionRepository::touch_session_activity(const domain::Uuid& session_id, domain::time_point now,
                                                       pqxx::transaction_base& tx) {
    try {
        auto res =
            db::exec_sql(tx, kTouchSessionActivitySql, pqxx::params{domain::to_iso8601(now), session_id.to_string()});
        return res.affected_rows() > 0;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to touch session activity: " + std::string(ex.what()));
    }
}

uint64_t PostgresSessionRepository::expire_stale_sessions(domain::time_point now) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    uint64_t result = expire_stale_sessions(now, tx);
    tx.commit();
    return result;
}

uint64_t PostgresSessionRepository::expire_stale_sessions(domain::time_point now, pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kExpireStaleSessionsSql, pqxx::params{domain::to_iso8601(now)});
        return static_cast<uint64_t>(res.affected_rows());
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to expire stale sessions: " + std::string(ex.what()));
    }
}

bool PostgresSessionRepository::revoke_session_atomic(const domain::Uuid& session_id, domain::time_point revoked_at) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    bool result = revoke_session_atomic(session_id, revoked_at, tx);
    tx.commit();
    return result;
}

bool PostgresSessionRepository::revoke_session_atomic(const domain::Uuid& session_id, domain::time_point revoked_at,
                                                      pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kRevokeSessionAtomicSql,
                                pqxx::params{domain::to_iso8601(revoked_at), session_id.to_string()});
        return res.affected_rows() > 0;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to atomically revoke session: " + std::string(ex.what()));
    }
}

uint64_t PostgresSessionRepository::revoke_all_device_sessions_atomic(const domain::Uuid& device_id,
                                                                      domain::time_point revoked_at) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    uint64_t result = revoke_all_device_sessions_atomic(device_id, revoked_at, tx);
    tx.commit();
    return result;
}

uint64_t PostgresSessionRepository::revoke_all_device_sessions_atomic(const domain::Uuid& device_id,
                                                                      domain::time_point revoked_at,
                                                                      pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kRevokeAllDeviceSessionsAtomicSql,
                                pqxx::params{domain::to_iso8601(revoked_at), device_id.to_string()});
        return static_cast<uint64_t>(res.affected_rows());
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to atomically revoke device sessions: " + std::string(ex.what()));
    }
}

uint64_t PostgresSessionRepository::revoke_all_user_sessions_atomic(const domain::Uuid& user_id,
                                                                    domain::time_point revoked_at) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    uint64_t result = revoke_all_user_sessions_atomic(user_id, revoked_at, tx);
    tx.commit();
    return result;
}

uint64_t PostgresSessionRepository::revoke_all_user_sessions_atomic(const domain::Uuid& user_id,
                                                                    domain::time_point revoked_at,
                                                                    pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kRevokeAllUserSessionsAtomicSql,
                                pqxx::params{domain::to_iso8601(revoked_at), user_id.to_string()});
        return static_cast<uint64_t>(res.affected_rows());
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to atomically revoke user sessions: " + std::string(ex.what()));
    }
}

} // namespace securecloud::auth::repository
