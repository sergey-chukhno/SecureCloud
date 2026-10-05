#include "auth/repository/mfa_repository.hpp"

#include "auth/domain/mappers.hpp"
#include "auth/domain/timestamp.hpp"

#include <chrono>

namespace securecloud::auth::repository {

namespace {

constexpr std::string_view kInsertMfaConfigSql = "INSERT INTO mfa_configurations ("
                                                 "    mfa_configuration_id, user_id, factor_type, encrypted_secret,"
                                                 "    status, created_at, enabled_at, disabled_at, version"
                                                 ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);";

constexpr std::string_view kFindMfaConfigByUserSql =
    "SELECT mfa_configuration_id, user_id, factor_type, encrypted_secret,"
    "       status, created_at, enabled_at, disabled_at, version "
    "FROM mfa_configurations WHERE user_id = $1;";

constexpr std::string_view kCheckMfaConfigExistsSql =
    "SELECT 1 FROM mfa_configurations WHERE mfa_configuration_id = $1;";

constexpr std::string_view kEnableMfaSql = "UPDATE mfa_configurations "
                                           "SET status = 'Enabled', enabled_at = $1, version = version + 1 "
                                           "WHERE mfa_configuration_id = $2 AND version = $3;";

constexpr std::string_view kDisableMfaSql = "UPDATE mfa_configurations "
                                            "SET status = 'Disabled', disabled_at = $1, version = version + 1 "
                                            "WHERE mfa_configuration_id = $2 AND version = $3;";

constexpr std::string_view kInsertChallengeSql = "INSERT INTO mfa_challenges ("
                                                 "    mfa_challenge_id, user_id, session_id, challenge_purpose,"
                                                 "    challenge_status, created_at, expires_at, completed_at"
                                                 ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8);";

constexpr std::string_view kFindChallengeByIdSql = "SELECT mfa_challenge_id, user_id, session_id, challenge_purpose,"
                                                   "       challenge_status, created_at, expires_at, completed_at "
                                                   "FROM mfa_challenges WHERE mfa_challenge_id = $1;";

constexpr std::string_view kCompleteChallengeSql =
    "UPDATE mfa_challenges "
    "SET challenge_status = 'Completed', completed_at = $1 "
    "WHERE mfa_challenge_id = $2 AND challenge_status = 'Pending' AND expires_at > $3;";

constexpr std::string_view kFailChallengeSql = "UPDATE mfa_challenges "
                                               "SET challenge_status = 'Failed' "
                                               "WHERE mfa_challenge_id = $1 AND challenge_status = 'Pending';";

} // namespace

PostgresMfaRepository::PostgresMfaRepository(db::PostgresConnectionPool& pool) : pool_(pool) {}

void PostgresMfaRepository::store_mfa_configuration(const domain::MfaConfigurationEntity& config) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    store_mfa_configuration(config, tx);
    tx.commit();
}

void PostgresMfaRepository::store_mfa_configuration(const domain::MfaConfigurationEntity& config,
                                                    pqxx::transaction_base& tx) {
    try {
        const std::optional<std::string> enabled_at_str =
            config.enabled_at.has_value() ? std::optional<std::string>{domain::to_iso8601(*config.enabled_at)}
                                          : std::nullopt;

        const std::optional<std::string> disabled_at_str =
            config.disabled_at.has_value() ? std::optional<std::string>{domain::to_iso8601(*config.disabled_at)}
                                           : std::nullopt;

        const uint64_t initial_version = (config.version == 0) ? 1 : config.version;
        pqxx::bytes_view sec_bytes(reinterpret_cast<const std::byte*>(config.encrypted_secret.data()),
                                   config.encrypted_secret.size());

        tx.exec(kInsertMfaConfigSql,
                pqxx::params{config.mfa_configuration_id.to_string(), config.user_id.to_string(),
                             domain::to_string(config.factor_type), sec_bytes, domain::to_string(config.status),
                             domain::to_iso8601(config.created_at), enabled_at_str, disabled_at_str, initial_version});
    } catch (const pqxx::unique_violation& ex) {
        throw DuplicateEntityException("MFA configuration already exists: " + config.mfa_configuration_id.to_string());
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to store MFA configuration: " + std::string(ex.what()));
    }
}

std::optional<domain::MfaConfigurationEntity>
PostgresMfaRepository::find_mfa_config_by_user_id(const domain::Uuid& user_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = find_mfa_config_by_user_id(user_id, tx);
    tx.commit();
    return res;
}

std::optional<domain::MfaConfigurationEntity>
PostgresMfaRepository::find_mfa_config_by_user_id(const domain::Uuid& user_id, pqxx::transaction_base& tx) {
    try {
        auto res = tx.exec(kFindMfaConfigByUserSql, pqxx::params{user_id.to_string()});
        if (res.empty()) {
            return std::nullopt;
        }
        return domain::mfa_configuration_from_row(pqxx::row(res[0]));
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to find MFA configuration by user id: " + std::string(ex.what()));
    }
}

void PostgresMfaRepository::enable_mfa(const domain::Uuid& config_id, domain::time_point enabled_at,
                                       uint64_t expected_version) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    enable_mfa(config_id, enabled_at, expected_version, tx);
    tx.commit();
}

void PostgresMfaRepository::enable_mfa(const domain::Uuid& config_id, domain::time_point enabled_at,
                                       uint64_t expected_version, pqxx::transaction_base& tx) {
    try {
        auto res = tx.exec(kEnableMfaSql,
                           pqxx::params{domain::to_iso8601(enabled_at), config_id.to_string(), expected_version});

        if (res.affected_rows() == 0) {
            auto check = tx.exec(kCheckMfaConfigExistsSql, pqxx::params{config_id.to_string()});
            if (!check.empty()) {
                throw OptimisticLockException("Concurrent modification detected for MFA configuration: " +
                                              config_id.to_string());
            }
            throw EntityNotFoundException("MFA configuration not found: " + config_id.to_string());
        }
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to enable MFA: " + std::string(ex.what()));
    }
}

void PostgresMfaRepository::disable_mfa(const domain::Uuid& config_id, domain::time_point disabled_at,
                                        uint64_t expected_version) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    disable_mfa(config_id, disabled_at, expected_version, tx);
    tx.commit();
}

void PostgresMfaRepository::disable_mfa(const domain::Uuid& config_id, domain::time_point disabled_at,
                                        uint64_t expected_version, pqxx::transaction_base& tx) {
    try {
        auto res = tx.exec(kDisableMfaSql,
                           pqxx::params{domain::to_iso8601(disabled_at), config_id.to_string(), expected_version});

        if (res.affected_rows() == 0) {
            auto check = tx.exec(kCheckMfaConfigExistsSql, pqxx::params{config_id.to_string()});
            if (!check.empty()) {
                throw OptimisticLockException("Concurrent modification detected for MFA configuration: " +
                                              config_id.to_string());
            }
            throw EntityNotFoundException("MFA configuration not found: " + config_id.to_string());
        }
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to disable MFA: " + std::string(ex.what()));
    }
}

void PostgresMfaRepository::create_challenge(const domain::MfaChallengeEntity& challenge) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    create_challenge(challenge, tx);
    tx.commit();
}

void PostgresMfaRepository::create_challenge(const domain::MfaChallengeEntity& challenge, pqxx::transaction_base& tx) {
    try {
        const std::optional<std::string> completed_at_str =
            challenge.completed_at.has_value() ? std::optional<std::string>{domain::to_iso8601(*challenge.completed_at)}
                                               : std::nullopt;

        tx.exec(kInsertChallengeSql,
                pqxx::params{challenge.mfa_challenge_id.to_string(), challenge.user_id.to_string(),
                             challenge.session_id.to_string(), domain::to_string(challenge.challenge_purpose),
                             domain::to_string(challenge.challenge_status), domain::to_iso8601(challenge.created_at),
                             domain::to_iso8601(challenge.expires_at), completed_at_str});
    } catch (const pqxx::unique_violation& ex) {
        throw DuplicateEntityException("MFA challenge already exists: " + challenge.mfa_challenge_id.to_string());
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to create MFA challenge: " + std::string(ex.what()));
    }
}

std::optional<domain::MfaChallengeEntity>
PostgresMfaRepository::find_challenge_by_id(const domain::Uuid& challenge_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = find_challenge_by_id(challenge_id, tx);
    tx.commit();
    return res;
}

std::optional<domain::MfaChallengeEntity> PostgresMfaRepository::find_challenge_by_id(const domain::Uuid& challenge_id,
                                                                                      pqxx::transaction_base& tx) {
    try {
        auto res = tx.exec(kFindChallengeByIdSql, pqxx::params{challenge_id.to_string()});
        if (res.empty()) {
            return std::nullopt;
        }
        return domain::mfa_challenge_from_row(pqxx::row(res[0]));
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to find MFA challenge by id: " + std::string(ex.what()));
    }
}

void PostgresMfaRepository::complete_challenge(const domain::Uuid& challenge_id, domain::time_point completed_at) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    complete_challenge(challenge_id, completed_at, tx);
    tx.commit();
}

void PostgresMfaRepository::complete_challenge(const domain::Uuid& challenge_id, domain::time_point completed_at,
                                               pqxx::transaction_base& tx) {
    try {
        const auto now = std::chrono::system_clock::now();
        auto res = tx.exec(kCompleteChallengeSql, pqxx::params{domain::to_iso8601(completed_at),
                                                               challenge_id.to_string(), domain::to_iso8601(now)});

        if (res.affected_rows() == 0) {
            auto challenge_opt = find_challenge_by_id(challenge_id, tx);
            if (!challenge_opt.has_value()) {
                throw EntityNotFoundException("MFA challenge not found: " + challenge_id.to_string());
            }
            throw InvalidEntityStateException("Cannot complete challenge (expired or not pending): " +
                                              challenge_id.to_string());
        }
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to complete MFA challenge: " + std::string(ex.what()));
    }
}

void PostgresMfaRepository::fail_challenge(const domain::Uuid& challenge_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    fail_challenge(challenge_id, tx);
    tx.commit();
}

void PostgresMfaRepository::fail_challenge(const domain::Uuid& challenge_id, pqxx::transaction_base& tx) {
    try {
        auto res = tx.exec(kFailChallengeSql, pqxx::params{challenge_id.to_string()});
        if (res.affected_rows() == 0) {
            auto challenge_opt = find_challenge_by_id(challenge_id, tx);
            if (!challenge_opt.has_value()) {
                throw EntityNotFoundException("MFA challenge not found: " + challenge_id.to_string());
            }
            throw InvalidEntityStateException("Cannot fail non-pending MFA challenge: " + challenge_id.to_string());
        }
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to fail MFA challenge: " + std::string(ex.what()));
    }
}

} // namespace securecloud::auth::repository
