#pragma once

#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/repository/exceptions.hpp"

#include <optional>
#include <pqxx/pqxx>
#include <vector>

namespace securecloud::auth::repository {

/// Abstract interface contract for Multi-Factor Authentication state persistence.
class IMfaRepository {
  public:
    virtual ~IMfaRepository() = default;

    virtual void store_mfa_configuration(const domain::MfaConfigurationEntity& config) = 0;
    virtual void store_mfa_configuration(const domain::MfaConfigurationEntity& config, pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::optional<domain::MfaConfigurationEntity>
    find_mfa_config_by_user_id(const domain::Uuid& user_id) = 0;
    [[nodiscard]] virtual std::optional<domain::MfaConfigurationEntity>
    find_mfa_config_by_user_id(const domain::Uuid& user_id, pqxx::transaction_base& tx) = 0;

    virtual void enable_mfa(const domain::Uuid& config_id, domain::time_point enabled_at,
                            uint64_t expected_version) = 0;
    virtual void enable_mfa(const domain::Uuid& config_id, domain::time_point enabled_at, uint64_t expected_version,
                            pqxx::transaction_base& tx) = 0;

    virtual void disable_mfa(const domain::Uuid& config_id, domain::time_point disabled_at,
                             uint64_t expected_version) = 0;
    virtual void disable_mfa(const domain::Uuid& config_id, domain::time_point disabled_at, uint64_t expected_version,
                             pqxx::transaction_base& tx) = 0;

    virtual void create_challenge(const domain::MfaChallengeEntity& challenge) = 0;
    virtual void create_challenge(const domain::MfaChallengeEntity& challenge, pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::optional<domain::MfaChallengeEntity>
    find_challenge_by_id(const domain::Uuid& challenge_id) = 0;
    [[nodiscard]] virtual std::optional<domain::MfaChallengeEntity>
    find_challenge_by_id(const domain::Uuid& challenge_id, pqxx::transaction_base& tx) = 0;

    virtual void complete_challenge(const domain::Uuid& challenge_id, domain::time_point completed_at) = 0;
    virtual void complete_challenge(const domain::Uuid& challenge_id, domain::time_point completed_at,
                                    pqxx::transaction_base& tx) = 0;

    virtual void fail_challenge(const domain::Uuid& challenge_id) = 0;
    virtual void fail_challenge(const domain::Uuid& challenge_id, pqxx::transaction_base& tx) = 0;
};

/// PostgreSQL-backed implementation of IMfaRepository.
class PostgresMfaRepository : public IMfaRepository {
  public:
    explicit PostgresMfaRepository(db::PostgresConnectionPool& pool);

    void store_mfa_configuration(const domain::MfaConfigurationEntity& config) override;
    void store_mfa_configuration(const domain::MfaConfigurationEntity& config, pqxx::transaction_base& tx) override;

    [[nodiscard]] std::optional<domain::MfaConfigurationEntity>
    find_mfa_config_by_user_id(const domain::Uuid& user_id) override;
    [[nodiscard]] std::optional<domain::MfaConfigurationEntity>
    find_mfa_config_by_user_id(const domain::Uuid& user_id, pqxx::transaction_base& tx) override;

    void enable_mfa(const domain::Uuid& config_id, domain::time_point enabled_at, uint64_t expected_version) override;
    void enable_mfa(const domain::Uuid& config_id, domain::time_point enabled_at, uint64_t expected_version,
                    pqxx::transaction_base& tx) override;

    void disable_mfa(const domain::Uuid& config_id, domain::time_point disabled_at, uint64_t expected_version) override;
    void disable_mfa(const domain::Uuid& config_id, domain::time_point disabled_at, uint64_t expected_version,
                     pqxx::transaction_base& tx) override;

    void create_challenge(const domain::MfaChallengeEntity& challenge) override;
    void create_challenge(const domain::MfaChallengeEntity& challenge, pqxx::transaction_base& tx) override;

    [[nodiscard]] std::optional<domain::MfaChallengeEntity>
    find_challenge_by_id(const domain::Uuid& challenge_id) override;
    [[nodiscard]] std::optional<domain::MfaChallengeEntity> find_challenge_by_id(const domain::Uuid& challenge_id,
                                                                                 pqxx::transaction_base& tx) override;

    void complete_challenge(const domain::Uuid& challenge_id, domain::time_point completed_at) override;
    void complete_challenge(const domain::Uuid& challenge_id, domain::time_point completed_at,
                            pqxx::transaction_base& tx) override;

    void fail_challenge(const domain::Uuid& challenge_id) override;
    void fail_challenge(const domain::Uuid& challenge_id, pqxx::transaction_base& tx) override;

  private:
    db::PostgresConnectionPool& pool_;
};

} // namespace securecloud::auth::repository
