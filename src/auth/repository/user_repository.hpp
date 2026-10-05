#pragma once

#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/repository/exceptions.hpp"

#include <optional>
#include <pqxx/pqxx>
#include <string_view>

namespace securecloud::auth::repository {

/// Abstract interface contract for User persistence operations.
class IUserRepository {
  public:
    virtual ~IUserRepository() = default;

    virtual void create_user(const domain::UserEntity& user) = 0;
    virtual void create_user(const domain::UserEntity& user, pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::optional<domain::UserEntity> find_by_id(const domain::Uuid& user_id) = 0;
    [[nodiscard]] virtual std::optional<domain::UserEntity> find_by_id(const domain::Uuid& user_id,
                                                                       pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::optional<domain::UserEntity>
    find_by_credential_identifier(std::string_view credential_identifier) = 0;
    [[nodiscard]] virtual std::optional<domain::UserEntity>
    find_by_credential_identifier(std::string_view credential_identifier, pqxx::transaction_base& tx) = 0;

    virtual void update_user(const domain::UserEntity& user) = 0;
    virtual void update_user(const domain::UserEntity& user, pqxx::transaction_base& tx) = 0;

    virtual void set_account_status(const domain::Uuid& user_id, domain::AccountStatus status,
                                    uint64_t expected_version) = 0;
    virtual void set_account_status(const domain::Uuid& user_id, domain::AccountStatus status,
                                    uint64_t expected_version, pqxx::transaction_base& tx) = 0;
};

/// PostgreSQL-backed implementation of IUserRepository utilizing connection pooling and libpqxx.
class PostgresUserRepository : public IUserRepository {
  public:
    explicit PostgresUserRepository(db::PostgresConnectionPool& pool);

    void create_user(const domain::UserEntity& user) override;
    void create_user(const domain::UserEntity& user, pqxx::transaction_base& tx) override;

    [[nodiscard]] std::optional<domain::UserEntity> find_by_id(const domain::Uuid& user_id) override;
    [[nodiscard]] std::optional<domain::UserEntity> find_by_id(const domain::Uuid& user_id,
                                                               pqxx::transaction_base& tx) override;

    [[nodiscard]] std::optional<domain::UserEntity>
    find_by_credential_identifier(std::string_view credential_identifier) override;
    [[nodiscard]] std::optional<domain::UserEntity>
    find_by_credential_identifier(std::string_view credential_identifier, pqxx::transaction_base& tx) override;

    void update_user(const domain::UserEntity& user) override;
    void update_user(const domain::UserEntity& user, pqxx::transaction_base& tx) override;

    void set_account_status(const domain::Uuid& user_id, domain::AccountStatus status,
                            uint64_t expected_version) override;
    void set_account_status(const domain::Uuid& user_id, domain::AccountStatus status, uint64_t expected_version,
                            pqxx::transaction_base& tx) override;

  private:
    db::PostgresConnectionPool& pool_;
};

} // namespace securecloud::auth::repository
