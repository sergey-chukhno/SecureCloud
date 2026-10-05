#pragma once

#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/repository/exceptions.hpp"

#include <optional>
#include <pqxx/pqxx>
#include <vector>

namespace securecloud::auth::repository {

/// Abstract interface contract for Session persistence operations.
class ISessionRepository {
  public:
    virtual ~ISessionRepository() = default;

    virtual void create_session(const domain::SessionEntity& session) = 0;
    virtual void create_session(const domain::SessionEntity& session, pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::optional<domain::SessionEntity> find_by_id(const domain::Uuid& session_id) = 0;
    [[nodiscard]] virtual std::optional<domain::SessionEntity> find_by_id(const domain::Uuid& session_id,
                                                                          pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::vector<domain::SessionEntity> list_active_by_user_id(const domain::Uuid& user_id) = 0;
    [[nodiscard]] virtual std::vector<domain::SessionEntity> list_active_by_user_id(const domain::Uuid& user_id,
                                                                                    pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::vector<domain::SessionEntity>
    list_active_by_device_id(const domain::Uuid& device_id) = 0;
    [[nodiscard]] virtual std::vector<domain::SessionEntity> list_active_by_device_id(const domain::Uuid& device_id,
                                                                                      pqxx::transaction_base& tx) = 0;

    virtual void update_authentication_level(const domain::Uuid& session_id, domain::AuthenticationLevel level) = 0;
    virtual void update_authentication_level(const domain::Uuid& session_id, domain::AuthenticationLevel level,
                                             pqxx::transaction_base& tx) = 0;

    virtual void revoke_session(const domain::Uuid& session_id, domain::time_point revoked_at) = 0;
    virtual void revoke_session(const domain::Uuid& session_id, domain::time_point revoked_at,
                                pqxx::transaction_base& tx) = 0;

    virtual void revoke_all_user_sessions(const domain::Uuid& user_id, domain::time_point revoked_at) = 0;
    virtual void revoke_all_user_sessions(const domain::Uuid& user_id, domain::time_point revoked_at,
                                          pqxx::transaction_base& tx) = 0;

    virtual void revoke_all_device_sessions(const domain::Uuid& device_id, domain::time_point revoked_at) = 0;
    virtual void revoke_all_device_sessions(const domain::Uuid& device_id, domain::time_point revoked_at,
                                            pqxx::transaction_base& tx) = 0;
};

/// PostgreSQL-backed implementation of ISessionRepository.
class PostgresSessionRepository : public ISessionRepository {
  public:
    explicit PostgresSessionRepository(db::PostgresConnectionPool& pool);

    void create_session(const domain::SessionEntity& session) override;
    void create_session(const domain::SessionEntity& session, pqxx::transaction_base& tx) override;

    [[nodiscard]] std::optional<domain::SessionEntity> find_by_id(const domain::Uuid& session_id) override;
    [[nodiscard]] std::optional<domain::SessionEntity> find_by_id(const domain::Uuid& session_id,
                                                                  pqxx::transaction_base& tx) override;

    [[nodiscard]] std::vector<domain::SessionEntity> list_active_by_user_id(const domain::Uuid& user_id) override;
    [[nodiscard]] std::vector<domain::SessionEntity> list_active_by_user_id(const domain::Uuid& user_id,
                                                                            pqxx::transaction_base& tx) override;

    [[nodiscard]] std::vector<domain::SessionEntity> list_active_by_device_id(const domain::Uuid& device_id) override;
    [[nodiscard]] std::vector<domain::SessionEntity> list_active_by_device_id(const domain::Uuid& device_id,
                                                                              pqxx::transaction_base& tx) override;

    void update_authentication_level(const domain::Uuid& session_id, domain::AuthenticationLevel level) override;
    void update_authentication_level(const domain::Uuid& session_id, domain::AuthenticationLevel level,
                                     pqxx::transaction_base& tx) override;

    void revoke_session(const domain::Uuid& session_id, domain::time_point revoked_at) override;
    void revoke_session(const domain::Uuid& session_id, domain::time_point revoked_at,
                        pqxx::transaction_base& tx) override;

    void revoke_all_user_sessions(const domain::Uuid& user_id, domain::time_point revoked_at) override;
    void revoke_all_user_sessions(const domain::Uuid& user_id, domain::time_point revoked_at,
                                  pqxx::transaction_base& tx) override;

    void revoke_all_device_sessions(const domain::Uuid& device_id, domain::time_point revoked_at) override;
    void revoke_all_device_sessions(const domain::Uuid& device_id, domain::time_point revoked_at,
                                    pqxx::transaction_base& tx) override;

  private:
    db::PostgresConnectionPool& pool_;
};

} // namespace securecloud::auth::repository
