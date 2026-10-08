#pragma once

#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/repository/exceptions.hpp"

#include <optional>
#include <pqxx/pqxx>
#include <string_view>
#include <vector>

namespace securecloud::auth::repository {

/// Abstract interface contract for Device persistence operations.
class IDeviceRepository {
  public:
    virtual ~IDeviceRepository() = default;

    virtual void register_device(const domain::DeviceEntity& device) = 0;
    virtual void register_device(const domain::DeviceEntity& device, pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::optional<domain::DeviceEntity> find_by_id(const domain::Uuid& device_id) = 0;
    [[nodiscard]] virtual std::optional<domain::DeviceEntity> find_by_id(const domain::Uuid& device_id,
                                                                         pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::vector<domain::DeviceEntity> list_active_by_user_id(const domain::Uuid& user_id) = 0;
    [[nodiscard]] virtual std::vector<domain::DeviceEntity> list_active_by_user_id(const domain::Uuid& user_id,
                                                                                   pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::vector<domain::DeviceEntity> list_all_by_user_id(const domain::Uuid& user_id,
                                                                                bool include_revoked = false) = 0;
    [[nodiscard]] virtual std::vector<domain::DeviceEntity>
    list_all_by_user_id(const domain::Uuid& user_id, bool include_revoked, pqxx::transaction_base& tx) = 0;

    virtual void authorize_device(const domain::Uuid& device_id, domain::time_point authorized_at) = 0;
    virtual void authorize_device(const domain::Uuid& device_id, domain::time_point authorized_at,
                                  pqxx::transaction_base& tx) = 0;

    virtual void revoke_device(const domain::Uuid& device_id, std::string_view reason,
                               domain::time_point revoked_at) = 0;
    virtual void revoke_device(const domain::Uuid& device_id, std::string_view reason, domain::time_point revoked_at,
                               pqxx::transaction_base& tx) = 0;

    virtual void update_last_authenticated(const domain::Uuid& device_id, domain::time_point auth_time) = 0;
    virtual void update_last_authenticated(const domain::Uuid& device_id, domain::time_point auth_time,
                                           pqxx::transaction_base& tx) = 0;
};

/// PostgreSQL-backed implementation of IDeviceRepository.
class PostgresDeviceRepository : public IDeviceRepository {
  public:
    explicit PostgresDeviceRepository(db::PostgresConnectionPool& pool);

    void register_device(const domain::DeviceEntity& device) override;
    void register_device(const domain::DeviceEntity& device, pqxx::transaction_base& tx) override;

    [[nodiscard]] std::optional<domain::DeviceEntity> find_by_id(const domain::Uuid& device_id) override;
    [[nodiscard]] std::optional<domain::DeviceEntity> find_by_id(const domain::Uuid& device_id,
                                                                 pqxx::transaction_base& tx) override;

    [[nodiscard]] std::vector<domain::DeviceEntity> list_active_by_user_id(const domain::Uuid& user_id) override;
    [[nodiscard]] std::vector<domain::DeviceEntity> list_active_by_user_id(const domain::Uuid& user_id,
                                                                           pqxx::transaction_base& tx) override;

    [[nodiscard]] std::vector<domain::DeviceEntity> list_all_by_user_id(const domain::Uuid& user_id,
                                                                        bool include_revoked = false) override;
    [[nodiscard]] std::vector<domain::DeviceEntity>
    list_all_by_user_id(const domain::Uuid& user_id, bool include_revoked, pqxx::transaction_base& tx) override;

    void authorize_device(const domain::Uuid& device_id, domain::time_point authorized_at) override;
    void authorize_device(const domain::Uuid& device_id, domain::time_point authorized_at,
                          pqxx::transaction_base& tx) override;

    void revoke_device(const domain::Uuid& device_id, std::string_view reason, domain::time_point revoked_at) override;
    void revoke_device(const domain::Uuid& device_id, std::string_view reason, domain::time_point revoked_at,
                       pqxx::transaction_base& tx) override;

    void update_last_authenticated(const domain::Uuid& device_id, domain::time_point auth_time) override;
    void update_last_authenticated(const domain::Uuid& device_id, domain::time_point auth_time,
                                   pqxx::transaction_base& tx) override;

  private:
    db::PostgresConnectionPool& pool_;
};

} // namespace securecloud::auth::repository
