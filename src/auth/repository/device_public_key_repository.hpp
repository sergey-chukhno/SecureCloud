#pragma once

#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/repository/exceptions.hpp"

#include <optional>
#include <pqxx/pqxx>
#include <vector>

namespace securecloud::auth::repository {

/// Abstract interface contract for Device Public Key directory persistence.
class IDevicePublicKeyRepository {
  public:
    virtual ~IDevicePublicKeyRepository() = default;

    virtual void store_public_key(const domain::DevicePublicKeyEntity& key) = 0;
    virtual void store_public_key(const domain::DevicePublicKeyEntity& key, pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::optional<domain::DevicePublicKeyEntity> find_by_id(const domain::Uuid& key_id) = 0;
    [[nodiscard]] virtual std::optional<domain::DevicePublicKeyEntity> find_by_id(const domain::Uuid& key_id,
                                                                                  pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::vector<domain::DevicePublicKeyEntity>
    list_active_keys_by_device_id(const domain::Uuid& device_id) = 0;
    [[nodiscard]] virtual std::vector<domain::DevicePublicKeyEntity>
    list_active_keys_by_device_id(const domain::Uuid& device_id, pqxx::transaction_base& tx) = 0;

    virtual void replace_key(const domain::Uuid& old_key_id, const domain::DevicePublicKeyEntity& new_key) = 0;
    virtual void replace_key(const domain::Uuid& old_key_id, const domain::DevicePublicKeyEntity& new_key,
                             pqxx::transaction_base& tx) = 0;

    virtual void revoke_all_device_keys(const domain::Uuid& device_id, domain::time_point revoked_at) = 0;
    virtual void revoke_all_device_keys(const domain::Uuid& device_id, domain::time_point revoked_at,
                                        pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::optional<domain::DevicePublicKeyEntity>
    claim_one_time_prekey(const domain::Uuid& device_id) = 0;
    [[nodiscard]] virtual std::optional<domain::DevicePublicKeyEntity>
    claim_one_time_prekey(const domain::Uuid& device_id, pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual int32_t count_active_one_time_prekeys(const domain::Uuid& device_id) = 0;
    [[nodiscard]] virtual int32_t count_active_one_time_prekeys(const domain::Uuid& device_id,
                                                                pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::optional<domain::DevicePublicKeyEntity>
    find_active_identity_key(const domain::Uuid& device_id) = 0;
    [[nodiscard]] virtual std::optional<domain::DevicePublicKeyEntity>
    find_active_identity_key(const domain::Uuid& device_id, pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::optional<domain::DevicePublicKeyEntity>
    find_active_signed_prekey(const domain::Uuid& device_id) = 0;
    [[nodiscard]] virtual std::optional<domain::DevicePublicKeyEntity>
    find_active_signed_prekey(const domain::Uuid& device_id, pqxx::transaction_base& tx) = 0;

    virtual void store_one_time_prekeys(const domain::Uuid& device_id,
                                        const std::vector<std::vector<uint8_t>>& keys) = 0;
    virtual void store_one_time_prekeys(const domain::Uuid& device_id, const std::vector<std::vector<uint8_t>>& keys,
                                        pqxx::transaction_base& tx) = 0;
};

/// PostgreSQL-backed implementation of IDevicePublicKeyRepository.
class PostgresDevicePublicKeyRepository : public IDevicePublicKeyRepository {
  public:
    explicit PostgresDevicePublicKeyRepository(db::PostgresConnectionPool& pool);

    void store_public_key(const domain::DevicePublicKeyEntity& key) override;
    void store_public_key(const domain::DevicePublicKeyEntity& key, pqxx::transaction_base& tx) override;

    [[nodiscard]] std::optional<domain::DevicePublicKeyEntity> find_by_id(const domain::Uuid& key_id) override;
    [[nodiscard]] std::optional<domain::DevicePublicKeyEntity> find_by_id(const domain::Uuid& key_id,
                                                                          pqxx::transaction_base& tx) override;

    [[nodiscard]] std::vector<domain::DevicePublicKeyEntity>
    list_active_keys_by_device_id(const domain::Uuid& device_id) override;
    [[nodiscard]] std::vector<domain::DevicePublicKeyEntity>
    list_active_keys_by_device_id(const domain::Uuid& device_id, pqxx::transaction_base& tx) override;

    void replace_key(const domain::Uuid& old_key_id, const domain::DevicePublicKeyEntity& new_key) override;
    void replace_key(const domain::Uuid& old_key_id, const domain::DevicePublicKeyEntity& new_key,
                     pqxx::transaction_base& tx) override;

    void revoke_all_device_keys(const domain::Uuid& device_id, domain::time_point revoked_at) override;
    void revoke_all_device_keys(const domain::Uuid& device_id, domain::time_point revoked_at,
                                pqxx::transaction_base& tx) override;

    [[nodiscard]] std::optional<domain::DevicePublicKeyEntity>
    claim_one_time_prekey(const domain::Uuid& device_id) override;
    [[nodiscard]] std::optional<domain::DevicePublicKeyEntity>
    claim_one_time_prekey(const domain::Uuid& device_id, pqxx::transaction_base& tx) override;

    [[nodiscard]] int32_t count_active_one_time_prekeys(const domain::Uuid& device_id) override;
    [[nodiscard]] int32_t count_active_one_time_prekeys(const domain::Uuid& device_id,
                                                        pqxx::transaction_base& tx) override;

    [[nodiscard]] std::optional<domain::DevicePublicKeyEntity>
    find_active_identity_key(const domain::Uuid& device_id) override;
    [[nodiscard]] std::optional<domain::DevicePublicKeyEntity>
    find_active_identity_key(const domain::Uuid& device_id, pqxx::transaction_base& tx) override;

    [[nodiscard]] std::optional<domain::DevicePublicKeyEntity>
    find_active_signed_prekey(const domain::Uuid& device_id) override;
    [[nodiscard]] std::optional<domain::DevicePublicKeyEntity>
    find_active_signed_prekey(const domain::Uuid& device_id, pqxx::transaction_base& tx) override;

    void store_one_time_prekeys(const domain::Uuid& device_id, const std::vector<std::vector<uint8_t>>& keys) override;
    void store_one_time_prekeys(const domain::Uuid& device_id, const std::vector<std::vector<uint8_t>>& keys,
                                pqxx::transaction_base& tx) override;

  private:
    db::PostgresConnectionPool& pool_;
};

} // namespace securecloud::auth::repository
