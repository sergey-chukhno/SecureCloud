#include "auth/repository/device_public_key_repository.hpp"

#include "auth/domain/mappers.hpp"
#include "auth/domain/timestamp.hpp"

#include <chrono>

namespace securecloud::auth::repository {

namespace {

constexpr std::string_view kInsertPublicKeySql = "INSERT INTO device_public_keys ("
                                                 "    key_id, device_id, key_type, public_key,"
                                                 "    key_status, created_at, revoked_at, replaced_by_key_id,"
                                                 "    signature"
                                                 ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);";

constexpr std::string_view kFindPublicKeyByIdSql =
    "SELECT key_id, device_id, key_type, public_key,"
    "       key_status, created_at, revoked_at, replaced_by_key_id, signature "
    "FROM device_public_keys WHERE key_id = $1;";

constexpr std::string_view kFindPublicKeyByIdForUpdateSql =
    "SELECT key_id, device_id, key_type, public_key,"
    "       key_status, created_at, revoked_at, replaced_by_key_id, signature "
    "FROM device_public_keys WHERE key_id = $1 FOR UPDATE;";

constexpr std::string_view kListActiveKeysByDeviceSql =
    "SELECT key_id, device_id, key_type, public_key,"
    "       key_status, created_at, revoked_at, replaced_by_key_id, signature "
    "FROM device_public_keys "
    "WHERE device_id = $1 AND key_status = 'Active' "
    "ORDER BY created_at ASC;";

constexpr std::string_view kUpdateKeyReplacedSql = "UPDATE device_public_keys "
                                                   "SET key_status = 'Replaced', replaced_by_key_id = $1 "
                                                   "WHERE key_id = $2 AND key_status = 'Active';";

constexpr std::string_view kRevokeAllDeviceKeysSql = "UPDATE device_public_keys "
                                                     "SET key_status = 'Revoked', revoked_at = $1 "
                                                     "WHERE device_id = $2 AND key_status = 'Active';";

constexpr std::string_view kClaimOneTimePrekeySql =
    "SELECT key_id, device_id, key_type, public_key, key_status, created_at, revoked_at, replaced_by_key_id, signature "
    "FROM device_public_keys "
    "WHERE device_id = $1 AND key_type = 'ONE_TIME_PREKEY' AND key_status = 'Active' "
    "ORDER BY created_at ASC "
    "LIMIT 1 FOR UPDATE SKIP LOCKED;";

constexpr std::string_view kMarkPrekeyClaimedSql = "UPDATE device_public_keys "
                                                   "SET key_status = 'Claimed' "
                                                   "WHERE key_id = $1 AND key_status = 'Active';";

constexpr std::string_view kCountActiveOneTimePrekeysSql =
    "SELECT COUNT(*) "
    "FROM device_public_keys "
    "WHERE device_id = $1 AND key_type = 'ONE_TIME_PREKEY' AND key_status = 'Active';";

constexpr std::string_view kFindActiveIdentityKeySql =
    "SELECT key_id, device_id, key_type, public_key, key_status, created_at, revoked_at, replaced_by_key_id, signature "
    "FROM device_public_keys "
    "WHERE device_id = $1 AND key_type = 'IDENTITY_SIGNING' AND key_status = 'Active' "
    "ORDER BY created_at DESC "
    "LIMIT 1;";

constexpr std::string_view kFindActiveSignedPrekeySql =
    "SELECT key_id, device_id, key_type, public_key, key_status, created_at, revoked_at, replaced_by_key_id, signature "
    "FROM device_public_keys "
    "WHERE device_id = $1 AND key_type = 'SIGNED_PREKEY' AND key_status = 'Active' "
    "ORDER BY created_at DESC "
    "LIMIT 1;";

} // namespace

PostgresDevicePublicKeyRepository::PostgresDevicePublicKeyRepository(db::PostgresConnectionPool& pool) : pool_(pool) {}

void PostgresDevicePublicKeyRepository::store_public_key(const domain::DevicePublicKeyEntity& key) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    store_public_key(key, tx);
    tx.commit();
}

void PostgresDevicePublicKeyRepository::store_public_key(const domain::DevicePublicKeyEntity& key,
                                                         pqxx::transaction_base& tx) {
    try {
        const std::optional<std::string> revoked_at_str =
            key.revoked_at.has_value() ? std::optional<std::string>{domain::to_iso8601(*key.revoked_at)} : std::nullopt;

        const std::optional<std::string> replaced_by_str =
            key.replaced_by_key_id.has_value() ? std::optional<std::string>{key.replaced_by_key_id->to_string()}
                                               : std::nullopt;

        pqxx::bytes_view pk_bytes(reinterpret_cast<const std::byte*>(key.public_key.data()), key.public_key.size());

        std::optional<pqxx::bytes_view> sig_bytes = std::nullopt;
        if (key.signature.has_value()) {
            sig_bytes =
                pqxx::bytes_view(reinterpret_cast<const std::byte*>(key.signature->data()), key.signature->size());
        }

        db::exec_sql(tx, kInsertPublicKeySql,
                     pqxx::params{key.key_id.to_string(), key.device_id.to_string(), domain::to_string(key.key_type),
                                  pk_bytes, domain::to_string(key.key_status), domain::to_iso8601(key.created_at),
                                  revoked_at_str, replaced_by_str, sig_bytes});
    } catch (const pqxx::unique_violation&) {
        throw DuplicateEntityException("Device public key already exists: " + key.key_id.to_string());
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to insert device public key: " + std::string(ex.what()));
    }
}

std::optional<domain::DevicePublicKeyEntity> PostgresDevicePublicKeyRepository::find_by_id(const domain::Uuid& key_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = find_by_id(key_id, tx);
    tx.commit();
    return res;
}

std::optional<domain::DevicePublicKeyEntity> PostgresDevicePublicKeyRepository::find_by_id(const domain::Uuid& key_id,
                                                                                           pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kFindPublicKeyByIdSql, pqxx::params{key_id.to_string()});
        if (res.empty()) {
            return std::nullopt;
        }
        return domain::device_public_key_from_row(pqxx::row(res[0]));
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to find public key by id: " + std::string(ex.what()));
    }
}

std::vector<domain::DevicePublicKeyEntity>
PostgresDevicePublicKeyRepository::list_active_keys_by_device_id(const domain::Uuid& device_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = list_active_keys_by_device_id(device_id, tx);
    tx.commit();
    return res;
}

std::vector<domain::DevicePublicKeyEntity>
PostgresDevicePublicKeyRepository::list_active_keys_by_device_id(const domain::Uuid& device_id,
                                                                 pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kListActiveKeysByDeviceSql, pqxx::params{device_id.to_string()});
        std::vector<domain::DevicePublicKeyEntity> keys;
        keys.reserve(static_cast<std::size_t>(res.size()));
        for (const auto& row : res) {
            keys.push_back(domain::device_public_key_from_row(pqxx::row(row)));
        }
        return keys;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to list active device public keys: " + std::string(ex.what()));
    }
}

void PostgresDevicePublicKeyRepository::replace_key(const domain::Uuid& old_key_id,
                                                    const domain::DevicePublicKeyEntity& new_key) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    replace_key(old_key_id, new_key, tx);
    tx.commit();
}

void PostgresDevicePublicKeyRepository::replace_key(const domain::Uuid& old_key_id,
                                                    const domain::DevicePublicKeyEntity& new_key,
                                                    pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kFindPublicKeyByIdForUpdateSql, pqxx::params{old_key_id.to_string()});
        if (res.empty()) {
            throw EntityNotFoundException("Device public key not found: " + old_key_id.to_string());
        }

        domain::DevicePublicKeyEntity old_key = domain::device_public_key_from_row(pqxx::row(res[0]));
        if (old_key.key_status != domain::KeyStatus::Active) {
            throw InvalidEntityStateException("Cannot replace non-active public key (" +
                                              std::string(domain::to_string(old_key.key_status)) +
                                              "): " + old_key_id.to_string());
        }

        // 1. Insert new key
        store_public_key(new_key, tx);

        // 2. Mark old key as replaced
        auto update_res =
            db::exec_sql(tx, kUpdateKeyReplacedSql, pqxx::params{new_key.key_id.to_string(), old_key_id.to_string()});

        if (update_res.affected_rows() == 0) {
            throw OptimisticLockException("Concurrent key replacement conflict detected for key: " +
                                          old_key_id.to_string());
        }
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to replace device public key: " + std::string(ex.what()));
    }
}

void PostgresDevicePublicKeyRepository::revoke_all_device_keys(const domain::Uuid& device_id,
                                                               domain::time_point revoked_at) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    revoke_all_device_keys(device_id, revoked_at, tx);
    tx.commit();
}

void PostgresDevicePublicKeyRepository::revoke_all_device_keys(const domain::Uuid& device_id,
                                                               domain::time_point revoked_at,
                                                               pqxx::transaction_base& tx) {
    try {
        db::exec_sql(tx, kRevokeAllDeviceKeysSql, pqxx::params{domain::to_iso8601(revoked_at), device_id.to_string()});
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to revoke all device keys: " + std::string(ex.what()));
    }
}

std::optional<domain::DevicePublicKeyEntity>
PostgresDevicePublicKeyRepository::claim_one_time_prekey(const domain::Uuid& device_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = claim_one_time_prekey(device_id, tx);
    tx.commit();
    return res;
}

std::optional<domain::DevicePublicKeyEntity>
PostgresDevicePublicKeyRepository::claim_one_time_prekey(const domain::Uuid& device_id, pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kClaimOneTimePrekeySql, pqxx::params{device_id.to_string()});
        if (res.empty()) {
            return std::nullopt;
        }

        auto entity = domain::device_public_key_from_row(pqxx::row(res[0]));
        db::exec_sql(tx, kMarkPrekeyClaimedSql, pqxx::params{entity.key_id.to_string()});
        entity.key_status = domain::KeyStatus::Claimed;
        return entity;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to claim one-time prekey: " + std::string(ex.what()));
    }
}

int32_t PostgresDevicePublicKeyRepository::count_active_one_time_prekeys(const domain::Uuid& device_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto count = count_active_one_time_prekeys(device_id, tx);
    tx.commit();
    return count;
}

int32_t PostgresDevicePublicKeyRepository::count_active_one_time_prekeys(const domain::Uuid& device_id,
                                                                         pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kCountActiveOneTimePrekeysSql, pqxx::params{device_id.to_string()});
        if (res.empty() || res[0][0].is_null()) {
            return 0;
        }
        return res[0][0].as<int32_t>();
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to count active one-time prekeys: " + std::string(ex.what()));
    }
}

std::optional<domain::DevicePublicKeyEntity>
PostgresDevicePublicKeyRepository::find_active_identity_key(const domain::Uuid& device_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = find_active_identity_key(device_id, tx);
    tx.commit();
    return res;
}

std::optional<domain::DevicePublicKeyEntity>
PostgresDevicePublicKeyRepository::find_active_identity_key(const domain::Uuid& device_id, pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kFindActiveIdentityKeySql, pqxx::params{device_id.to_string()});
        if (res.empty()) {
            return std::nullopt;
        }
        return domain::device_public_key_from_row(pqxx::row(res[0]));
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to find active identity key: " + std::string(ex.what()));
    }
}

std::optional<domain::DevicePublicKeyEntity>
PostgresDevicePublicKeyRepository::find_active_signed_prekey(const domain::Uuid& device_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = find_active_signed_prekey(device_id, tx);
    tx.commit();
    return res;
}

std::optional<domain::DevicePublicKeyEntity>
PostgresDevicePublicKeyRepository::find_active_signed_prekey(const domain::Uuid& device_id,
                                                             pqxx::transaction_base& tx) {
    try {
        auto res = db::exec_sql(tx, kFindActiveSignedPrekeySql, pqxx::params{device_id.to_string()});
        if (res.empty()) {
            return std::nullopt;
        }
        return domain::device_public_key_from_row(pqxx::row(res[0]));
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to find active signed prekey: " + std::string(ex.what()));
    }
}

void PostgresDevicePublicKeyRepository::store_one_time_prekeys(const domain::Uuid& device_id,
                                                               const std::vector<std::vector<uint8_t>>& keys) {
    if (keys.empty()) {
        return;
    }
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    store_one_time_prekeys(device_id, keys, tx);
    tx.commit();
}

void PostgresDevicePublicKeyRepository::store_one_time_prekeys(const domain::Uuid& device_id,
                                                               const std::vector<std::vector<uint8_t>>& keys,
                                                               pqxx::transaction_base& tx) {
    if (keys.empty()) {
        return;
    }
    const auto now = std::chrono::system_clock::now();
    for (const auto& key : keys) {
        domain::DevicePublicKeyEntity otk{
            .key_id = domain::Uuid::generate_v7(),
            .device_id = device_id,
            .key_type = domain::KeyType::OneTimePrekey,
            .public_key = key,
            .key_status = domain::KeyStatus::Active,
            .created_at = now,
            .revoked_at = std::nullopt,
            .replaced_by_key_id = std::nullopt,
            .signature = std::nullopt,
        };
        store_public_key(otk, tx);
    }
}

} // namespace securecloud::auth::repository
