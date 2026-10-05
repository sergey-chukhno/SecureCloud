#include "auth/repository/device_repository.hpp"

#include "auth/domain/mappers.hpp"
#include "auth/domain/timestamp.hpp"

#include <chrono>

namespace securecloud::auth::repository {

namespace {

constexpr std::string_view kInsertDeviceSql = "INSERT INTO devices ("
                                              "    device_id, user_id, device_status, registered_at,"
                                              "    revoked_at, revocation_reason, last_authenticated_at,"
                                              "    created_at, updated_at"
                                              ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);";

constexpr std::string_view kFindDeviceByIdSql = "SELECT device_id, user_id, device_status, registered_at,"
                                                "       revoked_at, revocation_reason, last_authenticated_at,"
                                                "       created_at, updated_at "
                                                "FROM devices WHERE device_id = $1;";

constexpr std::string_view kListActiveDevicesByUserSql = "SELECT device_id, user_id, device_status, registered_at,"
                                                         "       revoked_at, revocation_reason, last_authenticated_at,"
                                                         "       created_at, updated_at "
                                                         "FROM devices "
                                                         "WHERE user_id = $1 AND device_status = 'Active' "
                                                         "ORDER BY created_at ASC;";

constexpr std::string_view kRevokeDeviceSql =
    "UPDATE devices "
    "SET device_status = 'Revoked', revocation_reason = $1, revoked_at = $2, updated_at = $3 "
    "WHERE device_id = $4;";

constexpr std::string_view kUpdateLastAuthSql = "UPDATE devices "
                                                "SET last_authenticated_at = $1, updated_at = $2 "
                                                "WHERE device_id = $3 AND device_status != 'Revoked';";

constexpr std::string_view kGetDeviceStatusSql = "SELECT device_status FROM devices WHERE device_id = $1;";

} // namespace

PostgresDeviceRepository::PostgresDeviceRepository(db::PostgresConnectionPool& pool) : pool_(pool) {}

void PostgresDeviceRepository::register_device(const domain::DeviceEntity& device) {
    if (device.device_status == domain::DeviceStatus::Revoked) {
        throw InvalidEntityStateException("Cannot register a device with Revoked status: " +
                                          device.device_id.to_string());
    }
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    register_device(device, tx);
    tx.commit();
}

void PostgresDeviceRepository::register_device(const domain::DeviceEntity& device, pqxx::transaction_base& tx) {
    if (device.device_status == domain::DeviceStatus::Revoked) {
        throw InvalidEntityStateException("Cannot register a device with Revoked status: " +
                                          device.device_id.to_string());
    }

    try {
        const std::optional<std::string> revoked_at_str =
            device.revoked_at.has_value() ? std::optional<std::string>{domain::to_iso8601(*device.revoked_at)}
                                          : std::nullopt;

        tx.exec(kInsertDeviceSql,
                pqxx::params{device.device_id.to_string(), device.user_id.to_string(),
                             domain::to_string(device.device_status), domain::to_iso8601(device.registered_at),
                             revoked_at_str, device.revocation_reason, domain::to_iso8601(device.last_authenticated_at),
                             domain::to_iso8601(device.created_at), domain::to_iso8601(device.updated_at)});
    } catch (const pqxx::unique_violation& ex) {
        throw DuplicateEntityException("Device already registered: " + device.device_id.to_string());
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to register device: " + std::string(ex.what()));
    }
}

std::optional<domain::DeviceEntity> PostgresDeviceRepository::find_by_id(const domain::Uuid& device_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = find_by_id(device_id, tx);
    tx.commit();
    return res;
}

std::optional<domain::DeviceEntity> PostgresDeviceRepository::find_by_id(const domain::Uuid& device_id,
                                                                         pqxx::transaction_base& tx) {
    try {
        auto res = tx.exec(kFindDeviceByIdSql, pqxx::params{device_id.to_string()});
        if (res.empty()) {
            return std::nullopt;
        }
        return domain::device_from_row(pqxx::row(res[0]));
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to find device by id: " + std::string(ex.what()));
    }
}

std::vector<domain::DeviceEntity> PostgresDeviceRepository::list_active_by_user_id(const domain::Uuid& user_id) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    auto res = list_active_by_user_id(user_id, tx);
    tx.commit();
    return res;
}

std::vector<domain::DeviceEntity> PostgresDeviceRepository::list_active_by_user_id(const domain::Uuid& user_id,
                                                                                   pqxx::transaction_base& tx) {
    try {
        auto res = tx.exec(kListActiveDevicesByUserSql, pqxx::params{user_id.to_string()});
        std::vector<domain::DeviceEntity> devices;
        devices.reserve(static_cast<std::size_t>(res.size()));
        for (const auto& row : res) {
            devices.push_back(domain::device_from_row(pqxx::row(row)));
        }
        return devices;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to list active devices for user: " + std::string(ex.what()));
    }
}

void PostgresDeviceRepository::revoke_device(const domain::Uuid& device_id, std::string_view reason,
                                             domain::time_point revoked_at) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    revoke_device(device_id, reason, revoked_at, tx);
    tx.commit();
}

void PostgresDeviceRepository::revoke_device(const domain::Uuid& device_id, std::string_view reason,
                                             domain::time_point revoked_at, pqxx::transaction_base& tx) {
    try {
        const auto now = std::chrono::system_clock::now();
        auto res = tx.exec(kRevokeDeviceSql, pqxx::params{std::string(reason), domain::to_iso8601(revoked_at),
                                                          domain::to_iso8601(now), device_id.to_string()});

        if (res.affected_rows() == 0) {
            throw EntityNotFoundException("Device not found: " + device_id.to_string());
        }
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to revoke device: " + std::string(ex.what()));
    }
}

void PostgresDeviceRepository::update_last_authenticated(const domain::Uuid& device_id, domain::time_point auth_time) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    update_last_authenticated(device_id, auth_time, tx);
    tx.commit();
}

void PostgresDeviceRepository::update_last_authenticated(const domain::Uuid& device_id, domain::time_point auth_time,
                                                         pqxx::transaction_base& tx) {
    try {
        const auto now = std::chrono::system_clock::now();
        auto res = tx.exec(kUpdateLastAuthSql,
                           pqxx::params{domain::to_iso8601(auth_time), domain::to_iso8601(now), device_id.to_string()});

        if (res.affected_rows() == 0) {
            auto check = tx.exec(kGetDeviceStatusSql, pqxx::params{device_id.to_string()});
            if (check.empty()) {
                throw EntityNotFoundException("Device not found: " + device_id.to_string());
            }
            throw InvalidEntityStateException("Cannot update authentication on a revoked device: " +
                                              device_id.to_string());
        }
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to update last authenticated time: " + std::string(ex.what()));
    }
}

} // namespace securecloud::auth::repository
