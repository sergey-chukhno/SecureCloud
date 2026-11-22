#include "files/repository/device_revocation_provider.hpp"

#include "files/db/pqxx_compat.hpp"

#include <mutex>
#include <stdexcept>

namespace securecloud::files {

DeviceRevocationProvider::DeviceRevocationProvider(std::shared_ptr<db::FilesDbConnectionPool> pool)
    : pool_(std::move(pool)) {}

bool DeviceRevocationProvider::is_device_revoked(const std::string& device_id) {
    if (device_id.empty()) {
        return false;
    }

    // 1. Check local fast-path in-memory set under read lock
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        if (revoked_devices_.contains(device_id)) {
            return true;
        }
    }

    // 2. Query database if connection pool is available
    if (pool_) {
        try {
            auto lease = pool_->acquire();

            auto* pg_conn = dynamic_cast<db::DefaultDbConnection*>(lease.get());
            if (!pg_conn) {
                throw std::runtime_error("Database connection is not a PostgreSQL connection");
            }

            pqxx::work tx(pg_conn->native_handle());

            auto res =
                tx.exec("SELECT 1 FROM file_access WHERE grantee_device_id = $1 AND revoked_at IS NOT NULL LIMIT 1",
                        pqxx::params{device_id});

            if (!res.empty()) {
                // Cache the revocation status
                std::unique_lock<std::shared_mutex> lock(mutex_);
                revoked_devices_.insert(device_id);
                return true;
            }
        } catch (...) {
            // Degrade gracefully to cache if DB table is uninitialized or transient error
        }
    }

    return false;
}

void DeviceRevocationProvider::mark_device_revoked(const std::string& device_id) {
    if (device_id.empty()) {
        return;
    }

    std::unique_lock<std::shared_mutex> lock(mutex_);
    revoked_devices_.insert(device_id);
}

void DeviceRevocationProvider::clear_revocation(const std::string& device_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    revoked_devices_.erase(device_id);
}

} // namespace securecloud::files
