#pragma once

#include "files/db/files_connection_pool.hpp"

#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_set>

namespace securecloud::files {

/**
 * @brief Abstract interface contract for checking device revocation status.
 */
class IDeviceRevocationProvider {
  public:
    virtual ~IDeviceRevocationProvider() = default;

    /// Checks whether the given device_id is marked as revoked.
    [[nodiscard]] virtual bool is_device_revoked(const std::string& device_id) = 0;

    /// Marks a device as revoked.
    virtual void mark_device_revoked(const std::string& device_id) = 0;

    /// Clears any cached or simulated revocation state.
    virtual void clear_revocation(const std::string& device_id) = 0;
};

/**
 * @brief Thread-safe PostgreSQL and cached implementation of IDeviceRevocationProvider.
 */
class DeviceRevocationProvider : public IDeviceRevocationProvider {
  public:
    explicit DeviceRevocationProvider(std::shared_ptr<db::FilesDbConnectionPool> pool = nullptr);

    [[nodiscard]] bool is_device_revoked(const std::string& device_id) override;

    void mark_device_revoked(const std::string& device_id) override;

    void clear_revocation(const std::string& device_id) override;

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
    mutable std::shared_mutex mutex_;
    std::unordered_set<std::string> revoked_devices_;
};

} // namespace securecloud::files
