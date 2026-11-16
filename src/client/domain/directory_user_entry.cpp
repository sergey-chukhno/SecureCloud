#include "domain/directory_user_entry.hpp"

#include <utility>

namespace securecloud::client::domain {

DirectoryUserEntry::DirectoryUserEntry(UserId user_id, std::string handle, std::string display_name,
                                       std::vector<uint8_t> identity_public_key, std::string identity_fingerprint,
                                       uint32_t active_device_count, std::chrono::system_clock::time_point created_at)
    : user_id_(std::move(user_id)), handle_(std::move(handle)), display_name_(std::move(display_name)),
      identity_public_key_(std::move(identity_public_key)), identity_fingerprint_(std::move(identity_fingerprint)),
      active_device_count_(active_device_count), created_at_(created_at) {}

bool DirectoryUserEntry::operator==(const DirectoryUserEntry& other) const noexcept {
    return user_id_ == other.user_id_ && handle_ == other.handle_ && display_name_ == other.display_name_ &&
           identity_public_key_ == other.identity_public_key_ && identity_fingerprint_ == other.identity_fingerprint_ &&
           active_device_count_ == other.active_device_count_;
}

} // namespace securecloud::client::domain
