#include "domain/user.hpp"

#include <algorithm>
#include <utility>

namespace securecloud::client::domain {

User::User(UserId user_id, std::string display_name, std::vector<Device> devices,
           std::chrono::system_clock::time_point created_at)
    : user_id_(std::move(user_id)), display_name_(std::move(display_name)), devices_(std::move(devices)),
      created_at_(created_at) {}

void User::add_device(Device device) {
    auto it = std::find_if(devices_.begin(), devices_.end(),
                           [&device](const Device& d) { return d.device_id() == device.device_id(); });
    if (it != devices_.end()) {
        *it = std::move(device);
    } else {
        devices_.push_back(std::move(device));
    }
}

void User::remove_device(const DeviceId& device_id) {
    devices_.erase(std::remove_if(devices_.begin(), devices_.end(),
                                  [&device_id](const Device& d) { return d.device_id() == device_id; }),
                   devices_.end());
}

bool User::operator==(const User& other) const noexcept {
    return user_id_ == other.user_id_ && display_name_ == other.display_name_ && devices_ == other.devices_;
}

} // namespace securecloud::client::domain
