#pragma once

#include "domain/device.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <string>
#include <vector>

namespace securecloud::client::domain {

class User {
  public:
    User() = default;
    User(UserId user_id, std::string display_name = "", std::vector<Device> devices = {},
         std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now());

    [[nodiscard]] const UserId& user_id() const noexcept { return user_id_; }
    [[nodiscard]] const std::string& display_name() const noexcept { return display_name_; }
    [[nodiscard]] const std::vector<Device>& devices() const noexcept { return devices_; }
    [[nodiscard]] std::chrono::system_clock::time_point created_at() const noexcept { return created_at_; }

    void set_display_name(std::string name) { display_name_ = std::move(name); }
    void add_device(Device device);
    void remove_device(const DeviceId& device_id);

    bool operator==(const User& other) const noexcept;
    bool operator!=(const User& other) const noexcept { return !(*this == other); }

  private:
    UserId user_id_;
    std::string display_name_;
    std::vector<Device> devices_;
    std::chrono::system_clock::time_point created_at_{std::chrono::system_clock::now()};
};

} // namespace securecloud::client::domain
