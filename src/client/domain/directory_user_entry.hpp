#pragma once

#include "domain/user_id.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

class DirectoryUserEntry {
  public:
    DirectoryUserEntry() = default;
    DirectoryUserEntry(UserId user_id, std::string handle, std::string display_name,
                       std::vector<uint8_t> identity_public_key, std::string identity_fingerprint,
                       uint32_t active_device_count = 1,
                       std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now());

    [[nodiscard]] const UserId& user_id() const noexcept { return user_id_; }
    [[nodiscard]] const std::string& handle() const noexcept { return handle_; }
    [[nodiscard]] const std::string& display_name() const noexcept { return display_name_; }
    [[nodiscard]] const std::vector<uint8_t>& identity_public_key() const noexcept { return identity_public_key_; }
    [[nodiscard]] const std::string& identity_fingerprint() const noexcept { return identity_fingerprint_; }
    [[nodiscard]] uint32_t active_device_count() const noexcept { return active_device_count_; }
    [[nodiscard]] std::chrono::system_clock::time_point created_at() const noexcept { return created_at_; }

    void set_display_name(std::string name) { display_name_ = std::move(name); }
    void set_active_device_count(uint32_t count) noexcept { active_device_count_ = count; }

    bool operator==(const DirectoryUserEntry& other) const noexcept;
    bool operator!=(const DirectoryUserEntry& other) const noexcept { return !(*this == other); }

  private:
    UserId user_id_;
    std::string handle_;
    std::string display_name_;
    std::vector<uint8_t> identity_public_key_;
    std::string identity_fingerprint_;
    uint32_t active_device_count_{1};
    std::chrono::system_clock::time_point created_at_{std::chrono::system_clock::now()};
};

} // namespace securecloud::client::domain
