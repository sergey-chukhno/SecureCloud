#pragma once

#include "domain/crypto_identity.hpp"
#include "domain/device_id.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <string>
#include <string_view>

namespace securecloud::client::domain {

enum class DeviceAuthorizationStatus { Authorized, Revoked, Pending };

[[nodiscard]] std::string_view to_string(DeviceAuthorizationStatus status) noexcept;

class Device {
  public:
    Device() = default;
    Device(DeviceId device_id, UserId user_id, std::string display_name, CryptoIdentity crypto_identity,
           DeviceAuthorizationStatus status = DeviceAuthorizationStatus::Authorized,
           std::chrono::system_clock::time_point last_seen_at = std::chrono::system_clock::now());

    [[nodiscard]] const DeviceId& device_id() const noexcept { return device_id_; }
    [[nodiscard]] const UserId& user_id() const noexcept { return user_id_; }
    [[nodiscard]] const std::string& display_name() const noexcept { return display_name_; }
    [[nodiscard]] const CryptoIdentity& crypto_identity() const noexcept { return crypto_identity_; }
    [[nodiscard]] DeviceAuthorizationStatus status() const noexcept { return status_; }
    [[nodiscard]] std::chrono::system_clock::time_point last_seen_at() const noexcept { return last_seen_at_; }

    void set_status(DeviceAuthorizationStatus status) noexcept { status_ = status; }
    void set_last_seen_at(std::chrono::system_clock::time_point tp) noexcept { last_seen_at_ = tp; }

    bool operator==(const Device& other) const noexcept;
    bool operator!=(const Device& other) const noexcept { return !(*this == other); }

  private:
    DeviceId device_id_;
    UserId user_id_;
    std::string display_name_;
    CryptoIdentity crypto_identity_;
    DeviceAuthorizationStatus status_{DeviceAuthorizationStatus::Authorized};
    std::chrono::system_clock::time_point last_seen_at_{std::chrono::system_clock::now()};
};

} // namespace securecloud::client::domain
