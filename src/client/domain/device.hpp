#pragma once

#include "domain/crypto_identity.hpp"
#include "domain/device_id.hpp"
#include "domain/device_platform_info.hpp"
#include "domain/device_trust_level.hpp"
#include "domain/hardware_attestation_record.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <optional>
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
           std::chrono::system_clock::time_point last_seen_at = std::chrono::system_clock::now(),
           DeviceTrustLevel trust_level = DeviceTrustLevel::Untrusted, DevicePlatformInfo platform_info = {},
           bool is_hardware_backed = false,
           std::optional<HardwareAttestationRecord> hardware_attestation = std::nullopt);

    [[nodiscard]] const DeviceId& device_id() const noexcept { return device_id_; }
    [[nodiscard]] const UserId& user_id() const noexcept { return user_id_; }
    [[nodiscard]] const std::string& display_name() const noexcept { return display_name_; }
    [[nodiscard]] const CryptoIdentity& crypto_identity() const noexcept { return crypto_identity_; }
    [[nodiscard]] DeviceAuthorizationStatus status() const noexcept { return status_; }
    [[nodiscard]] std::chrono::system_clock::time_point last_seen_at() const noexcept { return last_seen_at_; }
    [[nodiscard]] DeviceTrustLevel trust_level() const noexcept { return trust_level_; }
    [[nodiscard]] const DevicePlatformInfo& platform_info() const noexcept { return platform_info_; }
    [[nodiscard]] bool is_hardware_backed() const noexcept { return is_hardware_backed_; }
    [[nodiscard]] const std::optional<HardwareAttestationRecord>& hardware_attestation() const noexcept {
        return hardware_attestation_;
    }

    void set_status(DeviceAuthorizationStatus status) noexcept { status_ = status; }
    void set_last_seen_at(std::chrono::system_clock::time_point tp) noexcept { last_seen_at_ = tp; }
    void set_trust_level(DeviceTrustLevel level) noexcept { trust_level_ = level; }
    void set_platform_info(DevicePlatformInfo info) { platform_info_ = std::move(info); }
    void set_hardware_backed(bool backed) noexcept { is_hardware_backed_ = backed; }
    void set_hardware_attestation(std::optional<HardwareAttestationRecord> attestation) {
        hardware_attestation_ = std::move(attestation);
    }

    bool operator==(const Device& other) const noexcept;
    bool operator!=(const Device& other) const noexcept { return !(*this == other); }

  private:
    DeviceId device_id_;
    UserId user_id_;
    std::string display_name_;
    CryptoIdentity crypto_identity_;
    DeviceAuthorizationStatus status_{DeviceAuthorizationStatus::Authorized};
    std::chrono::system_clock::time_point last_seen_at_{std::chrono::system_clock::now()};
    DeviceTrustLevel trust_level_{DeviceTrustLevel::Untrusted};
    DevicePlatformInfo platform_info_{};
    bool is_hardware_backed_{false};
    std::optional<HardwareAttestationRecord> hardware_attestation_{std::nullopt};
};

} // namespace securecloud::client::domain
