#pragma once

#include <string>
#include <string_view>

namespace securecloud::client::domain {

class DevicePlatformInfo {
  public:
    DevicePlatformInfo() = default;

    DevicePlatformInfo(std::string os_name, std::string os_version, std::string hardware_architecture,
                       std::string device_model = "", bool secure_enclave_available = false,
                       bool hardware_key_enforced = false, std::string client_version = "1.0.0");

    [[nodiscard]] const std::string& os_name() const noexcept { return os_name_; }
    [[nodiscard]] const std::string& os_version() const noexcept { return os_version_; }
    [[nodiscard]] const std::string& hardware_architecture() const noexcept { return hardware_architecture_; }
    [[nodiscard]] const std::string& device_model() const noexcept { return device_model_; }
    [[nodiscard]] bool secure_enclave_available() const noexcept { return secure_enclave_available_; }
    [[nodiscard]] bool hardware_key_enforced() const noexcept { return hardware_key_enforced_; }
    [[nodiscard]] const std::string& client_version() const noexcept { return client_version_; }

    void set_os_name(std::string os_name) { os_name_ = std::move(os_name); }
    void set_os_version(std::string os_version) { os_version_ = std::move(os_version); }
    void set_hardware_architecture(std::string arch) { hardware_architecture_ = std::move(arch); }
    void set_device_model(std::string model) { device_model_ = std::move(model); }
    void set_secure_enclave_available(bool available) noexcept { secure_enclave_available_ = available; }
    void set_hardware_key_enforced(bool enforced) noexcept { hardware_key_enforced_ = enforced; }
    void set_client_version(std::string version) { client_version_ = std::move(version); }

    [[nodiscard]] std::string formatted_summary() const;

    bool operator==(const DevicePlatformInfo& other) const noexcept;
    bool operator!=(const DevicePlatformInfo& other) const noexcept { return !(*this == other); }

  private:
    std::string os_name_{"macOS"};
    std::string os_version_{"15.0"};
    std::string hardware_architecture_{"arm64"};
    std::string device_model_{""};
    bool secure_enclave_available_{false};
    bool hardware_key_enforced_{false};
    std::string client_version_{"1.0.0"};
};

} // namespace securecloud::client::domain
