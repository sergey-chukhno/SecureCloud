#include "domain/device_platform_info.hpp"

#include <sstream>
#include <utility>

namespace securecloud::client::domain {

DevicePlatformInfo::DevicePlatformInfo(std::string os_name, std::string os_version, std::string hardware_architecture,
                                       std::string device_model, bool secure_enclave_available,
                                       bool hardware_key_enforced, std::string client_version)
    : os_name_(std::move(os_name)), os_version_(std::move(os_version)),
      hardware_architecture_(std::move(hardware_architecture)), device_model_(std::move(device_model)),
      secure_enclave_available_(secure_enclave_available), hardware_key_enforced_(hardware_key_enforced),
      client_version_(std::move(client_version)) {}

std::string DevicePlatformInfo::formatted_summary() const {
    std::ostringstream oss;
    if (!device_model_.empty()) {
        oss << device_model_ << " · ";
    } else if (secure_enclave_available_) {
        oss << "Apple M-Series Secure Enclave · ";
    }

    if (!os_name_.empty()) {
        oss << os_name_;
        if (!os_version_.empty()) {
            oss << " " << os_version_;
        }
    } else {
        oss << "Native Client";
    }

    if (!hardware_architecture_.empty()) {
        oss << " · " << hardware_architecture_;
    }

    if (hardware_key_enforced_) {
        oss << " · FIDO2 Enforced";
    }

    return oss.str();
}

bool DevicePlatformInfo::operator==(const DevicePlatformInfo& other) const noexcept {
    return os_name_ == other.os_name_ && os_version_ == other.os_version_ &&
           hardware_architecture_ == other.hardware_architecture_ && device_model_ == other.device_model_ &&
           secure_enclave_available_ == other.secure_enclave_available_ &&
           hardware_key_enforced_ == other.hardware_key_enforced_ && client_version_ == other.client_version_;
}

} // namespace securecloud::client::domain
