#include "domain/device.hpp"

#include <utility>

namespace securecloud::client::domain {

std::string_view to_string(DeviceAuthorizationStatus status) noexcept {
    switch (status) {
    case DeviceAuthorizationStatus::Authorized:
        return "Authorized";
    case DeviceAuthorizationStatus::Revoked:
        return "Revoked";
    case DeviceAuthorizationStatus::Pending:
        return "Pending";
    }
    return "Unknown";
}

Device::Device(DeviceId device_id, UserId user_id, std::string display_name, CryptoIdentity crypto_identity,
               DeviceAuthorizationStatus status, std::chrono::system_clock::time_point last_seen_at)
    : device_id_(std::move(device_id)), user_id_(std::move(user_id)), display_name_(std::move(display_name)),
      crypto_identity_(std::move(crypto_identity)), status_(status), last_seen_at_(last_seen_at) {}

bool Device::operator==(const Device& other) const noexcept {
    return device_id_ == other.device_id_ && user_id_ == other.user_id_ && display_name_ == other.display_name_ &&
           crypto_identity_ == other.crypto_identity_ && status_ == other.status_;
}

} // namespace securecloud::client::domain
