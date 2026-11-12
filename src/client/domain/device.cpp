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
               DeviceAuthorizationStatus status, std::chrono::system_clock::time_point last_seen_at,
               DeviceTrustLevel trust_level, DevicePlatformInfo platform_info, bool is_hardware_backed,
               std::optional<HardwareAttestationRecord> hardware_attestation)
    : device_id_(std::move(device_id)), user_id_(std::move(user_id)), display_name_(std::move(display_name)),
      crypto_identity_(std::move(crypto_identity)), status_(status), last_seen_at_(last_seen_at),
      trust_level_(trust_level), platform_info_(std::move(platform_info)), is_hardware_backed_(is_hardware_backed),
      hardware_attestation_(std::move(hardware_attestation)) {}

bool Device::operator==(const Device& other) const noexcept {
    return device_id_ == other.device_id_ && user_id_ == other.user_id_ && display_name_ == other.display_name_ &&
           crypto_identity_ == other.crypto_identity_ && status_ == other.status_ &&
           trust_level_ == other.trust_level_ && platform_info_ == other.platform_info_ &&
           is_hardware_backed_ == other.is_hardware_backed_ && hardware_attestation_ == other.hardware_attestation_;
}

} // namespace securecloud::client::domain
