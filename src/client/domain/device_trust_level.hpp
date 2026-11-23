#pragma once

#include <optional>
#include <string_view>

namespace securecloud::client::domain {

enum class DeviceTrustLevel {
    Untrusted,
    PendingVerification,
    VerifiedOutOfBand,
    HardwareAttested,
    EnterpriseAttested,
    Revoked
};

[[nodiscard]] std::string_view to_string(DeviceTrustLevel level) noexcept;
[[nodiscard]] std::optional<DeviceTrustLevel> parse_device_trust_level(std::string_view str) noexcept;

} // namespace securecloud::client::domain
