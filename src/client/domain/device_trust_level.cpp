#include "domain/device_trust_level.hpp"

namespace securecloud::client::domain {

std::string_view to_string(DeviceTrustLevel level) noexcept {
    switch (level) {
    case DeviceTrustLevel::Untrusted:
        return "Untrusted";
    case DeviceTrustLevel::PendingVerification:
        return "PendingVerification";
    case DeviceTrustLevel::VerifiedOutOfBand:
        return "VerifiedOutOfBand";
    case DeviceTrustLevel::HardwareAttested:
        return "HardwareAttested";
    case DeviceTrustLevel::EnterpriseAttested:
        return "EnterpriseAttested";
    case DeviceTrustLevel::Revoked:
        return "Revoked";
    }
    return "Unknown";
}

std::optional<DeviceTrustLevel> parse_device_trust_level(std::string_view str) noexcept {
    if (str == "Untrusted") {
        return DeviceTrustLevel::Untrusted;
    }
    if (str == "PendingVerification" || str == "Pending") {
        return DeviceTrustLevel::PendingVerification;
    }
    if (str == "VerifiedOutOfBand" || str == "Verified") {
        return DeviceTrustLevel::VerifiedOutOfBand;
    }
    if (str == "HardwareAttested" || str == "Attested") {
        return DeviceTrustLevel::HardwareAttested;
    }
    if (str == "EnterpriseAttested" || str == "Enterprise") {
        return DeviceTrustLevel::EnterpriseAttested;
    }
    if (str == "Revoked") {
        return DeviceTrustLevel::Revoked;
    }
    return std::nullopt;
}

} // namespace securecloud::client::domain
