#pragma once

#include "application/client_error.hpp"
#include "domain/hardware_attestation_record.hpp"

#include <string>
#include <string_view>

namespace securecloud::client::application::interfaces {

class IHardwareAuthenticator {
  public:
    virtual ~IHardwareAuthenticator() = default;

    /// Prompts user for platform biometric / security key touch gesture and generates MFA token
    virtual ClientResult<std::string> prompt_for_hardware_mfa(std::string_view challenge = "") = 0;

    /// Attests the current device platform authenticator (e.g. Touch ID / TPM 2.0 / YubiKey)
    virtual ClientResult<domain::HardwareAttestationRecord> attest_device_authenticator() = 0;

    /// Returns whether a hardware-backed authenticator is available on the current platform
    [[nodiscard]] virtual bool is_hardware_authenticator_available() const noexcept = 0;
};

} // namespace securecloud::client::application::interfaces

