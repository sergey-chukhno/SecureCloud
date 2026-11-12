#include "infrastructure/adapters/simulated_hardware_authenticator.hpp"

namespace securecloud::client::infrastructure::adapters {

application::ClientResult<std::string>
SimulatedHardwareAuthenticator::prompt_for_hardware_mfa(std::string_view challenge) {
    if (!hardware_available_) {
        return application::ClientResult<std::string>::error(
            application::ClientError::authentication("No hardware authenticator available on this system"));
    }

    if (!touch_approved_) {
        return application::ClientResult<std::string>::error(
            application::ClientError::authentication("Hardware touch prompt was cancelled or rejected by user"));
    }

    std::string token = "fido2_hardware_token_approved";
    if (!challenge.empty()) {
        token += ":" + std::string(challenge);
    }
    return application::ClientResult<std::string>::ok(std::move(token));
}

application::ClientResult<domain::HardwareAttestationRecord>
SimulatedHardwareAuthenticator::attest_device_authenticator() {
    if (!hardware_available_) {
        return application::ClientResult<domain::HardwareAttestationRecord>::error(
            application::ClientError::authentication("Hardware attestation unavailable: no security enclave detected"));
    }

    if (simulated_record_.has_value()) {
        return application::ClientResult<domain::HardwareAttestationRecord>::ok(*simulated_record_);
    }

    domain::HardwareAttestationRecord default_record(
        domain::AuthenticatorType::Platform, "00112233-4455-6677-8899-aabbccddeeff", "packed",
        "3045022100a1b2c3d4e5f60718293a4b5c6d7e8f00112233445566778899aabbccddeeff0220112233445566778899aabbccddeeff0011"
        "2233445566778899aabbccddeeff00",
        std::chrono::system_clock::now(), true);

    return application::ClientResult<domain::HardwareAttestationRecord>::ok(std::move(default_record));
}

bool SimulatedHardwareAuthenticator::is_hardware_authenticator_available() const noexcept {
    return hardware_available_;
}

} // namespace securecloud::client::infrastructure::adapters
