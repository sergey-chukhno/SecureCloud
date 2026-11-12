#pragma once

#include "application/interfaces/i_hardware_authenticator.hpp"

namespace securecloud::client::infrastructure::adapters {

class SimulatedHardwareAuthenticator final : public application::interfaces::IHardwareAuthenticator {
  public:
    SimulatedHardwareAuthenticator() = default;
    ~SimulatedHardwareAuthenticator() override = default;

    SimulatedHardwareAuthenticator(const SimulatedHardwareAuthenticator&) = delete;
    SimulatedHardwareAuthenticator& operator=(const SimulatedHardwareAuthenticator&) = delete;

    application::ClientResult<std::string> prompt_for_hardware_mfa(std::string_view challenge = "") override;

    application::ClientResult<domain::HardwareAttestationRecord> attest_device_authenticator() override;

    [[nodiscard]] bool is_hardware_authenticator_available() const noexcept override;

    // Test Hooks
    void set_touch_approved(bool approved) noexcept { touch_approved_ = approved; }
    void set_hardware_available(bool available) noexcept { hardware_available_ = available; }
    void set_simulated_attestation_record(domain::HardwareAttestationRecord record) {
        simulated_record_ = std::move(record);
    }

  private:
    bool touch_approved_{true};
    bool hardware_available_{true};
    std::optional<domain::HardwareAttestationRecord> simulated_record_;
};

} // namespace securecloud::client::infrastructure::adapters
