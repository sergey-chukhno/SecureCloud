#pragma once

#include <chrono>
#include <string>
#include <string_view>

namespace securecloud::client::domain {

enum class AuthenticatorType { Platform, CrossPlatformSecurityKey };

[[nodiscard]] std::string_view to_string(AuthenticatorType type) noexcept;

class HardwareAttestationRecord {
  public:
    HardwareAttestationRecord() = default;

    HardwareAttestationRecord(AuthenticatorType authenticator_type, std::string aaguid,
                              std::string attestation_format = "packed", std::string attestation_statement_hex = "",
                              std::chrono::system_clock::time_point attested_at = std::chrono::system_clock::now(),
                              bool is_verified = true);

    [[nodiscard]] AuthenticatorType authenticator_type() const noexcept { return authenticator_type_; }
    [[nodiscard]] const std::string& aaguid() const noexcept { return aaguid_; }
    [[nodiscard]] const std::string& attestation_format() const noexcept { return attestation_format_; }
    [[nodiscard]] const std::string& attestation_statement_hex() const noexcept { return attestation_statement_hex_; }
    [[nodiscard]] std::chrono::system_clock::time_point attested_at() const noexcept { return attested_at_; }
    [[nodiscard]] bool is_verified() const noexcept { return is_verified_; }

    void set_authenticator_type(AuthenticatorType type) noexcept { authenticator_type_ = type; }
    void set_aaguid(std::string aaguid) { aaguid_ = std::move(aaguid); }
    void set_attestation_format(std::string format) { attestation_format_ = std::move(format); }
    void set_attestation_statement_hex(std::string stmt) { attestation_statement_hex_ = std::move(stmt); }
    void set_attested_at(std::chrono::system_clock::time_point tp) noexcept { attested_at_ = tp; }
    void set_verified(bool verified) noexcept { is_verified_ = verified; }

    bool operator==(const HardwareAttestationRecord& other) const noexcept;
    bool operator!=(const HardwareAttestationRecord& other) const noexcept { return !(*this == other); }

  private:
    AuthenticatorType authenticator_type_{AuthenticatorType::Platform};
    std::string aaguid_{"00000000-0000-0000-0000-000000000000"};
    std::string attestation_format_{"packed"};
    std::string attestation_statement_hex_{""};
    std::chrono::system_clock::time_point attested_at_{std::chrono::system_clock::now()};
    bool is_verified_{true};
};

} // namespace securecloud::client::domain
