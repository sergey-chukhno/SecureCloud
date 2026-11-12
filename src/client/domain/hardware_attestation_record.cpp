#include "domain/hardware_attestation_record.hpp"

#include <utility>

namespace securecloud::client::domain {

std::string_view to_string(AuthenticatorType type) noexcept {
    switch (type) {
    case AuthenticatorType::Platform:
        return "Platform";
    case AuthenticatorType::CrossPlatformSecurityKey:
        return "CrossPlatformSecurityKey";
    }
    return "Unknown";
}

HardwareAttestationRecord::HardwareAttestationRecord(AuthenticatorType authenticator_type, std::string aaguid,
                                                     std::string attestation_format,
                                                     std::string attestation_statement_hex,
                                                     std::chrono::system_clock::time_point attested_at,
                                                     bool is_verified)
    : authenticator_type_(authenticator_type), aaguid_(std::move(aaguid)),
      attestation_format_(std::move(attestation_format)),
      attestation_statement_hex_(std::move(attestation_statement_hex)), attested_at_(attested_at),
      is_verified_(is_verified) {}

bool HardwareAttestationRecord::operator==(const HardwareAttestationRecord& other) const noexcept {
    return authenticator_type_ == other.authenticator_type_ && aaguid_ == other.aaguid_ &&
           attestation_format_ == other.attestation_format_ &&
           attestation_statement_hex_ == other.attestation_statement_hex_ && is_verified_ == other.is_verified_;
}

} // namespace securecloud::client::domain
