#pragma once

#include "enums.hpp"
#include "validation_result.hpp"

#include <string>
#include <vector>

namespace securecloud::audit::domain {

struct PeerIdentity {
    std::string common_name;
    std::vector<std::string> san_dns_names;
    std::vector<std::string> san_uri_names;
    bool is_authenticated{false};
};

class ProducerIdentityValidator {
  public:
    /// Returns whether any authenticated CN, DNS SAN, or URI SAN matches a service's short name or FQDN.
    [[nodiscard]] static bool matches_peer_identity(ProducerService producer,
                                                    const PeerIdentity& peer_identity) noexcept;

    /// Validates whether an authenticated mTLS peer identity matches the declared ProducerService.
    [[nodiscard]] static AuditValidationResult
    validate_producer_authorization(ProducerService declared_producer, const PeerIdentity& peer_identity) noexcept;
};

} // namespace securecloud::audit::domain
