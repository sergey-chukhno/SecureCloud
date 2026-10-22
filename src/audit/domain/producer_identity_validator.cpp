#include "producer_identity_validator.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>

namespace securecloud::audit::domain {

namespace {

std::string to_lower_string(std::string_view sv) {
    std::string lower(sv);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lower;
}

bool matches_identity(std::string_view candidate, std::string_view expected_short,
                      std::string_view expected_fqdn) noexcept {
    if (candidate.empty()) {
        return false;
    }
    std::string lower_cand = to_lower_string(candidate);
    return lower_cand == expected_short || lower_cand == expected_fqdn;
}

bool is_peer_authorized(ProducerService producer, const PeerIdentity& peer) noexcept {
    std::string_view short_name;
    std::string_view fqdn;

    switch (producer) {
        case ProducerService::Gateway:
            short_name = "gateway";
            fqdn = "gateway.securecloud.internal";
            break;
        case ProducerService::Auth:
            short_name = "auth";
            fqdn = "auth.securecloud.internal";
            break;
        case ProducerService::Messaging:
            short_name = "messaging";
            fqdn = "messaging.securecloud.internal";
            break;
        case ProducerService::Files:
            short_name = "files";
            fqdn = "files.securecloud.internal";
            break;
        case ProducerService::Audit:
            short_name = "audit";
            fqdn = "audit.securecloud.internal";
            break;
    }

    if (matches_identity(peer.common_name, short_name, fqdn)) {
        return true;
    }

    for (const auto& dns_name : peer.san_dns_names) {
        if (matches_identity(dns_name, short_name, fqdn)) {
            return true;
        }
    }

    for (const auto& uri_name : peer.san_uri_names) {
        if (matches_identity(uri_name, short_name, fqdn)) {
            return true;
        }
    }

    return false;
}

} // namespace

AuditValidationResult ProducerIdentityValidator::validate_producer_authorization(
    ProducerService declared_producer, const PeerIdentity& peer_identity) noexcept {

    if (!peer_identity.is_authenticated) {
        return AuditValidationResult::failure({
            AuditValidationErrorCode::UnauthorizedProducer,
            "producer_service",
            "Unauthenticated peer attempting to produce audit events"
        });
    }

    if (!is_peer_authorized(declared_producer, peer_identity)) {
        return AuditValidationResult::failure({
            AuditValidationErrorCode::UnauthorizedProducer,
            "producer_service",
            "Declared producer service '" + std::string(to_string(declared_producer)) +
                "' does not match authenticated peer identity"
        });
    }

    return AuditValidationResult::ok();
}

} // namespace securecloud::audit::domain