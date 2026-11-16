#pragma once

#include "domain/audit_event.hpp"
#include "gateway_audit_event_types.hpp"
#include "gateway_audit_observation.hpp"
#include "gateway_audit_validator.hpp"
#include "securecloud/audit/v1/audit.pb.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace securecloud::gateway::audit {

/**
 * @brief Pure, I/O-free canonical AuditEvent construction and serialization factory.
 *
 * Enforces trusted attribution mapping, correlation-ID hardening, metadata whitelisting,
 * truncation, sensitive data filtering, and local validation.
 */
class GatewayAuditEventFactory {
  public:
    explicit GatewayAuditEventFactory(std::string producer_instance = "gateway-1");

    /// Creates a validated pure domain AuditEvent from an observation
    [[nodiscard]] securecloud::audit::domain::AuditEvent
    create_domain_event(const GatewayAuditObservation& observation) const;

    /// Converts a pure domain AuditEvent to the canonical Protobuf message
    [[nodiscard]] static ::securecloud::audit::v1::AuditEventProto
    to_protobuf(const securecloud::audit::domain::AuditEvent& domain_event);

    /// Serializes a Protobuf AuditEvent into deterministic canonical bytes
    [[nodiscard]] static std::vector<uint8_t>
    serialize_canonical_proto(const ::securecloud::audit::v1::AuditEventProto& proto_event);

    /// Hardens correlation ID: retains syntactically valid UUID or generates fresh UUIDv7
    [[nodiscard]] static std::string sanitize_correlation_id(const std::optional<std::string>& raw_id);

    [[nodiscard]] const GatewayAuditEventValidator& validator() const noexcept { return validator_; }

  private:
    [[nodiscard]] std::map<std::string, std::string>
    sanitize_metadata(GatewayAuditEventType type, const GatewayAuditObservation& observation) const;

    std::string producer_instance_;
    GatewayAuditEventValidator validator_;
};

} // namespace securecloud::gateway::audit
