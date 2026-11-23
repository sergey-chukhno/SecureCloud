#include "gateway_audit_event_types.hpp"

namespace securecloud::gateway::audit {

std::string_view to_event_type_string(GatewayAuditEventType type) noexcept {
    switch (type) {
    case GatewayAuditEventType::TokenRejected:
        return "security.token.rejected";
    case GatewayAuditEventType::AuthorizationDenied:
        return "security.authorization.denied";
    case GatewayAuditEventType::IdentityHeaderStripped:
        return "gateway.security.identity_header_stripped";
    case GatewayAuditEventType::ChunkIntegrityRejected:
        return "gateway.file.chunk_integrity_rejected";
    case GatewayAuditEventType::RateLimitExceeded:
        return "gateway.rate_limit.exceeded";
    case GatewayAuditEventType::RequestRejected:
        return "gateway.request.rejected";
    case GatewayAuditEventType::CircuitOpened:
        return "gateway.dependency.circuit_opened";
    case GatewayAuditEventType::CircuitClosed:
        return "gateway.dependency.circuit_closed";
    case GatewayAuditEventType::LifecycleStarted:
        return "gateway.lifecycle.started";
    case GatewayAuditEventType::LifecycleDrainStarted:
        return "gateway.lifecycle.drain_started";
    case GatewayAuditEventType::LifecycleStopped:
        return "gateway.lifecycle.stopped";
    case GatewayAuditEventType::EventsLost:
        return "gateway.audit_producer.events_lost";
    }
    return "gateway.request.rejected";
}

AuditSeverity get_default_severity(GatewayAuditEventType type) noexcept {
    switch (type) {
    case GatewayAuditEventType::TokenRejected:
    case GatewayAuditEventType::AuthorizationDenied:
    case GatewayAuditEventType::IdentityHeaderStripped:
    case GatewayAuditEventType::ChunkIntegrityRejected:
        return AuditSeverity::Security;
    case GatewayAuditEventType::RateLimitExceeded:
    case GatewayAuditEventType::RequestRejected:
    case GatewayAuditEventType::CircuitOpened:
        return AuditSeverity::Warning;
    case GatewayAuditEventType::CircuitClosed:
    case GatewayAuditEventType::LifecycleStarted:
    case GatewayAuditEventType::LifecycleDrainStarted:
    case GatewayAuditEventType::LifecycleStopped:
        return AuditSeverity::Info;
    case GatewayAuditEventType::EventsLost:
        return AuditSeverity::Critical;
    }
    return AuditSeverity::Info;
}

AuditEventClass get_event_class(GatewayAuditEventType type) noexcept {
    switch (type) {
    case GatewayAuditEventType::CircuitOpened:
    case GatewayAuditEventType::CircuitClosed:
    case GatewayAuditEventType::LifecycleStarted:
    case GatewayAuditEventType::LifecycleDrainStarted:
    case GatewayAuditEventType::LifecycleStopped:
        return AuditEventClass::BestEffort;
    default:
        return AuditEventClass::Mandatory;
    }
}

} // namespace securecloud::gateway::audit
