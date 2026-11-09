#pragma once

#include <cstdint>
#include <string_view>

namespace securecloud::gateway::audit {

/// Closed classification of audit event durability classes.
enum class AuditEventClass : uint8_t {
    Mandatory, // Written to per-instance WAL spool with group-commit fsync (ADR-011)
    BestEffort // Bounded process-lifetime in-memory buffer
};

/// Closed classification of severity levels matching securecloud.audit.v1 proto.
enum class AuditSeverity : uint8_t { Info, Warning, Security, Critical };

/// Closed taxonomy of Gateway perimeter audit events (Catalog E1–E9).
enum class GatewayAuditEventType : uint8_t {
    TokenRejected,          // E1: security.token.rejected
    AuthorizationDenied,    // E2: security.authorization.denied
    IdentityHeaderStripped, // E3: gateway.security.identity_header_stripped
    ChunkIntegrityRejected, // E4: gateway.file.chunk_integrity_rejected
    RateLimitExceeded,      // E5: gateway.rate_limit.exceeded
    RequestRejected,        // E6: gateway.request.rejected
    CircuitOpened,          // E7a: gateway.dependency.circuit_opened
    CircuitClosed,          // E7b: gateway.dependency.circuit_closed
    LifecycleStarted,       // E8a: gateway.lifecycle.started
    LifecycleDrainStarted,  // E8b: gateway.lifecycle.drain_started
    LifecycleStopped,       // E8c: gateway.lifecycle.stopped
    EventsLost              // E9: gateway.audit_producer.events_lost
};

/// Helper functions returning canonical event taxonomy properties
[[nodiscard]] std::string_view to_event_type_string(GatewayAuditEventType type) noexcept;
[[nodiscard]] AuditSeverity get_default_severity(GatewayAuditEventType type) noexcept;
[[nodiscard]] AuditEventClass get_event_class(GatewayAuditEventType type) noexcept;

} // namespace securecloud::gateway::audit
