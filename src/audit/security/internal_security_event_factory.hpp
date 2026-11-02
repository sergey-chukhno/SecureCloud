#pragma once

#include "domain/audit_event.hpp"
#include "security/internal_security_event_types.hpp"

#include <optional>
#include <string>
#include <unordered_map>

namespace securecloud::audit::security {

    /// Runtime context captured during an internal security event trigger.
    struct SecurityEventContext {
        std::optional<std::string> verified_peer_identity; // Extracted from mTLS SAN (e.g. "gateway.securecloud.internal")
        std::string peer_socket_address;                   // IP:port extracted from gRPC peer context
        std::string rpc_method;                            // Invoked RPC method (e.g. "SubmitAuditEvent")
        std::optional<std::string> correlation_id;         // Extracted from gRPC header context
        std::unordered_map<std::string, std::string> metadata;
    };

    /// Authoritative factory creating validated domain::AuditEvent instances for internal security events.
    class InternalSecurityEventFactory {
    public:
        explicit InternalSecurityEventFactory(std::string producer_instance = "securecloud-audit")
            : producer_instance_(std::move(producer_instance)) {}

        /// Constructs a fully populated, sanitized domain::AuditEvent with strict context attribution.
        [[nodiscard]] domain::AuditEvent create_event(
            InternalSecurityEventType type,
            const SecurityEventContext& ctx) const;

    private:
        std::string producer_instance_;
    };

} // namespace securecloud::audit::security
