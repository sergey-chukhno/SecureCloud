#include "security/internal_security_event_factory.hpp"

#include "domain/event_id.hpp"
#include "domain/sensitive_data_guard.hpp"

#include <chrono>

namespace securecloud::audit::security {

domain::AuditEvent InternalSecurityEventFactory::create_event(InternalSecurityEventType type,
                                                              const SecurityEventContext& ctx) const {
    domain::AuditEvent event{};

    event.event_id = domain::EventId::generate_v7();
    event.occurred_at = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    event.received_at = event.occurred_at;
    event.event_type = std::string(to_event_type_string(type));
    event.severity = to_severity(type);
    event.producer_service = domain::ProducerService::Audit;
    event.producer_instance = producer_instance_.empty() ? "securecloud-audit" : producer_instance_;

    event.target_type = domain::TargetType::Service;
    event.target_id = "securecloud-audit";

    // Strict Context Attribution Policy (No Speculation & Domain Invariant Compliance)
    if (ctx.verified_peer_identity.has_value() && !ctx.verified_peer_identity->empty()) {
        event.actor_type = domain::ActorType::Service;
        event.actor_id = *ctx.verified_peer_identity;
    } else {
        event.actor_type = to_default_actor_type(type);
        if (event.actor_type == domain::ActorType::Unknown) {
            // Per AuditEventValidator invariants, Unknown actor_type requires an empty actor_id
            event.actor_id.clear();
        } else if (event.actor_type == domain::ActorType::System) {
            event.actor_id = producer_instance_.empty() ? "securecloud-audit" : producer_instance_;
        } else {
            event.actor_id = !ctx.peer_socket_address.empty() ? ctx.peer_socket_address : "unauthenticated";
        }
    }

    if (ctx.correlation_id.has_value() && !ctx.correlation_id->empty()) {
        event.correlation_id = *ctx.correlation_id;
    } else {
        event.correlation_id = event.event_id.to_string();
    }

    // Assemble and sanitize metadata
    std::unordered_map<std::string, std::string> raw_metadata;

    if (!ctx.rpc_method.empty()) {
        raw_metadata["rpc_method"] = ctx.rpc_method;
    }
    if (!ctx.peer_socket_address.empty() && event.actor_id != ctx.peer_socket_address) {
        raw_metadata["peer_address"] = ctx.peer_socket_address;
    }

    for (const auto& [k, v] : ctx.metadata) {
        if (raw_metadata.size() >= kMaxInternalMetadataPairs) {
            break;
        }
        if (validate_internal_metadata_key_value(k, v)) {
            raw_metadata[k] = v;
        }
    }

    event.metadata = raw_metadata;
    return event;
}

} // namespace securecloud::audit::security
