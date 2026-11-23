#pragma once

#include "gateway_audit_event_types.hpp"

#include <chrono>
#include <map>
#include <optional>
#include <string>

namespace securecloud::gateway::audit {

/**
 * @brief Structured observation emitted at Gateway perimeter decision points.
 *
 * Isolated from HTTP/Auth header dependencies to prevent include-path collisions.
 * Identity fields are populated exclusively from verified AuthenticatedContext.
 */
struct GatewayAuditObservation {
    GatewayAuditEventType type{GatewayAuditEventType::RequestRejected};
    std::optional<AuditSeverity> override_severity{std::nullopt};
    std::chrono::system_clock::time_point occurred_at{std::chrono::system_clock::now()};

    // Trusted attribution fields (populated strictly from AuthenticatedContext)
    std::optional<std::string> actor_id{std::nullopt};
    std::optional<std::string> device_id{std::nullopt};
    std::optional<std::string> session_id{std::nullopt};

    // Target attribution
    std::string target_type{"SERVICE"};
    std::string target_id{"gateway"};

    // Request & correlation context
    std::optional<std::string> client_request_id{std::nullopt};
    std::string client_ip{"127.0.0.1"};
    std::string route_class{"unknown"};
    std::string http_method{"GET"};

    // Bounded metadata whitelist
    std::map<std::string, std::string> metadata;
};

} // namespace securecloud::gateway::audit
