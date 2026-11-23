#pragma once

#include "audit/audit_pending_store.hpp"
#include "audit/gateway_audit_observation.hpp"

#include <cstdint>
#include <memory>

namespace securecloud::gateway::audit {

class GatewayAuditEventFactory;

/**
 * @brief Public Gateway Audit Producer Façade.
 *
 * Exposes ONLY Gateway-owned observation types. Includes NO domain/... headers,
 * completely preventing ODR / include collisions with securecloud::auth.
 */
class IGatewayAuditProducer {
  public:
    virtual ~IGatewayAuditProducer() = default;

    /// Admits a perimeter observation for processing and spooling
    virtual AdmissionResult record_observation(const GatewayAuditObservation& observation) = 0;

    /// Synchronously flushes spooled events to upstream Audit Service
    virtual void flush() = 0;

    /// Returns true if spool capacity or network retry failures have degraded producer health
    [[nodiscard]] virtual bool is_degraded() const noexcept = 0;

    /// Total count of admitted events
    [[nodiscard]] virtual uint64_t enqueued_count() const noexcept = 0;

    /// Total count of dropped events due to spool capacity limits
    [[nodiscard]] virtual uint64_t dropped_count() const noexcept = 0;
};

std::shared_ptr<IGatewayAuditProducer> create_gateway_audit_producer(std::shared_ptr<IAuditPendingStore> store,
                                                                     std::shared_ptr<GatewayAuditEventFactory> factory,
                                                                     bool enabled = true,
                                                                     uint32_t aggregation_window_sec = 10,
                                                                     size_t aggregation_max_keys = 1000);

} // namespace securecloud::gateway::audit
