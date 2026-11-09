#pragma once

#include "gateway_audit_observation.hpp"

#include <cstdint>
#include <memory>

namespace securecloud::gateway::audit {

/// Tri-state admission result returned by producer admission calls.
enum class AdmissionResult : uint8_t {
    DurablyQueued,       // Written & fsync'd to disk WAL spool (tests & shutdown)
    AcceptedPendingSync, // Accepted into memory buffer/queue pending background fsync
    RejectedSpoolFull,   // Spool capacity cap reached
    RejectedDisabled     // Producer disabled in configuration
};

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

} // namespace securecloud::gateway::audit
