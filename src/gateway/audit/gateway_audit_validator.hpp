#pragma once

#include "domain/audit_event.hpp"
#include "domain/audit_event_validator.hpp"
#include "domain/sensitive_data_guard.hpp"
#include "domain/validation_result.hpp"

#include <atomic>
#include <cstdint>
#include <string>

namespace securecloud::gateway::audit {

    /**
     * @brief Local event validator wrapping Audit domain rules and SensitiveDataGuard.
     *
     * Enforces AUDIT-002 and AUDIT-012 local validation requirements before queuing events to spool.
     */
    class GatewayAuditEventValidator {
    public:
        GatewayAuditEventValidator() = default;

        /// Validates an in-memory domain AuditEvent against mirrored Audit limits and sensitivity constraints.
        [[nodiscard]] securecloud::audit::domain::AuditValidationResult
        validate(const securecloud::audit::domain::AuditEvent& event) const noexcept;

        /// Counter of locally failed validations (closed metric set)
        [[nodiscard]] uint64_t invalid_events_count() const noexcept {
            return invalid_events_counter_.load(std::memory_order_relaxed);
        }

        void increment_invalid_count() const noexcept {
            invalid_events_counter_.fetch_add(1, std::memory_order_relaxed);
        }

    private:
        securecloud::audit::domain::AuditEventValidationLimits limits_{};
        mutable std::atomic<uint64_t> invalid_events_counter_{0};
    };

} // namespace securecloud::gateway::audit
