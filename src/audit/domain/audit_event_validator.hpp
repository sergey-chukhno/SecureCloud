#pragma once

#include "audit_event.hpp"
#include "validation_result.hpp"

#include <chrono>
#include <cstddef>

namespace securecloud::audit::domain {

struct AuditEventValidationLimits {
    size_t max_event_size_bytes{65536}; // 64 KB default, up to 1 MB
    size_t max_metadata_entries{50};
    size_t max_metadata_key_length{64};
    size_t max_metadata_value_length{1024};
    size_t max_event_type_length{64};
    size_t max_producer_instance_length{64};
    size_t max_actor_id_length{128};
    size_t max_target_id_length{128};
    size_t max_correlation_id_length{64};
    size_t max_causation_id_length{64};
    std::chrono::seconds max_future_skew{300}; // 5 minutes max clock drift
    std::chrono::hours max_past_age{24 * 365}; // 1 year historical window
};

class AuditEventValidator {
  public:
    /// Pure, deterministic validation of an AuditEvent against specified limits and time reference.
    [[nodiscard]] static AuditValidationResult
    validate(const AuditEvent& event, const AuditEventValidationLimits& limits = {},
             std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) noexcept;
};

} // namespace securecloud::audit::domain