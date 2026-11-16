#include "gateway_audit_validator.hpp"

namespace securecloud::gateway::audit {

securecloud::audit::domain::AuditValidationResult
GatewayAuditEventValidator::validate(const securecloud::audit::domain::AuditEvent& event) const noexcept {
    // 1. Run canonical domain field limit & timestamp validator
    auto result = securecloud::audit::domain::AuditEventValidator::validate(event, limits_);
    if (!result.is_valid()) {
        increment_invalid_count();
        return result;
    }

    // 2. Inspect for sensitive keys, raw credentials, and token patterns
    result = securecloud::audit::domain::SensitiveDataGuard::inspect(event);
    if (!result.is_valid()) {
        increment_invalid_count();
        return result;
    }

    return result;
}

} // namespace securecloud::gateway::audit
