#pragma once

#include "audit_event.hpp"
#include "validation_result.hpp"

#include <string>
#include <string_view>

namespace securecloud::audit::domain {

class SensitiveDataGuard {
  public:
    /// Inspects an AuditEvent for prohibited sensitive keys, credential terms,
    /// PEM private key headers, and JWT structures in metadata.
    [[nodiscard]] static AuditValidationResult inspect(const AuditEvent& event) noexcept;

    /// Sanitizes a diagnostic or log message by replacing sensitive key terms
    /// or secret patterns with '[REDACTED]'.
    [[nodiscard]] static std::string sanitize_diagnostic(std::string_view raw);
};

} // namespace securecloud::audit::domain