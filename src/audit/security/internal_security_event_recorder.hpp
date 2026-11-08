#pragma once

#include "security/anti_recursion_guard.hpp"
#include "security/internal_security_event_factory.hpp"
#include "security/internal_security_event_types.hpp"
#include "service/audit_ingestion_service.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

namespace securecloud::audit::security {

/// Asynchronous non-blocking recorder for internal audit service security events.
class InternalSecurityEventRecorder {
  public:
    explicit InternalSecurityEventRecorder(std::shared_ptr<service::AuditIngestionService> ingestion_service,
                                           std::string service_instance_name = "securecloud-audit");

    /// Asynchronously records an internal security event. Non-blocking and exception-safe.
    bool record_event(InternalSecurityEventType type, const SecurityEventContext& context) noexcept;

    [[nodiscard]] std::uint64_t events_recorded_count() const noexcept;
    [[nodiscard]] std::uint64_t events_dropped_count() const noexcept;
    [[nodiscard]] std::uint64_t recursion_prevented_count() const noexcept;

  private:
    std::shared_ptr<service::AuditIngestionService> ingestion_service_;
    InternalSecurityEventFactory factory_;
    std::atomic<std::uint64_t> events_recorded_count_{0};
    std::atomic<std::uint64_t> events_dropped_count_{0};
};

} // namespace securecloud::audit::security
