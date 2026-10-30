#pragma once

#include "audit_event.hpp"
#include "securecloud/audit/v1/audit.pb.h"

#include <chrono>

namespace securecloud::audit::domain {

class AuditEventMapper {
  public:
    /// Maps a Protobuf AuditEventProto to canonical C++20 domain AuditEvent.
    /// Authoritatively sets received_at to the provided ingestion timestamp.
    [[nodiscard]] static AuditEvent to_domain(const securecloud::audit::v1::AuditEventProto& proto,
                                              std::chrono::system_clock::time_point received_at);

    /// Maps a canonical C++20 domain AuditEvent to Protobuf AuditEventProto.
    [[nodiscard]] static securecloud::audit::v1::AuditEventProto to_proto(const AuditEvent& domain);

    /// Maps a canonical C++20 domain AuditEvent to PersistedAuditEventProto (includes received_at_ms).
    [[nodiscard]] static securecloud::audit::v1::PersistedAuditEventProto to_persisted_proto(const AuditEvent& domain);
};

} // namespace securecloud::audit::domain