#pragma once

#include "auth/domain/audit_event.hpp"
#include "auth/domain/auth_outbox_entity.hpp"
#include "securecloud/audit/v1/audit.pb.h"

#include <string>

namespace securecloud::auth::service {

    /// Converts Auth domain AuditEvents into persistent AuthOutboxEntity records
    /// and reconstructs AuditEventProto messages for gRPC batch relay.
    class OutboxEventMapper {
    public:
        /// Serializes a domain AuditEvent into an AuthOutboxEntity ready for staging.
        [[nodiscard]] static domain::AuthOutboxEntity to_outbox_entity(const domain::AuditEvent& event,
                                                                       std::string_view default_producer_instance = "auth-1");

        /// Deserializes a stored AuthOutboxEntity into a wire AuditEventProto.
        /// Throws std::runtime_error if payload_json is malformed or missing required fields.
        [[nodiscard]] static securecloud::audit::v1::AuditEventProto
        to_audit_proto(const domain::AuthOutboxEntity& entity);
    };

} // namespace securecloud::auth::service
