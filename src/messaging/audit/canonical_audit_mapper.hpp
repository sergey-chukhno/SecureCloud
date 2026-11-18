#pragma once

#include "messaging/repository/messaging_audit_outbox_repository_interface.hpp"
#include "securecloud/audit/v1/audit.pb.h"
#include <optional>

namespace securecloud::messaging::audit {

    /**
     * Maps an internal outbox record to the canonical AUDIT-002 Protobuf representation.
     * Performs validation and returns std::nullopt if the event is malformed.
     */
    std::optional<securecloud::audit::v1::AuditEventProto>
    map_outbox_record_to_canonical_proto(const repository::AuditOutboxRecord& record);

} // namespace securecloud::messaging::audit
