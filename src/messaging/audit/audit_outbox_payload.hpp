#pragma once

#include "messaging/repository/messaging_audit_outbox_repository_interface.hpp"
#include "securecloud/grpc/caller_context.hpp"

#include <nlohmann/json.hpp>
#include <string_view>

namespace securecloud::messaging::audit {

inline void set_outbox_correlation_id(repository::AuditOutboxRecord& record, std::string_view correlation_id) {
    if (!securecloud::common::rpc::is_valid_uuid(correlation_id)) {
        return;
    }
    const auto payload = nlohmann::json{{"correlation_id", correlation_id}}.dump();
    record.payload_proto_bin.assign(payload.begin(), payload.end());
}

} // namespace securecloud::messaging::audit
