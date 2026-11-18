#include "canonical_audit_mapper.hpp"
#include <nlohmann/json.hpp> // Supposé via le target securecloud::json
#include <chrono>

namespace securecloud::messaging::audit {

using securecloud::audit::v1::AuditEventProto;
using securecloud::audit::v1::SeverityProto;
using securecloud::audit::v1::ProducerServiceProto;
using securecloud::audit::v1::ActorTypeProto;

namespace {
SeverityProto parse_severity(const std::string& sev) {
    if (sev == "INFO") return securecloud::audit::v1::SEVERITY_INFO;
    if (sev == "WARNING") return securecloud::audit::v1::SEVERITY_WARNING;
    if (sev == "SECURITY") return securecloud::audit::v1::SEVERITY_SECURITY;
    if (sev == "CRITICAL") return securecloud::audit::v1::SEVERITY_CRITICAL;
    return securecloud::audit::v1::SEVERITY_UNSPECIFIED;
}
} // namespace

std::optional<AuditEventProto> map_outbox_record_to_canonical_proto(const repository::AuditOutboxRecord& record) {
    AuditEventProto proto;

    // 1. Core Event Metadata
    proto.set_event_id(record.event_id);
    proto.set_producer_service(securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING);
    proto.set_event_type(record.event_type);
    proto.set_severity(parse_severity(record.severity));

    // 2. High-precision OccurredAt
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(record.created_at.time_since_epoch()).count();
    proto.set_occurred_at_ms(ms);

    // 3. Actor Routing
    if (!record.actor_user_id.empty()) {
        proto.set_actor_type(securecloud::audit::v1::ACTOR_TYPE_USER);
        proto.set_actor_id(record.actor_user_id);
    } else if (!record.actor_device_id.empty()) {
        proto.set_actor_type(securecloud::audit::v1::ACTOR_TYPE_DEVICE);
        proto.set_actor_id(record.actor_device_id);
    }

    // 4. Target Routing
    if (!record.target_resource.empty()) {
        proto.set_target_id(record.target_resource);
        // By default, inferred as CONVERSATION for messaging unless parsing says otherwise
        proto.set_target_type(securecloud::audit::v1::TARGET_TYPE_CONVERSATION);
    }

    // 5. Metadata JSON parsing to map<string, string>
    if (!record.payload_proto_bin.empty()) {
        try {
            std::string raw_json(record.payload_proto_bin.begin(), record.payload_proto_bin.end());
            auto j = nlohmann::json::parse(raw_json);
            auto* proto_metadata = proto.mutable_metadata();
            for (auto& [key, value] : j.items()) {
                (*proto_metadata)[key] = value.is_string() ? value.get<std::string>() : value.dump();
            }
        } catch (...) {
            // Failure to parse JSON payload invalidates canonical compliance
            return std::nullopt;
        }
    }

    // (Optional) Integration with securecloud::audit::domain::validate_canonical_event()
    // goes here before returning.

    return proto;
}

} // namespace securecloud::messaging::audit
