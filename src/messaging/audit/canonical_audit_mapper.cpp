#include "canonical_audit_mapper.hpp"

#include "audit/messaging_audit_metrics.hpp"
#include "domain/audit_event_id.hpp"
#include "securecloud/grpc/caller_context.hpp"
#include "util/zero_plaintext_guard.hpp"

#include <chrono>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

namespace securecloud::messaging::audit {

using securecloud::audit::v1::ActorTypeProto;
using securecloud::audit::v1::AuditEventProto;
using securecloud::audit::v1::ProducerServiceProto;
using securecloud::audit::v1::SeverityProto;

namespace {

[[nodiscard]] std::optional<SeverityProto> parse_severity(std::string_view sev) noexcept {
    if (sev == "INFO") {
        return securecloud::audit::v1::SEVERITY_INFO;
    }
    if (sev == "WARNING") {
        return securecloud::audit::v1::SEVERITY_WARNING;
    }
    if (sev == "SECURITY") {
        return securecloud::audit::v1::SEVERITY_SECURITY;
    }
    if (sev == "CRITICAL") {
        return securecloud::audit::v1::SEVERITY_CRITICAL;
    }
    return std::nullopt;
}

} // namespace

std::optional<AuditEventProto> map_outbox_record_to_canonical_proto(const repository::AuditOutboxRecord& record,
                                                                    std::string_view producer_instance) {
    if (!domain::is_valid_audit_uuid_v7(record.event_id) || record.event_type.empty()) {
        return std::nullopt;
    }

    const auto severity_opt = parse_severity(record.severity);
    if (!severity_opt.has_value()) {
        return std::nullopt;
    }

    AuditEventProto proto;

    // 1. Core Event Metadata
    proto.set_event_id(record.event_id);
    proto.set_producer_service(securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING);
    proto.set_producer_instance(producer_instance.empty() ? "messaging" : std::string(producer_instance));
    proto.set_event_type(record.event_type);
    proto.set_severity(*severity_opt);

    // 2. High-precision OccurredAt
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(record.created_at.time_since_epoch()).count();
    proto.set_occurred_at_ms(ms);

    // 3. Actor Routing
    if (!record.actor_user_id.empty()) {
        proto.set_actor_type(securecloud::audit::v1::ACTOR_TYPE_USER);
        proto.set_actor_id(record.actor_user_id);
    } else if (!record.actor_device_id.empty()) {
        proto.set_actor_type(securecloud::audit::v1::ACTOR_TYPE_DEVICE);
        proto.set_actor_id(record.actor_device_id);
    } else {
        proto.set_actor_type(securecloud::audit::v1::ACTOR_TYPE_SYSTEM);
        proto.set_actor_id("messaging-service");
    }

    // 4. Target Routing
    if (!record.target_resource.empty()) {
        proto.set_target_id(record.target_resource);
        proto.set_target_type(securecloud::audit::v1::TARGET_TYPE_CONVERSATION);
    }

    // 5. Metadata JSON validation and parsing to map<string, string>
    if (!record.payload_proto_bin.empty()) {
        try {
            const std::string raw_json(record.payload_proto_bin.begin(), record.payload_proto_bin.end());
            if (!util::ZeroPlaintextGuard::is_safe_audit_payload(raw_json)) {
                return std::nullopt;
            }
            const auto j = nlohmann::json::parse(raw_json);
            auto* proto_metadata = proto.mutable_metadata();
            if (j.is_object()) {
                const auto corr = j.value("correlation_id", std::string{});
                if (securecloud::common::rpc::is_valid_uuid(corr)) {
                    proto.set_correlation_id(corr);
                }
            }
            for (const auto& [key, value] : j.items()) {
                if (key == "correlation_id") {
                    continue;
                }
                (*proto_metadata)[key] = value.is_string() ? value.get<std::string>() : value.dump();
            }
        } catch (...) {
            return std::nullopt;
        }
    }

    if (!record.actor_user_id.empty() && !record.actor_device_id.empty()) {
        auto* proto_metadata = proto.mutable_metadata();
        if (!proto_metadata->contains("actor_device_id")) {
            (*proto_metadata)["actor_device_id"] = record.actor_device_id;
        }
    }

    if (proto.correlation_id().empty()) {
        proto.set_correlation_id(securecloud::common::rpc::is_valid_uuid(record.event_id) ? record.event_id
                                                                                          : std::string{});
    }

    return proto;
}

repository::AuditOutboxRecord build_canonical_outbox_record(const domain::MessagingAuditEvent& event,
                                                            std::string_view routing_key,
                                                            std::string_view producer_instance) {
    if (!domain::is_valid_audit_uuid_v7(event.event_id)) {
        throw std::invalid_argument("MessagingAuditEvent event_id must be a valid RFC 9562 UUIDv7");
    }

    const std::string payload_json = event.payload_json.empty() ? "{}" : event.payload_json;
    util::ZeroPlaintextGuard::validate_audit_payload(payload_json);

    repository::AuditOutboxRecord record;
    record.outbox_bucket = domain::compute_outbox_bucket_utc(event.occurred_at);
    record.shard_id = domain::compute_outbox_shard_id(routing_key);
    record.created_at = event.occurred_at;
    record.event_id = event.event_id;
    record.event_type = std::string(domain::to_string(event.event_type));
    record.severity = std::string(domain::to_string(event.severity));
    record.actor_user_id = event.actor_user_id.str();
    record.actor_device_id = event.actor_device_id.str();
    record.target_resource = event.target_resource;
    record.publish_status = "PENDING";
    record.payload_proto_bin.assign(payload_json.begin(), payload_json.end());

    auto proto_opt = map_outbox_record_to_canonical_proto(record);
    if (!proto_opt.has_value()) {
        throw std::invalid_argument("Failed to map MessagingAuditEvent into canonical AuditEventProto");
    }

    if (!producer_instance.empty()) {
        proto_opt->set_producer_instance(std::string(producer_instance));
    }
    if (!event.correlation_id.empty() && securecloud::common::rpc::is_valid_uuid(event.correlation_id)) {
        proto_opt->set_correlation_id(event.correlation_id);
    } else if (proto_opt->correlation_id().empty() && securecloud::common::rpc::is_valid_uuid(event.event_id)) {
        proto_opt->set_correlation_id(event.event_id);
    }

    std::string serialized_wire;
    if (!proto_opt->SerializeToString(&serialized_wire)) {
        throw std::runtime_error("Failed to serialize canonical AuditEventProto to wire bytes");
    }
    record.payload_proto_bin.assign(serialized_wire.begin(), serialized_wire.end());

    return record;
}

void stage_canonical_audit_event(repository::IMessagingAuditOutboxRepository* audit_repo,
                                 const domain::MessagingAuditEvent& event, std::string_view routing_key,
                                 std::string_view producer_instance) {
    if (audit_repo == nullptr) {
        return;
    }
    const repository::AuditOutboxRecord record = build_canonical_outbox_record(event, routing_key, producer_instance);
    audit_repo->enqueue_audit_event(record);
    MessagingAuditMetrics::instance().increment_staged(record.event_type, record.severity);
}

} // namespace securecloud::messaging::audit
