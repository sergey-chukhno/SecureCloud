#include "auth/service/outbox_event_mapper.hpp"

#include <chrono>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace securecloud::auth::service {

namespace {

[[nodiscard]] domain::OutboxSeverity map_severity_to_outbox(domain::AuditSeverity sev) noexcept {
    switch (sev) {
    case domain::AuditSeverity::Info:
        return domain::OutboxSeverity::Info;
    case domain::AuditSeverity::Warning:
        return domain::OutboxSeverity::Warning;
    case domain::AuditSeverity::Security:
        return domain::OutboxSeverity::Security;
    case domain::AuditSeverity::Critical:
        return domain::OutboxSeverity::Critical;
    }
    return domain::OutboxSeverity::Info;
}

[[nodiscard]] securecloud::audit::v1::SeverityProto map_severity_to_proto(std::string_view sev) noexcept {
    if (sev == "WARNING") {
        return securecloud::audit::v1::SEVERITY_WARNING;
    }
    if (sev == "SECURITY") {
        return securecloud::audit::v1::SEVERITY_SECURITY;
    }
    if (sev == "CRITICAL") {
        return securecloud::audit::v1::SEVERITY_CRITICAL;
    }
    return securecloud::audit::v1::SEVERITY_INFO;
}

[[nodiscard]] securecloud::audit::v1::ActorTypeProto map_actor_type_to_proto(std::string_view actor) noexcept {
    if (actor == "USER") {
        return securecloud::audit::v1::ACTOR_TYPE_USER;
    }
    if (actor == "DEVICE") {
        return securecloud::audit::v1::ACTOR_TYPE_DEVICE;
    }
    if (actor == "SERVICE") {
        return securecloud::audit::v1::ACTOR_TYPE_SERVICE;
    }
    if (actor == "SYSTEM") {
        return securecloud::audit::v1::ACTOR_TYPE_SYSTEM;
    }
    return securecloud::audit::v1::ACTOR_TYPE_UNSPECIFIED;
}

[[nodiscard]] securecloud::audit::v1::TargetTypeProto map_target_type_to_proto(std::string_view target) noexcept {
    if (target == "USER") {
        return securecloud::audit::v1::TARGET_TYPE_USER;
    }
    if (target == "DEVICE") {
        return securecloud::audit::v1::TARGET_TYPE_DEVICE;
    }
    if (target == "CONVERSATION") {
        return securecloud::audit::v1::TARGET_TYPE_CONVERSATION;
    }
    if (target == "FILE") {
        return securecloud::audit::v1::TARGET_TYPE_FILE;
    }
    if (target == "SERVICE") {
        return securecloud::audit::v1::TARGET_TYPE_SERVICE;
    }
    return securecloud::audit::v1::TARGET_TYPE_UNSPECIFIED;
}

} // namespace

domain::AuthOutboxEntity OutboxEventMapper::to_outbox_entity(const domain::AuditEvent& event,
                                                             std::string_view default_producer_instance) {
    const domain::Uuid eid = event.event_id.is_nil() ? domain::Uuid::generate_v7() : event.event_id;
    const auto occurred_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(event.occurred_at.time_since_epoch()).count();

    const std::string actor_type_str(domain::to_string(event.actor_type));
    const std::string target_type_str(domain::to_string(event.target_type));
    const domain::OutboxSeverity outbox_sev = map_severity_to_outbox(event.severity);
    const std::string sev_str(domain::to_string(outbox_sev));

    nlohmann::json payload = {
        {"event_id", eid.to_string()},
        {"occurred_at_ms", occurred_ms},
        {"event_type", event.event_type},
        {"severity", sev_str},
        {"producer_service", "AUTH"},
        {"producer_instance",
         event.producer_instance.empty() ? std::string(default_producer_instance) : event.producer_instance},
        {"actor_type", actor_type_str},
        {"actor_id", event.actor_id},
        {"target_type", target_type_str},
        {"target_id", event.target_id},
        {"correlation_id", event.correlation_id},
        {"metadata", event.metadata},
    };

    if (event.causation_id.has_value() && !event.causation_id->empty()) {
        payload["causation_id"] = *event.causation_id;
    }

    domain::AuthOutboxEntity entity;
    entity.event_id = eid;
    entity.aggregate_type = target_type_str.empty() ? "AUTH" : target_type_str;
    entity.aggregate_id = domain::Uuid::from_string(event.target_id);
    if (!entity.aggregate_id.has_value()) {
        entity.aggregate_id = domain::Uuid::from_string(event.actor_id);
    }
    entity.event_type = event.event_type;
    entity.severity = outbox_sev;
    entity.payload_json = payload.dump();
    entity.status = domain::OutboxStatus::Pending;
    entity.retry_count = 0;
    entity.created_at = event.occurred_at;

    return entity;
}

securecloud::audit::v1::AuditEventProto OutboxEventMapper::to_audit_proto(const domain::AuthOutboxEntity& entity) {
    nlohmann::json j = nlohmann::json::parse(entity.payload_json);

    securecloud::audit::v1::AuditEventProto proto;
    proto.set_event_id(j.value("event_id", entity.event_id.to_string()));
    proto.set_occurred_at_ms(j.at("occurred_at_ms").get<int64_t>());
    proto.set_event_type(j.value("event_type", entity.event_type));
    proto.set_severity(map_severity_to_proto(j.value("severity", std::string(domain::to_string(entity.severity)))));
    proto.set_producer_service(securecloud::audit::v1::PRODUCER_SERVICE_AUTH);
    proto.set_producer_instance(j.value("producer_instance", "auth-1"));
    proto.set_actor_type(map_actor_type_to_proto(j.value("actor_type", "UNKNOWN")));
    proto.set_actor_id(j.value("actor_id", ""));
    proto.set_target_type(map_target_type_to_proto(j.value("target_type", "UNKNOWN")));
    proto.set_target_id(j.value("target_id", ""));
    proto.set_correlation_id(j.value("correlation_id", ""));

    if (j.contains("causation_id") && j["causation_id"].is_string()) {
        proto.set_causation_id(j["causation_id"].get<std::string>());
    }

    if (j.contains("metadata") && j["metadata"].is_object()) {
        auto* meta_map = proto.mutable_metadata();
        for (const auto& [k, v] : j["metadata"].items()) {
            if (v.is_string()) {
                (*meta_map)[k] = v.get<std::string>();
            } else {
                (*meta_map)[k] = v.dump();
            }
        }
    }

    return proto;
}

} // namespace securecloud::auth::service
