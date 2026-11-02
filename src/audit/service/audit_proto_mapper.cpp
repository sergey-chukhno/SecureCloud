#include "service/audit_proto_mapper.hpp"

#include <chrono>

namespace securecloud::audit::service {

domain::AuditEvent AuditProtoMapper::to_domain(const v1::AuditEventProto& proto) {
    domain::AuditEvent ev{};

    if (auto id_opt = domain::EventId::from_string(proto.event_id())) {
        ev.event_id = *id_opt;
    }

    ev.occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(proto.occurred_at_ms()));
    ev.event_type = proto.event_type();
    ev.severity = to_domain_severity(proto.severity());
    ev.producer_service = to_domain_producer(proto.producer_service());
    ev.producer_instance = proto.producer_instance();
    ev.actor_type = to_domain_actor_type(proto.actor_type());
    ev.actor_id = proto.actor_id();
    ev.target_type = to_domain_target_type(proto.target_type());
    ev.target_id = proto.target_id();
    ev.correlation_id = proto.correlation_id();

    if (proto.has_causation_id()) {
        ev.causation_id = proto.causation_id();
    } else {
        ev.causation_id = std::nullopt;
    }

    ev.metadata.reserve(static_cast<std::size_t>(proto.metadata_size()));
    for (const auto& [k, v] : proto.metadata()) {
        ev.metadata[k] = v;
    }

    return ev;
}

v1::AuditEventProto AuditProtoMapper::to_proto(const domain::AuditEvent& event) {
    v1::AuditEventProto proto;

    proto.set_event_id(event.event_id.to_string());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(event.occurred_at.time_since_epoch()).count();
    proto.set_occurred_at_ms(ms);

    proto.set_event_type(event.event_type);
    proto.set_severity(to_proto_severity(event.severity));
    proto.set_producer_service(to_proto_producer(event.producer_service));
    proto.set_producer_instance(event.producer_instance);
    proto.set_actor_type(to_proto_actor_type(event.actor_type));
    proto.set_actor_id(event.actor_id);
    proto.set_target_type(to_proto_target_type(event.target_type));
    proto.set_target_id(event.target_id);
    proto.set_correlation_id(event.correlation_id);

    if (event.causation_id.has_value()) {
        proto.set_causation_id(*event.causation_id);
    }

    auto* mutable_meta = proto.mutable_metadata();
    for (const auto& [k, v] : event.metadata) {
        (*mutable_meta)[k] = v;
    }

    return proto;
}

domain::Severity AuditProtoMapper::to_domain_severity(v1::SeverityProto proto_severity) {
    switch (proto_severity) {
    case v1::SEVERITY_INFO:
        return domain::Severity::Info;
    case v1::SEVERITY_WARNING:
        return domain::Severity::Warning;
    case v1::SEVERITY_SECURITY:
        return domain::Severity::Security;
    case v1::SEVERITY_CRITICAL:
        return domain::Severity::Critical;
    default:
        return domain::Severity::Info;
    }
}

v1::SeverityProto AuditProtoMapper::to_proto_severity(domain::Severity severity) {
    switch (severity) {
    case domain::Severity::Info:
        return v1::SEVERITY_INFO;
    case domain::Severity::Warning:
        return v1::SEVERITY_WARNING;
    case domain::Severity::Security:
        return v1::SEVERITY_SECURITY;
    case domain::Severity::Critical:
        return v1::SEVERITY_CRITICAL;
    default:
        return v1::SEVERITY_UNSPECIFIED;
    }
}

domain::ProducerService AuditProtoMapper::to_domain_producer(v1::ProducerServiceProto proto_producer) {
    switch (proto_producer) {
    case v1::PRODUCER_SERVICE_GATEWAY:
        return domain::ProducerService::Gateway;
    case v1::PRODUCER_SERVICE_AUTH:
        return domain::ProducerService::Auth;
    case v1::PRODUCER_SERVICE_MESSAGING:
        return domain::ProducerService::Messaging;
    case v1::PRODUCER_SERVICE_FILES:
        return domain::ProducerService::Files;
    case v1::PRODUCER_SERVICE_AUDIT:
        return domain::ProducerService::Audit;
    default:
        return domain::ProducerService::Audit;
    }
}

v1::ProducerServiceProto AuditProtoMapper::to_proto_producer(domain::ProducerService producer) {
    switch (producer) {
    case domain::ProducerService::Gateway:
        return v1::PRODUCER_SERVICE_GATEWAY;
    case domain::ProducerService::Auth:
        return v1::PRODUCER_SERVICE_AUTH;
    case domain::ProducerService::Messaging:
        return v1::PRODUCER_SERVICE_MESSAGING;
    case domain::ProducerService::Files:
        return v1::PRODUCER_SERVICE_FILES;
    case domain::ProducerService::Audit:
        return v1::PRODUCER_SERVICE_AUDIT;
    default:
        return v1::PRODUCER_SERVICE_UNSPECIFIED;
    }
}

domain::ActorType AuditProtoMapper::to_domain_actor_type(v1::ActorTypeProto proto_actor) {
    switch (proto_actor) {
    case v1::ACTOR_TYPE_USER:
        return domain::ActorType::User;
    case v1::ACTOR_TYPE_DEVICE:
        return domain::ActorType::Device;
    case v1::ACTOR_TYPE_SERVICE:
        return domain::ActorType::Service;
    case v1::ACTOR_TYPE_SYSTEM:
        return domain::ActorType::System;
    default:
        return domain::ActorType::Unknown;
    }
}

v1::ActorTypeProto AuditProtoMapper::to_proto_actor_type(domain::ActorType actor) {
    switch (actor) {
    case domain::ActorType::User:
        return v1::ACTOR_TYPE_USER;
    case domain::ActorType::Device:
        return v1::ACTOR_TYPE_DEVICE;
    case domain::ActorType::Service:
        return v1::ACTOR_TYPE_SERVICE;
    case domain::ActorType::System:
        return v1::ACTOR_TYPE_SYSTEM;
    default:
        return v1::ACTOR_TYPE_UNSPECIFIED;
    }
}

domain::TargetType AuditProtoMapper::to_domain_target_type(v1::TargetTypeProto proto_target) {
    switch (proto_target) {
    case v1::TARGET_TYPE_USER:
        return domain::TargetType::User;
    case v1::TARGET_TYPE_DEVICE:
        return domain::TargetType::Device;
    case v1::TARGET_TYPE_CONVERSATION:
        return domain::TargetType::Conversation;
    case v1::TARGET_TYPE_FILE:
        return domain::TargetType::File;
    case v1::TARGET_TYPE_SERVICE:
        return domain::TargetType::Service;
    default:
        return domain::TargetType::Unknown;
    }
}

v1::TargetTypeProto AuditProtoMapper::to_proto_target_type(domain::TargetType target) {
    switch (target) {
    case domain::TargetType::User:
        return v1::TARGET_TYPE_USER;
    case domain::TargetType::Device:
        return v1::TARGET_TYPE_DEVICE;
    case domain::TargetType::Conversation:
        return v1::TARGET_TYPE_CONVERSATION;
    case domain::TargetType::File:
        return v1::TARGET_TYPE_FILE;
    case domain::TargetType::Service:
        return v1::TARGET_TYPE_SERVICE;
    default:
        return v1::TARGET_TYPE_UNSPECIFIED;
    }
}

} // namespace securecloud::audit::service