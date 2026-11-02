#include "audit_event_mapper.hpp"

namespace securecloud::audit::domain {

namespace {

Severity to_domain_severity(securecloud::audit::v1::SeverityProto proto) noexcept {
    switch (proto) {
    case securecloud::audit::v1::SEVERITY_INFO:
        return Severity::Info;
    case securecloud::audit::v1::SEVERITY_WARNING:
        return Severity::Warning;
    case securecloud::audit::v1::SEVERITY_SECURITY:
        return Severity::Security;
    case securecloud::audit::v1::SEVERITY_CRITICAL:
        return Severity::Critical;
    default:
        return Severity::Info;
    }
}

securecloud::audit::v1::SeverityProto to_proto_severity(Severity domain) noexcept {
    switch (domain) {
    case Severity::Info:
        return securecloud::audit::v1::SEVERITY_INFO;
    case Severity::Warning:
        return securecloud::audit::v1::SEVERITY_WARNING;
    case Severity::Security:
        return securecloud::audit::v1::SEVERITY_SECURITY;
    case Severity::Critical:
        return securecloud::audit::v1::SEVERITY_CRITICAL;
    }
    return securecloud::audit::v1::SEVERITY_UNSPECIFIED;
}

ProducerService to_domain_producer(securecloud::audit::v1::ProducerServiceProto proto) noexcept {
    switch (proto) {
    case securecloud::audit::v1::PRODUCER_SERVICE_GATEWAY:
        return ProducerService::Gateway;
    case securecloud::audit::v1::PRODUCER_SERVICE_AUTH:
        return ProducerService::Auth;
    case securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING:
        return ProducerService::Messaging;
    case securecloud::audit::v1::PRODUCER_SERVICE_FILES:
        return ProducerService::Files;
    case securecloud::audit::v1::PRODUCER_SERVICE_AUDIT:
        return ProducerService::Audit;
    default:
        return ProducerService::Audit;
    }
}

securecloud::audit::v1::ProducerServiceProto to_proto_producer(ProducerService domain) noexcept {
    switch (domain) {
    case ProducerService::Gateway:
        return securecloud::audit::v1::PRODUCER_SERVICE_GATEWAY;
    case ProducerService::Auth:
        return securecloud::audit::v1::PRODUCER_SERVICE_AUTH;
    case ProducerService::Messaging:
        return securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING;
    case ProducerService::Files:
        return securecloud::audit::v1::PRODUCER_SERVICE_FILES;
    case ProducerService::Audit:
        return securecloud::audit::v1::PRODUCER_SERVICE_AUDIT;
    }
    return securecloud::audit::v1::PRODUCER_SERVICE_UNSPECIFIED;
}

ActorType to_domain_actor_type(securecloud::audit::v1::ActorTypeProto proto) noexcept {
    switch (proto) {
    case securecloud::audit::v1::ACTOR_TYPE_USER:
        return ActorType::User;
    case securecloud::audit::v1::ACTOR_TYPE_DEVICE:
        return ActorType::Device;
    case securecloud::audit::v1::ACTOR_TYPE_SERVICE:
        return ActorType::Service;
    case securecloud::audit::v1::ACTOR_TYPE_SYSTEM:
        return ActorType::System;
    default:
        return ActorType::Unknown;
    }
}

securecloud::audit::v1::ActorTypeProto to_proto_actor_type(ActorType domain) noexcept {
    switch (domain) {
    case ActorType::User:
        return securecloud::audit::v1::ACTOR_TYPE_USER;
    case ActorType::Device:
        return securecloud::audit::v1::ACTOR_TYPE_DEVICE;
    case ActorType::Service:
        return securecloud::audit::v1::ACTOR_TYPE_SERVICE;
    case ActorType::System:
        return securecloud::audit::v1::ACTOR_TYPE_SYSTEM;
    case ActorType::Unknown:
        return securecloud::audit::v1::ACTOR_TYPE_UNSPECIFIED;
    }
    return securecloud::audit::v1::ACTOR_TYPE_UNSPECIFIED;
}

TargetType to_domain_target_type(securecloud::audit::v1::TargetTypeProto proto) noexcept {
    switch (proto) {
    case securecloud::audit::v1::TARGET_TYPE_USER:
        return TargetType::User;
    case securecloud::audit::v1::TARGET_TYPE_DEVICE:
        return TargetType::Device;
    case securecloud::audit::v1::TARGET_TYPE_CONVERSATION:
        return TargetType::Conversation;
    case securecloud::audit::v1::TARGET_TYPE_FILE:
        return TargetType::File;
    case securecloud::audit::v1::TARGET_TYPE_SERVICE:
        return TargetType::Service;
    default:
        return TargetType::Unknown;
    }
}

securecloud::audit::v1::TargetTypeProto to_proto_target_type(TargetType domain) noexcept {
    switch (domain) {
    case TargetType::User:
        return securecloud::audit::v1::TARGET_TYPE_USER;
    case TargetType::Device:
        return securecloud::audit::v1::TARGET_TYPE_DEVICE;
    case TargetType::Conversation:
        return securecloud::audit::v1::TARGET_TYPE_CONVERSATION;
    case TargetType::File:
        return securecloud::audit::v1::TARGET_TYPE_FILE;
    case TargetType::Service:
        return securecloud::audit::v1::TARGET_TYPE_SERVICE;
    case TargetType::Unknown:
        return securecloud::audit::v1::TARGET_TYPE_UNSPECIFIED;
    }
    return securecloud::audit::v1::TARGET_TYPE_UNSPECIFIED;
}

} // namespace

AuditEvent AuditEventMapper::to_domain(const securecloud::audit::v1::AuditEventProto& proto,
                                       std::chrono::system_clock::time_point received_at) {

    AuditEvent domain{};

    if (auto id_opt = EventId::from_string(proto.event_id()); id_opt.has_value()) {
        domain.event_id = *id_opt;
    }

    domain.occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(proto.occurred_at_ms()));
    domain.received_at = received_at;
    domain.event_type = proto.event_type();
    domain.severity = to_domain_severity(proto.severity());
    domain.producer_service = to_domain_producer(proto.producer_service());
    domain.producer_instance = proto.producer_instance();
    domain.actor_type = to_domain_actor_type(proto.actor_type());
    domain.actor_id = proto.actor_id();
    domain.target_type = to_domain_target_type(proto.target_type());
    domain.target_id = proto.target_id();
    domain.correlation_id = proto.correlation_id();

    if (proto.has_causation_id()) {
        domain.causation_id = proto.causation_id();
    }

    for (const auto& [k, v] : proto.metadata()) {
        domain.metadata[k] = v;
    }

    return domain;
}

securecloud::audit::v1::AuditEventProto AuditEventMapper::to_proto(const AuditEvent& domain) {
    securecloud::audit::v1::AuditEventProto proto;

    proto.set_event_id(domain.event_id.to_string());
    proto.set_occurred_at_ms(
        std::chrono::duration_cast<std::chrono::milliseconds>(domain.occurred_at.time_since_epoch()).count());
    proto.set_event_type(domain.event_type);
    proto.set_severity(to_proto_severity(domain.severity));
    proto.set_producer_service(to_proto_producer(domain.producer_service));
    proto.set_producer_instance(domain.producer_instance);
    proto.set_actor_type(to_proto_actor_type(domain.actor_type));
    proto.set_actor_id(domain.actor_id);
    proto.set_target_type(to_proto_target_type(domain.target_type));
    proto.set_target_id(domain.target_id);
    proto.set_correlation_id(domain.correlation_id);

    if (domain.causation_id.has_value()) {
        proto.set_causation_id(*domain.causation_id);
    }

    auto* mutable_meta = proto.mutable_metadata();
    for (const auto& [k, v] : domain.metadata) {
        (*mutable_meta)[k] = v;
    }

    return proto;
}

securecloud::audit::v1::PersistedAuditEventProto AuditEventMapper::to_persisted_proto(const AuditEvent& domain) {
    securecloud::audit::v1::PersistedAuditEventProto persisted;
    *persisted.mutable_event() = to_proto(domain);
    const int64_t recv_ms =
        domain.received_at.has_value()
            ? std::chrono::duration_cast<std::chrono::milliseconds>(domain.received_at->time_since_epoch()).count()
            : 0;
    persisted.set_received_at_ms(recv_ms);
    return persisted;
}

} // namespace securecloud::audit::domain