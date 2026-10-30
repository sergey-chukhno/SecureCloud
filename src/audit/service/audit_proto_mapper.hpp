#pragma once

#include "domain/audit_event.hpp"
#include "securecloud/audit/v1/audit.pb.h"

namespace securecloud::audit::service {

class AuditProtoMapper {
  public:
    [[nodiscard]] static domain::AuditEvent to_domain(const v1::AuditEventProto& proto);
    [[nodiscard]] static v1::AuditEventProto to_proto(const domain::AuditEvent& event);

    [[nodiscard]] static domain::Severity to_domain_severity(v1::SeverityProto proto_severity);
    [[nodiscard]] static v1::SeverityProto to_proto_severity(domain::Severity severity);

    [[nodiscard]] static domain::ProducerService to_domain_producer(v1::ProducerServiceProto proto_producer);
    [[nodiscard]] static v1::ProducerServiceProto to_proto_producer(domain::ProducerService producer);

    [[nodiscard]] static domain::ActorType to_domain_actor_type(v1::ActorTypeProto proto_actor);
    [[nodiscard]] static v1::ActorTypeProto to_proto_actor_type(domain::ActorType actor);

    [[nodiscard]] static domain::TargetType to_domain_target_type(v1::TargetTypeProto proto_target);
    [[nodiscard]] static v1::TargetTypeProto to_proto_target_type(domain::TargetType target);
};

} // namespace securecloud::audit::service