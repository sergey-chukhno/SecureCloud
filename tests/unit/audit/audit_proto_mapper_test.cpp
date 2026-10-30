#include "service/audit_proto_mapper.hpp"

#include <chrono>
#include <gtest/gtest.h>

namespace securecloud::audit::service::testing {

TEST(AuditProtoMapperTest, BidirectionalRoundTrip) {
    domain::AuditEvent original{};
    original.event_id = domain::EventId::generate_v7();
    original.occurred_at = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    original.event_type = "user.authentication.login";
    original.severity = domain::Severity::Security;
    original.producer_service = domain::ProducerService::Auth;
    original.producer_instance = "auth-node-01";
    original.actor_type = domain::ActorType::User;
    original.actor_id = "user-uuid-999";
    original.target_type = domain::TargetType::Device;
    original.target_id = "device-uuid-888";
    original.correlation_id = domain::EventId::generate_v7().to_string();
    original.causation_id = domain::EventId::generate_v7().to_string();
    original.metadata = {{"ip", "10.0.0.1"}, {"mfa", "true"}};

    auto proto = AuditProtoMapper::to_proto(original);

    EXPECT_EQ(proto.event_id(), original.event_id.to_string());
    EXPECT_EQ(proto.event_type(), "user.authentication.login");
    EXPECT_EQ(proto.severity(), v1::SEVERITY_SECURITY);
    EXPECT_EQ(proto.producer_service(), v1::PRODUCER_SERVICE_AUTH);
    EXPECT_TRUE(proto.has_causation_id());
    EXPECT_EQ(proto.causation_id(), *original.causation_id);

    auto restored = AuditProtoMapper::to_domain(proto);

    EXPECT_EQ(restored.event_id, original.event_id);
    EXPECT_EQ(restored.occurred_at, original.occurred_at);
    EXPECT_EQ(restored.event_type, original.event_type);
    EXPECT_EQ(restored.severity, original.severity);
    EXPECT_EQ(restored.producer_service, original.producer_service);
    EXPECT_EQ(restored.producer_instance, original.producer_instance);
    EXPECT_EQ(restored.actor_type, original.actor_type);
    EXPECT_EQ(restored.actor_id, original.actor_id);
    EXPECT_EQ(restored.target_type, original.target_type);
    EXPECT_EQ(restored.target_id, original.target_id);
    EXPECT_EQ(restored.correlation_id, original.correlation_id);
    EXPECT_TRUE(restored.causation_id.has_value());
    EXPECT_EQ(*restored.causation_id, *original.causation_id);
    EXPECT_EQ(restored.metadata, original.metadata);
}

TEST(AuditProtoMapperTest, HandlesUnspecifiedEnumsGracefully) {
    v1::AuditEventProto proto;
    proto.set_event_id(domain::EventId::generate_v7().to_string());
    proto.set_severity(v1::SEVERITY_UNSPECIFIED);
    proto.set_producer_service(v1::PRODUCER_SERVICE_UNSPECIFIED);
    proto.set_actor_type(v1::ACTOR_TYPE_UNSPECIFIED);
    proto.set_target_type(v1::TARGET_TYPE_UNSPECIFIED);

    auto domain_event = AuditProtoMapper::to_domain(proto);

    EXPECT_EQ(domain_event.severity, domain::Severity::Info);
    EXPECT_EQ(domain_event.producer_service, domain::ProducerService::Audit);
    EXPECT_EQ(domain_event.actor_type, domain::ActorType::Unknown);
    EXPECT_EQ(domain_event.target_type, domain::TargetType::Unknown);
    EXPECT_FALSE(domain_event.causation_id.has_value());
}

} // namespace securecloud::audit::service::testing