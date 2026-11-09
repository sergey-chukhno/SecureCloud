#include "audit/gateway_audit_event_factory.hpp"
#include "audit/gateway_audit_event_types.hpp"

#include <gtest/gtest.h>

using namespace securecloud::gateway::audit;

TEST(GatewayAuditEventFactoryTest, GeneratesValidCanonicalEvent) {
    GatewayAuditEventFactory factory("gateway-test-instance");
    GatewayAuditObservation obs;
    obs.type = GatewayAuditEventType::TokenRejected;
    obs.client_ip = "192.168.1.100";
    obs.route_class = "auth_login";
    obs.http_method = "POST";
    obs.actor_id = "user_123456789";
    obs.device_id = "device_987654321";
    obs.metadata["reason"] = "invalid_signature";

    const auto domain_event = factory.create_domain_event(obs);

    EXPECT_FALSE(domain_event.event_id.is_nil());
    EXPECT_EQ(domain_event.event_type, "security.token.rejected");
    EXPECT_EQ(domain_event.severity, securecloud::audit::domain::Severity::Security);
    EXPECT_EQ(domain_event.producer_instance, "gateway-test-instance");
    EXPECT_EQ(domain_event.actor_id, "user_123456789");
    EXPECT_EQ(domain_event.metadata.at("client_ip"), "192.168.1.100");
    EXPECT_EQ(domain_event.metadata.at("device_id"), "device_987654321");
    EXPECT_EQ(domain_event.metadata.at("reason"), "invalid_signature");

    const auto proto_event = factory.to_protobuf(domain_event);
    EXPECT_EQ(proto_event.event_id(), domain_event.event_id.to_string());
    EXPECT_EQ(proto_event.producer_service(), ::securecloud::audit::v1::PRODUCER_SERVICE_GATEWAY);
    EXPECT_EQ(proto_event.severity(), ::securecloud::audit::v1::SEVERITY_SECURITY);

    const auto bytes = factory.serialize_canonical_proto(proto_event);
    EXPECT_FALSE(bytes.empty());
}

TEST(GatewayAuditEventFactoryTest, HardensCorrelationId) {
    GatewayAuditEventFactory factory;

    // Malformed client request ID replaced by fresh UUIDv7
    const auto sanitized_garbage = factory.sanitize_correlation_id("invalid-client-garbage-id");
    EXPECT_NE(sanitized_garbage, "invalid-client-garbage-id");
    EXPECT_EQ(sanitized_garbage.length(), 36);

    // Valid UUID passthrough
    const std::string valid_uuid = "018f3b2a-7c12-7123-8123-456789abcdef";
    EXPECT_EQ(factory.sanitize_correlation_id(valid_uuid), valid_uuid);
}

TEST(GatewayAuditEventFactoryTest, FiltersUnwhitelistedMetadata) {
    GatewayAuditEventFactory factory;
    GatewayAuditObservation obs;
    obs.type = GatewayAuditEventType::TokenRejected;
    obs.metadata["reason"] = "expired_local";
    obs.metadata["unapproved_custom_field"] = "should_be_stripped";

    const auto domain_event = factory.create_domain_event(obs);
    EXPECT_EQ(domain_event.metadata.count("reason"), 1);
    EXPECT_EQ(domain_event.metadata.count("unapproved_custom_field"), 0);
}
