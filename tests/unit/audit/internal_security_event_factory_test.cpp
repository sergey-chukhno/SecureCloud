#include "domain/audit_event_validator.hpp"
#include "security/internal_security_event_factory.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::security::testing {

class InternalSecurityEventFactoryTest : public ::testing::Test {
  protected:
    InternalSecurityEventFactory factory_{"audit-node-01"};
    domain::AuditEventValidator validator_{};
};

TEST_F(InternalSecurityEventFactoryTest, VerifiedPeerIdentityAttribution) {
    SecurityEventContext ctx;
    ctx.verified_peer_identity = "gateway.securecloud.internal";
    ctx.peer_socket_address = "10.0.1.50:50055";
    ctx.rpc_method = "SubmitAuditEvent";

    auto event = factory_.create_event(InternalSecurityEventType::ProducerIdentityMismatch, ctx);

    EXPECT_EQ(event.actor_type, domain::ActorType::Service);
    EXPECT_EQ(event.actor_id, "gateway.securecloud.internal");
    EXPECT_EQ(event.producer_service, domain::ProducerService::Audit);
    EXPECT_EQ(event.producer_instance, "audit-node-01");
    EXPECT_EQ(event.target_type, domain::TargetType::Service);
    EXPECT_EQ(event.target_id, "securecloud-audit");
    EXPECT_EQ(event.event_type, "audit.security.auth.producer_identity_mismatch");

    auto validation_res = validator_.validate(event);
    EXPECT_TRUE(validation_res.is_valid());
}

TEST_F(InternalSecurityEventFactoryTest, SocketAddressFallbackWhenUnauthenticated) {
    SecurityEventContext ctx;
    ctx.peer_socket_address = "192.168.1.100:44321";
    ctx.rpc_method = "SubmitBatch";

    auto event = factory_.create_event(InternalSecurityEventType::UnauthenticatedConnection, ctx);

    EXPECT_EQ(event.actor_type, domain::ActorType::Unknown);
    EXPECT_TRUE(event.actor_id.empty());
    EXPECT_EQ(event.metadata.at("peer_address"), "192.168.1.100:44321");

    auto validation_res = validator_.validate(event);
    EXPECT_TRUE(validation_res.is_valid());
}

TEST_F(InternalSecurityEventFactoryTest, DefaultUnauthenticatedIdentityWhenContextEmpty) {
    SecurityEventContext ctx;

    auto event = factory_.create_event(InternalSecurityEventType::IngestionQueueSaturated, ctx);

    EXPECT_EQ(event.actor_type, domain::ActorType::System);
    EXPECT_EQ(event.actor_id, "audit-node-01");

    auto validation_res = validator_.validate(event);
    EXPECT_TRUE(validation_res.is_valid());
}

TEST_F(InternalSecurityEventFactoryTest, MetadataSanitizationAndProhibitedKeyStripping) {
    SecurityEventContext ctx;
    ctx.verified_peer_identity = "auth.securecloud.internal";
    ctx.rpc_method = "SubmitAuditEvent";
    ctx.metadata["auth_token"] = "secret_bearer_123";
    ctx.metadata["error_code"] = "INVALID_PAYLOAD";

    auto event = factory_.create_event(InternalSecurityEventType::SensitiveDataDetected, ctx);

    EXPECT_EQ(event.metadata.count("auth_token"), 0);
    EXPECT_EQ(event.metadata.at("error_code"), "INVALID_PAYLOAD");
    EXPECT_EQ(event.metadata.at("rpc_method"), "SubmitAuditEvent");

    auto validation_res = validator_.validate(event);
    EXPECT_TRUE(validation_res.is_valid());
}

} // namespace securecloud::audit::security::testing
