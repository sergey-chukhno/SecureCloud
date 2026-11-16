#include "auth/domain/audit_event.hpp"
#include "auth/domain/auth_outbox_entity.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/outbox_event_mapper.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

namespace securecloud::auth::service::test {
namespace {

using domain::AuditEvent;
using domain::AuthOutboxEntity;
using domain::OutboxSeverity;
using domain::OutboxStatus;
using domain::Uuid;

TEST(OutboxEventMapperTest, ToOutboxEntity_LoginSucceeded_MapsUserActorAndMetadata) {
    const Uuid user_id = Uuid::generate_v7();
    const Uuid device_id = Uuid::generate_v7();
    const Uuid session_id = Uuid::generate_v7();

    const AuditEvent event =
        AuditEvent::login_succeeded(user_id, "alice@securecloud.io", device_id, session_id, "198.51.100.42");

    const AuthOutboxEntity entity = OutboxEventMapper::to_outbox_entity(event, "auth-node-01");

    EXPECT_EQ(entity.event_id, event.event_id);
    EXPECT_EQ(entity.aggregate_type, "USER");
    ASSERT_TRUE(entity.aggregate_id.has_value());
    EXPECT_EQ(*entity.aggregate_id, user_id);
    EXPECT_EQ(entity.event_type, "auth.login.succeeded");
    EXPECT_EQ(entity.severity, OutboxSeverity::Info);
    EXPECT_EQ(entity.status, OutboxStatus::Pending);
    EXPECT_EQ(entity.retry_count, 0);

    const nlohmann::json j = nlohmann::json::parse(entity.payload_json);
    EXPECT_EQ(j.at("event_id"), event.event_id.to_string());
    EXPECT_EQ(j.at("event_type"), "auth.login.succeeded");
    EXPECT_EQ(j.at("severity"), "INFO");
    EXPECT_EQ(j.at("producer_service"), "AUTH");
    EXPECT_EQ(j.at("producer_instance"), "auth-node-01");
    EXPECT_EQ(j.at("actor_type"), "USER");
    EXPECT_EQ(j.at("actor_id"), user_id.to_string());
    EXPECT_EQ(j.at("target_type"), "USER");
    EXPECT_EQ(j.at("target_id"), user_id.to_string());
    EXPECT_EQ(j.at("correlation_id"), session_id.to_string());

    const auto& meta = j.at("metadata");
    EXPECT_EQ(meta.at("client_ip"), "198.51.100.42");
    EXPECT_EQ(meta.at("credential_identifier"), "alice@securecloud.io");
    EXPECT_EQ(meta.at("user_id"), user_id.to_string());
    EXPECT_EQ(meta.at("device_id"), device_id.to_string());
    EXPECT_EQ(meta.at("session_id"), session_id.to_string());
}

TEST(OutboxEventMapperTest, ToOutboxEntity_DeviceRevoked_SetsDeviceAggregateAndWarningSeverity) {
    const Uuid user_id = Uuid::generate_v7();
    const Uuid device_id = Uuid::generate_v7();

    const AuditEvent event = AuditEvent::device_revoked(user_id, device_id, "compromised_device", "10.20.30.40");
    const AuthOutboxEntity entity = OutboxEventMapper::to_outbox_entity(event);

    EXPECT_EQ(entity.aggregate_type, "DEVICE");
    ASSERT_TRUE(entity.aggregate_id.has_value());
    EXPECT_EQ(*entity.aggregate_id, device_id);
    EXPECT_EQ(entity.event_type, "auth.device.revoked");
    EXPECT_EQ(entity.severity, OutboxSeverity::Warning);

    const nlohmann::json j = nlohmann::json::parse(entity.payload_json);
    EXPECT_EQ(j.at("actor_type"), "USER");
    EXPECT_EQ(j.at("actor_id"), user_id.to_string());
    EXPECT_EQ(j.at("target_type"), "DEVICE");
    EXPECT_EQ(j.at("target_id"), device_id.to_string());
    EXPECT_EQ(j.at("metadata").at("failure_reason"), "compromised_device");
}

TEST(OutboxEventMapperTest, ToOutboxEntity_TokenReuseDetected_MapsToCriticalSeverityAndDeviceActor) {
    const Uuid session_id = Uuid::generate_v7();
    const Uuid device_id = Uuid::generate_v7();

    const AuditEvent event = AuditEvent::token_reuse_detected(session_id, device_id, "203.0.113.99");
    const AuthOutboxEntity entity = OutboxEventMapper::to_outbox_entity(event);

    EXPECT_EQ(entity.severity, OutboxSeverity::Critical);
    EXPECT_EQ(entity.event_type, "auth.token.reuse_detected");
    EXPECT_EQ(entity.aggregate_type, "DEVICE");
    ASSERT_TRUE(entity.aggregate_id.has_value());
    EXPECT_EQ(*entity.aggregate_id, device_id);

    const nlohmann::json j = nlohmann::json::parse(entity.payload_json);
    EXPECT_EQ(j.at("actor_type"), "DEVICE");
    EXPECT_EQ(j.at("actor_id"), device_id.to_string());
    EXPECT_EQ(j.at("target_type"), "DEVICE");
    EXPECT_EQ(j.at("target_id"), device_id.to_string());
    EXPECT_EQ(j.at("correlation_id"), session_id.to_string());
}

TEST(OutboxEventMapperTest, ToOutboxEntity_NilEventIdAndUnknownActor_GeneratesUuidV7AndSystemActor) {
    AuditEvent event = AuditEvent::login_failed("bob@securecloud.io", "invalid_password");
    event.event_id = Uuid{}; // nil UUID

    const AuthOutboxEntity entity = OutboxEventMapper::to_outbox_entity(event);

    EXPECT_FALSE(entity.event_id.is_nil());
    EXPECT_EQ(entity.severity, OutboxSeverity::Warning);
    EXPECT_EQ(entity.aggregate_type, "AUTH");
    EXPECT_FALSE(entity.aggregate_id.has_value());

    const nlohmann::json j = nlohmann::json::parse(entity.payload_json);
    EXPECT_EQ(j.at("actor_type"), "SYSTEM");
    EXPECT_EQ(j.at("actor_id"), "bob@securecloud.io");
    EXPECT_EQ(j.at("metadata").at("failure_reason"), "invalid_password");
}

TEST(OutboxEventMapperTest, RoundTrip_ToOutboxEntityThenToAuditProto_PreservesAllFields) {
    const Uuid user_id = Uuid::generate_v7();
    const Uuid device_id = Uuid::generate_v7();

    const AuditEvent event = AuditEvent::prekey_inventory_exhausted(user_id, device_id, "192.0.2.15");
    const AuthOutboxEntity entity = OutboxEventMapper::to_outbox_entity(event, "auth-eu-1");
    const auto proto = OutboxEventMapper::to_audit_proto(entity);

    EXPECT_EQ(proto.event_id(), event.event_id.to_string());
    EXPECT_EQ(proto.event_type(), "auth.device.prekey_inventory_exhausted");
    EXPECT_EQ(proto.severity(), securecloud::audit::v1::SEVERITY_SECURITY);
    EXPECT_EQ(proto.producer_service(), securecloud::audit::v1::PRODUCER_SERVICE_AUTH);
    EXPECT_EQ(proto.producer_instance(), "auth-eu-1");
    EXPECT_EQ(proto.actor_type(), securecloud::audit::v1::ACTOR_TYPE_USER);
    EXPECT_EQ(proto.actor_id(), user_id.to_string());
    EXPECT_EQ(proto.target_type(), securecloud::audit::v1::TARGET_TYPE_DEVICE);
    EXPECT_EQ(proto.target_id(), device_id.to_string());
    EXPECT_EQ(proto.metadata().at("client_ip"), "192.0.2.15");
    EXPECT_EQ(proto.metadata().at("failure_reason"), "REMAINING_COUNT=0");
}

TEST(OutboxEventMapperTest, ToAuditProto_MapsAllFieldsSeveritiesActorsTargetsAndMetadata) {
    const Uuid eid = Uuid::generate_v7();
    const Uuid actor_id = Uuid::generate_v7();
    const Uuid target_id = Uuid::generate_v7();
    const int64_t occurred_ms = 1794512880123LL;

    nlohmann::json payload = {
        {"event_id", eid.to_string()},
        {"occurred_at_ms", occurred_ms},
        {"event_type", "auth.token.reuse_detected"},
        {"severity", "CRITICAL"},
        {"producer_service", "AUTH"},
        {"producer_instance", "auth-eu-west-1"},
        {"actor_type", "DEVICE"},
        {"actor_id", actor_id.to_string()},
        {"target_type", "USER"},
        {"target_id", target_id.to_string()},
        {"correlation_id", "req-9988"},
        {"causation_id", "evt-1122"},
        {"metadata", {{"client_ip", "203.0.113.10"}, {"attempt_count", 3}}},
    };

    AuthOutboxEntity entity;
    entity.event_id = eid;
    entity.aggregate_type = "USER";
    entity.aggregate_id = target_id;
    entity.event_type = "auth.token.reuse_detected";
    entity.severity = OutboxSeverity::Critical;
    entity.payload_json = payload.dump();
    entity.status = OutboxStatus::Pending;

    const auto proto = OutboxEventMapper::to_audit_proto(entity);

    EXPECT_EQ(proto.event_id(), eid.to_string());
    EXPECT_EQ(proto.occurred_at_ms(), occurred_ms);
    EXPECT_EQ(proto.event_type(), "auth.token.reuse_detected");
    EXPECT_EQ(proto.severity(), securecloud::audit::v1::SEVERITY_CRITICAL);
    EXPECT_EQ(proto.producer_service(), securecloud::audit::v1::PRODUCER_SERVICE_AUTH);
    EXPECT_EQ(proto.producer_instance(), "auth-eu-west-1");
    EXPECT_EQ(proto.actor_type(), securecloud::audit::v1::ACTOR_TYPE_DEVICE);
    EXPECT_EQ(proto.actor_id(), actor_id.to_string());
    EXPECT_EQ(proto.target_type(), securecloud::audit::v1::TARGET_TYPE_USER);
    EXPECT_EQ(proto.target_id(), target_id.to_string());
    EXPECT_EQ(proto.correlation_id(), "req-9988");
    EXPECT_EQ(proto.causation_id(), "evt-1122");
    ASSERT_EQ(proto.metadata().size(), 2u);
    EXPECT_EQ(proto.metadata().at("client_ip"), "203.0.113.10");
    EXPECT_EQ(proto.metadata().at("attempt_count"), "3");
}

TEST(OutboxEventMapperTest, ToAuditProto_ThrowsOnMalformedJsonOrMissingTimestamp) {
    AuthOutboxEntity bad_json;
    bad_json.event_id = Uuid::generate_v7();
    bad_json.payload_json = "{broken";
    EXPECT_THROW((void)OutboxEventMapper::to_audit_proto(bad_json), std::exception);

    AuthOutboxEntity missing_ts;
    missing_ts.event_id = Uuid::generate_v7();
    missing_ts.payload_json = R"({"event_type":"auth.login.succeeded"})";
    EXPECT_THROW((void)OutboxEventMapper::to_audit_proto(missing_ts), std::exception);
}

} // namespace
} // namespace securecloud::auth::service::test
