#include "auth/audit/auth_audit_mapper.hpp"
#include "auth/auth_config.hpp"
#include "auth/domain/audit_event.hpp"
#include "auth/domain/auth_outbox_entity.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/outbox_event_mapper.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

namespace securecloud::auth::audit::test {
namespace {

using domain::AuditEvent;
using domain::AuthOutboxEntity;
using domain::Uuid;

AuthOutboxEntity make_valid_entity() {
    const Uuid uid = Uuid::generate_v7();
    const Uuid did = Uuid::generate_v7();
    const Uuid sid = Uuid::generate_v7();
    const AuditEvent ev = AuditEvent::login_succeeded(uid, "alice@securecloud.io", did, sid, "198.51.100.7");
    return service::OutboxEventMapper::to_outbox_entity(ev);
}

TEST(AuthAuditMapperTest, Map_ValidOutboxEntity_ProducesCompliantAuditEventProto) {
    AuthConfig cfg;
    cfg.common.service_name = "auth-prod-eu1";

    AuthAuditMapper mapper(cfg);
    const AuthOutboxEntity entity = make_valid_entity();

    const auto proto = mapper.map(entity);

    EXPECT_EQ(proto.event_id(), entity.event_id.to_string());
    EXPECT_EQ(proto.event_type(), "auth.login.succeeded");
    EXPECT_EQ(proto.severity(), ::securecloud::audit::v1::SEVERITY_INFO);
    EXPECT_EQ(proto.producer_service(), ::securecloud::audit::v1::PRODUCER_SERVICE_AUTH);
    EXPECT_EQ(proto.producer_instance(), "auth-prod-eu1");
    EXPECT_EQ(proto.actor_type(), ::securecloud::audit::v1::ACTOR_TYPE_USER);
    EXPECT_EQ(proto.target_type(), ::securecloud::audit::v1::TARGET_TYPE_USER);
    EXPECT_FALSE(proto.correlation_id().empty());

    // `credential_identifier` is normalized to `account_identifier` for SensitiveDataGuard compatibility
    EXPECT_FALSE(proto.metadata().contains("credential_identifier"));
    EXPECT_EQ(proto.metadata().at("account_identifier"), "alice@securecloud.io");
    EXPECT_EQ(proto.metadata().at("client_ip"), "198.51.100.7");
}

TEST(AuthAuditMapperTest, Map_SanitizesSecretKeysAndRedactsSecretValuesInMetadata) {
    AuthOutboxEntity entity = make_valid_entity();
    nlohmann::json j = nlohmann::json::parse(entity.payload_json);
    j["metadata"]["password"] = "S3cr3tP@ss!";
    j["metadata"]["refresh_token"] = "rt_live_999888";
    j["metadata"]["private_key"] = "-----BEGIN PRIVATE KEY-----";
    j["metadata"]["totp_secret"] = "JBSWY3DPEHPK3PXP";
    j["metadata"]["api_key"] = "sk_live_12345";
    j["metadata"]["credential_blob"] = "raw_secret_blob";
    j["metadata"]["jwt_in_reason"] =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    j["metadata"]["auth_header"] = "Bearer abcdef123456";
    j["metadata"]["safe_field"] = "ok_value";
    entity.payload_json = j.dump();

    AuthAuditMapper mapper("auth-1");
    const auto proto = mapper.map(entity);

    EXPECT_FALSE(proto.metadata().contains("password"));
    EXPECT_FALSE(proto.metadata().contains("refresh_token"));
    EXPECT_FALSE(proto.metadata().contains("private_key"));
    EXPECT_FALSE(proto.metadata().contains("totp_secret"));
    EXPECT_FALSE(proto.metadata().contains("api_key"));
    EXPECT_FALSE(proto.metadata().contains("credential_blob"));

    EXPECT_EQ(proto.metadata().at("jwt_in_reason"), "[REDACTED]");
    EXPECT_EQ(proto.metadata().at("auth_header"), "[REDACTED]");
    EXPECT_EQ(proto.metadata().at("safe_field"), "ok_value");
}

TEST(AuthAuditMapperTest, Map_RejectsNonUuidV7EventId) {
    AuthOutboxEntity entity = make_valid_entity();
    nlohmann::json j = nlohmann::json::parse(entity.payload_json);
    // UUIDv4 (version nibble '4' instead of '7')
    j["event_id"] = "550e8400-e29b-41d4-a716-446655440000";
    entity.payload_json = j.dump();

    AuthAuditMapper mapper;
    EXPECT_THROW((void)mapper.map(entity), std::invalid_argument);
}

TEST(AuthAuditMapperTest, Map_RejectsOccurredAtOutsideClockSkewAndRetentionBounds) {
    AuthAuditMapper mapper;

    // 1. Future skew > 300s (5 min)
    {
        AuthOutboxEntity future_entity = make_valid_entity();
        nlohmann::json j_future = nlohmann::json::parse(future_entity.payload_json);
        const auto too_far_future_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                (std::chrono::system_clock::now() + std::chrono::minutes(10)).time_since_epoch())
                .count();
        j_future["occurred_at_ms"] = too_far_future_ms;
        future_entity.payload_json = j_future.dump();

        EXPECT_THROW((void)mapper.map(future_entity), std::invalid_argument);
    }

    // 2. Past age > 36 months (1,095 days)
    {
        AuthOutboxEntity expired_entity = make_valid_entity();
        nlohmann::json j_past = nlohmann::json::parse(expired_entity.payload_json);
        const auto too_old_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                (std::chrono::system_clock::now() - std::chrono::hours(24 * 1100)).time_since_epoch())
                .count();
        j_past["occurred_at_ms"] = too_old_ms;
        expired_entity.payload_json = j_past.dump();

        EXPECT_THROW((void)mapper.map(expired_entity), std::invalid_argument);
    }
}

TEST(AuthAuditMapperTest, Map_EnforcesAuditEventValidationLimitsAndNamespace) {
    AuthAuditMapper mapper;

    // 1. Wrong service namespace
    {
        AuthOutboxEntity entity = make_valid_entity();
        nlohmann::json j = nlohmann::json::parse(entity.payload_json);
        j["event_type"] = "gateway.request.denied";
        entity.payload_json = j.dump();
        EXPECT_THROW((void)mapper.map(entity), std::invalid_argument);
    }

    // 2. event_type exceeding 64 characters
    {
        AuthOutboxEntity entity = make_valid_entity();
        nlohmann::json j = nlohmann::json::parse(entity.payload_json);
        j["event_type"] = "auth." + std::string(65, 'a');
        entity.payload_json = j.dump();
        EXPECT_THROW((void)mapper.map(entity), std::invalid_argument);
    }

    // 3. actor_id exceeding 128 characters
    {
        AuthOutboxEntity entity = make_valid_entity();
        nlohmann::json j = nlohmann::json::parse(entity.payload_json);
        j["actor_id"] = std::string(129, 'x');
        entity.payload_json = j.dump();
        EXPECT_THROW((void)mapper.map(entity), std::invalid_argument);
    }

    // 4. correlation_id exceeding 64 characters
    {
        AuthOutboxEntity entity = make_valid_entity();
        nlohmann::json j = nlohmann::json::parse(entity.payload_json);
        j["correlation_id"] = std::string(65, 'c');
        entity.payload_json = j.dump();
        EXPECT_THROW((void)mapper.map(entity), std::invalid_argument);
    }
}

} // namespace
} // namespace securecloud::auth::audit::test
