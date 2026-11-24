#include "audit/canonical_audit_mapper.hpp"
#include "domain/audit_event.hpp"
#include "domain/audit_event_id.hpp"
#include "messaging/repository/messaging_audit_outbox_repository_interface.hpp"
#include "securecloud/audit/v1/audit.pb.h"

#include <chrono>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace securecloud::messaging::audit::test {

using securecloud::audit::v1::ACTOR_TYPE_DEVICE;
using securecloud::audit::v1::ACTOR_TYPE_SYSTEM;
using securecloud::audit::v1::ACTOR_TYPE_USER;
using securecloud::audit::v1::AuditEventProto;
using securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING;
using securecloud::audit::v1::SEVERITY_CRITICAL;
using securecloud::audit::v1::SEVERITY_INFO;
using securecloud::audit::v1::SEVERITY_SECURITY;
using securecloud::audit::v1::TARGET_TYPE_CONVERSATION;

class CanonicalAuditMapperTest : public ::testing::Test {
  protected:
    repository::AuditOutboxRecord create_base_record() {
        repository::AuditOutboxRecord record;
        record.event_id = "018d0000-0000-7000-8000-000000000001";
        record.event_type = "message.submitted";
        record.severity = "INFO";
        record.created_at = std::chrono::system_clock::now();
        record.actor_user_id = "user-123";
        record.target_resource = "conv-456";
        return record;
    }
};

TEST_F(CanonicalAuditMapperTest, MapsValidRecordWithJsonPayloadCorrectly) {
    auto record = create_base_record();
    std::string json_payload = R"({"priority": "high", "size": 1024, "is_encrypted": true})";
    record.payload_proto_bin = std::vector<uint8_t>(json_payload.begin(), json_payload.end());

    auto result = map_outbox_record_to_canonical_proto(record);
    ASSERT_TRUE(result.has_value());

    // 1. Verify Core Event Data
    EXPECT_EQ(result->event_id(), "018d0000-0000-7000-8000-000000000001");
    EXPECT_EQ(result->event_type(), "message.submitted");
    EXPECT_EQ(result->severity(), SEVERITY_INFO);
    EXPECT_EQ(result->producer_service(), PRODUCER_SERVICE_MESSAGING);
    EXPECT_GT(result->occurred_at_ms(), 0);

    // 2. Verify Routing
    EXPECT_EQ(result->actor_type(), ACTOR_TYPE_USER);
    EXPECT_EQ(result->actor_id(), "user-123");
    EXPECT_EQ(result->target_type(), TARGET_TYPE_CONVERSATION);
    EXPECT_EQ(result->target_id(), "conv-456");

    // 3. Verify JSON Metadata mapping
    const auto& metadata = result->metadata();
    ASSERT_EQ(metadata.size(), 3);
    EXPECT_EQ(metadata.at("priority"), "high");
    EXPECT_EQ(metadata.at("size"), "1024"); // nlohmann dumps non-strings as strings
    EXPECT_EQ(metadata.at("is_encrypted"), "true");
}

TEST_F(CanonicalAuditMapperTest, ReturnsNulloptOnMalformedJson) {
    auto record = create_base_record();
    std::string bad_json = "{ malformed_json: ";
    record.payload_proto_bin = std::vector<uint8_t>(bad_json.begin(), bad_json.end());

    auto result = map_outbox_record_to_canonical_proto(record);

    // Should fail gracefully and invalidate canonical compliance
    EXPECT_FALSE(result.has_value());
}

TEST_F(CanonicalAuditMapperTest, MapsActorDeviceIfUserIdIsEmpty) {
    auto record = create_base_record();
    record.actor_user_id = ""; // No user ID
    record.actor_device_id = "device-888";

    auto result = map_outbox_record_to_canonical_proto(record);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->actor_type(), ACTOR_TYPE_DEVICE);
    EXPECT_EQ(result->actor_id(), "device-888");
}

TEST_F(CanonicalAuditMapperTest, MapsSeveritiesStrictlyAndRejectsUnknownSeverity) {
    auto record = create_base_record();

    record.severity = "CRITICAL";
    const auto crit = map_outbox_record_to_canonical_proto(record);
    ASSERT_TRUE(crit.has_value());
    EXPECT_EQ(crit->severity(), SEVERITY_CRITICAL);

    record.severity = "SECURITY";
    const auto sec = map_outbox_record_to_canonical_proto(record);
    ASSERT_TRUE(sec.has_value());
    EXPECT_EQ(sec->severity(), SEVERITY_SECURITY);

    record.severity = "UNKNOWN_SEV";
    EXPECT_FALSE(map_outbox_record_to_canonical_proto(record).has_value());

    record.severity = "";
    EXPECT_FALSE(map_outbox_record_to_canonical_proto(record).has_value());
}

TEST_F(CanonicalAuditMapperTest, ReturnsNulloptOnInvalidUuidV7OrForbiddenSecret) {
    auto bad_id = create_base_record();
    bad_id.event_id = "not-a-uuid-v7";
    EXPECT_FALSE(map_outbox_record_to_canonical_proto(bad_id).has_value());

    auto secret_payload = create_base_record();
    const std::string raw = R"({"ciphertext":"deadbeef01020304"})";
    secret_payload.payload_proto_bin.assign(raw.begin(), raw.end());
    EXPECT_FALSE(map_outbox_record_to_canonical_proto(secret_payload).has_value());
}

TEST_F(CanonicalAuditMapperTest, MapsEmptyActorToSystem) {
    auto record = create_base_record();
    record.actor_user_id.clear();
    record.actor_device_id.clear();

    const auto result = map_outbox_record_to_canonical_proto(record);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->actor_type(), ACTOR_TYPE_SYSTEM);
    EXPECT_EQ(result->actor_id(), "messaging-service");
}

TEST_F(CanonicalAuditMapperTest, BuildCanonicalOutboxRecordProducesValidBucketShardAndWireProto) {
    const auto now = std::chrono::system_clock::now();
    domain::MessagingAuditEvent event{
        .event_id = domain::generate_audit_event_id(),
        .event_type = domain::MessagingAuditEventType::MessageSubmitted,
        .severity = domain::MessagingAuditSeverity::Info,
        .occurred_at = now,
        .actor_user_id = domain::UserId("user-123"),
        .actor_device_id = domain::DeviceId("dev-999"),
        .target_resource = "msg-777",
        .payload_json = R"({"sequence":42,"recipient_device_count":2})",
        .correlation_id = "01930000-0000-7000-8000-0000000000ab",
    };

    const auto rec = build_canonical_outbox_record(event, "conv-123", "messaging-01");
    EXPECT_EQ(rec.outbox_bucket, domain::compute_outbox_bucket_utc(now));
    EXPECT_EQ(rec.outbox_bucket.size(), 10U);
    EXPECT_EQ(rec.shard_id, domain::compute_outbox_shard_id("conv-123"));
    EXPECT_EQ(rec.publish_status, "PENDING");
    ASSERT_FALSE(rec.payload_proto_bin.empty());

    AuditEventProto parsed;
    ASSERT_TRUE(parsed.ParseFromArray(rec.payload_proto_bin.data(), static_cast<int>(rec.payload_proto_bin.size())));
    EXPECT_EQ(parsed.event_id(), event.event_id);
    EXPECT_EQ(parsed.producer_service(), PRODUCER_SERVICE_MESSAGING);
    EXPECT_EQ(parsed.producer_instance(), "messaging-01");
    EXPECT_EQ(parsed.correlation_id(), "01930000-0000-7000-8000-0000000000ab");
    EXPECT_EQ(parsed.actor_type(), ACTOR_TYPE_USER);
    EXPECT_EQ(parsed.actor_id(), "user-123");
    EXPECT_EQ(parsed.metadata().at("actor_device_id"), "dev-999");
    EXPECT_EQ(parsed.metadata().at("sequence"), "42");
    EXPECT_EQ(parsed.metadata().at("recipient_device_count"), "2");
}

} // namespace securecloud::messaging::audit::test