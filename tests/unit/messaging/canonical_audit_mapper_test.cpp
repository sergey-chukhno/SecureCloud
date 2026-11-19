#include "audit/canonical_audit_mapper.hpp"
#include "messaging/repository/messaging_audit_outbox_repository_interface.hpp"
#include "securecloud/audit/v1/audit.pb.h"

#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::messaging::audit::test {

using securecloud::audit::v1::ACTOR_TYPE_DEVICE;
using securecloud::audit::v1::ACTOR_TYPE_USER;
using securecloud::audit::v1::AuditEventProto;
using securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING;
using securecloud::audit::v1::SEVERITY_CRITICAL;
using securecloud::audit::v1::SEVERITY_INFO;
using securecloud::audit::v1::SEVERITY_UNSPECIFIED;
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

TEST_F(CanonicalAuditMapperTest, MapsSeveritiesCorrectly) {
    auto record = create_base_record();

    record.severity = "CRITICAL";
    EXPECT_EQ(map_outbox_record_to_canonical_proto(record)->severity(), SEVERITY_CRITICAL);

    record.severity = "UNKNOWN_SEV";
    EXPECT_EQ(map_outbox_record_to_canonical_proto(record)->severity(), SEVERITY_UNSPECIFIED);
}

} // namespace securecloud::messaging::audit::test