#include "domain/audit_event_validator.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::domain::test {

namespace {

AuditEvent create_valid_event() {
    AuditEvent event;
    event.event_id = EventId::generate_v7();
    event.occurred_at = std::chrono::system_clock::now();
    event.event_type = "auth.login.success";
    event.severity = Severity::Info;
    event.producer_service = ProducerService::Auth;
    event.producer_instance = "auth-pod-1";
    event.actor_type = ActorType::User;
    event.actor_id = "user_12345";
    event.target_type = TargetType::Device;
    event.target_id = "device_67890";
    event.correlation_id = "corr-abc-123";
    event.metadata["ip_address"] = "192.168.1.10";
    return event;
}

} // namespace

TEST(AuditEventValidatorTest, ValidEventPasses) {
    const std::array<ProducerService, 5> producers = {ProducerService::Gateway, ProducerService::Auth,
                                                      ProducerService::Messaging, ProducerService::Files,
                                                      ProducerService::Audit};

    for (auto prod : producers) {
        auto event = create_valid_event();
        event.producer_service = prod;
        auto res = AuditEventValidator::validate(event);
        EXPECT_TRUE(res.is_valid()) << "Failed for producer " << static_cast<int>(prod);
    }
}

TEST(AuditEventValidatorTest, MissingRequiredFieldsFails) {
    // Missing event_id (nil)
    {
        auto event = create_valid_event();
        event.event_id = EventId{};
        auto res = AuditEventValidator::validate(event);
        EXPECT_FALSE(res.is_valid());
    }
    // Invalid event_type format
    {
        auto event = create_valid_event();
        event.event_type = "";
        auto res = AuditEventValidator::validate(event);
        EXPECT_FALSE(res.is_valid());
    }
    // Missing actor_type when actor_id is present
    {
        auto event = create_valid_event();
        event.actor_type = ActorType::Unknown;
        auto res = AuditEventValidator::validate(event);
        EXPECT_FALSE(res.is_valid());
    }
}

TEST(AuditEventValidatorTest, MalformedUuidFails) {
    EXPECT_FALSE(EventId::from_string("invalid-uuid-string").has_value());
    EXPECT_FALSE(EventId::from_string("00000000-0000-0000-0000-000000000000").has_value()); // Nil/v0
}

TEST(AuditEventValidatorTest, NonUuidV7Fails) {
    // Generate UUIDv4 manually (version 4, variant 2)
    EventId::bytes_type v4_bytes{};
    v4_bytes[6] = 0x40; // version 4
    v4_bytes[8] = 0x80; // variant 2
    EventId v4_id(v4_bytes);

    auto event = create_valid_event();
    event.event_id = v4_id;

    auto res = AuditEventValidator::validate(event);
    EXPECT_FALSE(res.is_valid());

    bool found_v7_err = false;
    for (const auto& err : res.errors()) {
        if (err.code == AuditValidationErrorCode::EventIdNotUuidV7) {
            found_v7_err = true;
            break;
        }
    }
    EXPECT_TRUE(found_v7_err);
}

TEST(AuditEventValidatorTest, FutureClockSkewFails) {
    auto now = std::chrono::system_clock::now();
    AuditEventValidationLimits limits;

    // 10 minutes in the future -> rejected
    {
        auto event = create_valid_event();
        event.occurred_at = now + std::chrono::minutes(10);
        auto res = AuditEventValidator::validate(event, limits, now);
        EXPECT_FALSE(res.is_valid());
    }
    // 2 minutes in the future -> accepted (under 5 min limit)
    {
        auto event = create_valid_event();
        event.occurred_at = now + std::chrono::minutes(2);
        auto res = AuditEventValidator::validate(event, limits, now);
        EXPECT_TRUE(res.is_valid());
    }
}

TEST(AuditEventValidatorTest, ExpiredTimestampFails) {
    auto now = std::chrono::system_clock::now();
    AuditEventValidationLimits limits;

    auto event = create_valid_event();
    event.occurred_at = now - std::chrono::hours(24 * 400); // 400 days old

    auto res = AuditEventValidator::validate(event, limits, now);
    EXPECT_FALSE(res.is_valid());
}

TEST(AuditEventValidatorTest, ReceivedAtIntegrity) {
    auto now = std::chrono::system_clock::now();

    auto event = create_valid_event();
    event.occurred_at = now;
    event.received_at = now - std::chrono::minutes(10); // Received 10 min before occurred_at

    auto res = AuditEventValidator::validate(event);
    EXPECT_FALSE(res.is_valid());
}

TEST(AuditEventValidatorTest, MetadataCountLimitEnforced) {
    AuditEventValidationLimits limits;
    limits.max_metadata_entries = 50;

    // Exactly 50 entries
    {
        auto event = create_valid_event();
        event.metadata.clear();
        for (size_t i = 0; i < 50; ++i) {
            event.metadata["key_" + std::to_string(i)] = "val";
        }
        auto res = AuditEventValidator::validate(event, limits);
        EXPECT_TRUE(res.is_valid());
    }
    // 51 entries
    {
        auto event = create_valid_event();
        event.metadata.clear();
        for (size_t i = 0; i < 51; ++i) {
            event.metadata["key_" + std::to_string(i)] = "val";
        }
        auto res = AuditEventValidator::validate(event, limits);
        EXPECT_FALSE(res.is_valid());
    }
}

TEST(AuditEventValidatorTest, MetadataKeyValidation) {
    // Invalid characters (spaces)
    {
        auto event = create_valid_event();
        event.metadata["invalid key"] = "val";
        auto res = AuditEventValidator::validate(event);
        EXPECT_FALSE(res.is_valid());
    }
    // Valid key characters (a-z, A-Z, 0-9, _, ., -)
    {
        auto event = create_valid_event();
        event.metadata["valid_key.123-abc"] = "val";
        auto res = AuditEventValidator::validate(event);
        EXPECT_TRUE(res.is_valid());
    }
}

TEST(AuditEventValidatorTest, MetadataValueSizeEnforced) {
    AuditEventValidationLimits limits;
    limits.max_metadata_value_length = 1024;

    // 1024 bytes -> valid
    {
        auto event = create_valid_event();
        event.metadata["key"] = std::string(1024, 'x');
        auto res = AuditEventValidator::validate(event, limits);
        EXPECT_TRUE(res.is_valid());
    }
    // 1025 bytes -> rejected
    {
        auto event = create_valid_event();
        event.metadata["key"] = std::string(1025, 'x');
        auto res = AuditEventValidator::validate(event, limits);
        EXPECT_FALSE(res.is_valid());
    }
}

TEST(AuditEventValidatorTest, TotalPayloadBoundEnforced) {
    AuditEventValidationLimits limits;
    limits.max_event_size_bytes = 1024; // Low bound for test

    auto event = create_valid_event();
    event.metadata["large_field"] = std::string(2000, 'a');

    auto res = AuditEventValidator::validate(event, limits);
    EXPECT_FALSE(res.is_valid());
}

} // namespace securecloud::audit::domain::test