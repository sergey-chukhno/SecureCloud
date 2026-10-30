#include "repository/clickhouse_event_serializer.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <string>

using namespace std::string_literals;

namespace securecloud::audit::repository::testing {

TEST(ClickHouseEventSerializerTest, EscapeSpecialCharacters) {
    auto input = "Tab\tNewline\nNull\0Backslash\\Quote\"End"s;
    std::string escaped = ClickHouseEventSerializer::escape_tab_separated(input);

    EXPECT_NE(escaped.find("\\t"), std::string::npos);
    EXPECT_NE(escaped.find("\\n"), std::string::npos);
    EXPECT_NE(escaped.find("\\0"), std::string::npos);
    EXPECT_NE(escaped.find("\\\\"), std::string::npos);
}

TEST(ClickHouseEventSerializerTest, TimestampFormattingAndParsingRoundTrip) {
    using namespace std::chrono;
    auto now = time_point_cast<milliseconds>(system_clock::now());

    std::string formatted = ClickHouseEventSerializer::format_timestamp_ms(now);
    EXPECT_FALSE(formatted.empty());

    auto parsed = ClickHouseEventSerializer::parse_timestamp_ms(formatted);
    auto parsed_ms = time_point_cast<milliseconds>(parsed);

    EXPECT_EQ(now, parsed_ms);
}

TEST(ClickHouseEventSerializerTest, EmptyBatchSerialization) {
    std::vector<domain::AuditEvent> empty_events;
    std::string serialized = ClickHouseEventSerializer::serialize_for_insert(empty_events);

    EXPECT_TRUE(serialized.empty());
}

TEST(ClickHouseEventSerializerTest, RoundTripSerializationDeserialization) {
    domain::AuditEvent event{};
    event.event_id = domain::EventId::generate_v7();
    event.occurred_at = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    event.received_at = event.occurred_at;
    event.event_type = "user.login";
    event.severity = domain::Severity::Info;
    event.producer_service = domain::ProducerService::Audit;
    event.producer_instance = "audit-node-01";
    event.actor_type = domain::ActorType::User;
    event.actor_id = "user-123";
    event.target_type = domain::TargetType::Unknown;
    event.target_id = "system-456";
    event.correlation_id = domain::EventId::generate_v7().to_string();
    event.causation_id = domain::EventId::generate_v7().to_string();
    event.metadata = {{"ip", "192.168.1.1"}, {"session", "abc"}};

    std::vector<domain::AuditEvent> original_events{event};
    std::string serialized = ClickHouseEventSerializer::serialize_for_insert(original_events);
    EXPECT_FALSE(serialized.empty());

    std::vector<domain::AuditEvent> deserialized = ClickHouseEventSerializer::deserialize_from_query(serialized);
    ASSERT_EQ(deserialized.size(), std::size_t{1});

    const auto& restored = deserialized.front();
    EXPECT_EQ(restored.event_id, event.event_id);
    EXPECT_EQ(restored.event_type, event.event_type);
    EXPECT_EQ(restored.actor_id, event.actor_id);
    EXPECT_EQ(restored.target_id, event.target_id);
    EXPECT_EQ(restored.correlation_id, event.correlation_id);
    EXPECT_EQ(restored.causation_id, event.causation_id);
    EXPECT_EQ(restored.metadata, event.metadata);
}

} // namespace securecloud::audit::repository::testing