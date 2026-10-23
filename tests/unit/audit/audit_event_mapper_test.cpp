#include "domain/audit_event_mapper.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::domain::test {

TEST(AuditEventMapperTest, BidirectionalProtoDomainConversion) {
    AuditEvent original{};
    original.event_id = EventId::generate_v7();
    original.occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1700000000000ULL));
    original.event_type = "files.download.completed";
    original.severity = Severity::Security;
    original.producer_service = ProducerService::Files;
    original.producer_instance = "files-node-A";
    original.actor_type = ActorType::User;
    original.actor_id = "usr_999";
    original.target_type = TargetType::File;
    original.target_id = "file_888";
    original.correlation_id = "corr_777";
    original.causation_id = "caus_666";
    original.metadata["bytes"] = "1048576";

    // Domain -> Proto
    auto proto = AuditEventMapper::to_proto(original);

    EXPECT_EQ(proto.event_id(), original.event_id.to_string());
    EXPECT_EQ(proto.occurred_at_ms(), 1700000000000ULL);
    EXPECT_EQ(proto.event_type(), "files.download.completed");
    EXPECT_EQ(proto.severity(), securecloud::audit::v1::SEVERITY_SECURITY);
    EXPECT_EQ(proto.producer_service(), securecloud::audit::v1::PRODUCER_SERVICE_FILES);
    EXPECT_EQ(proto.producer_instance(), "files-node-A");
    EXPECT_EQ(proto.actor_type(), securecloud::audit::v1::ACTOR_TYPE_USER);
    EXPECT_EQ(proto.actor_id(), "usr_999");
    EXPECT_EQ(proto.target_type(), securecloud::audit::v1::TARGET_TYPE_FILE);
    EXPECT_EQ(proto.target_id(), "file_888");
    EXPECT_EQ(proto.correlation_id(), "corr_777");
    EXPECT_EQ(proto.causation_id(), "caus_666");
    EXPECT_EQ(proto.metadata().at("bytes"), "1048576");

    // Proto -> Domain
    auto now = std::chrono::system_clock::now();
    auto converted = AuditEventMapper::to_domain(proto, now);

    EXPECT_EQ(converted.event_id, original.event_id);
    EXPECT_EQ(converted.event_type, original.event_type);
    EXPECT_EQ(converted.severity, original.severity);
    EXPECT_EQ(converted.producer_service, original.producer_service);
    EXPECT_EQ(converted.actor_type, original.actor_type);
    EXPECT_EQ(converted.target_type, original.target_type);
    EXPECT_TRUE(converted.received_at.has_value());
    EXPECT_EQ(*converted.received_at, now); // Verified received_at is authoritatively injected
}

} // namespace securecloud::audit::domain::test