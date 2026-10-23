#include "domain/enums.hpp"
#include "domain/event_id.hpp"

#include <gtest/gtest.h>
#include <thread>

namespace securecloud::audit::domain::test {

TEST(AuditEventModelTest, EventIdGenerateV7HasValidVersionAndVariant) {
    auto id1 = EventId::generate_v7();
    EXPECT_FALSE(id1.is_nil());
    EXPECT_EQ(id1.version(), 7);
    EXPECT_EQ(id1.variant(), 2);

    std::this_thread::sleep_for(std::chrono::milliseconds(2));

    auto id2 = EventId::generate_v7();
    EXPECT_FALSE(id2.is_nil());
    EXPECT_EQ(id2.version(), 7);
    EXPECT_EQ(id2.variant(), 2);

    EXPECT_GT(id2.timestamp_ms(), 0u);
    EXPECT_GE(id2.timestamp_ms(), id1.timestamp_ms());
    EXPECT_GT(id2, id1);
}

TEST(AuditEventModelTest, EventIdFromStringAndToStringRoundtrip) {
    auto id = EventId::generate_v7();
    std::string str = id.to_string();

    EXPECT_EQ(str.size(), 36);

    auto parsed_opt = EventId::from_string(str);
    ASSERT_TRUE(parsed_opt.has_value());
    EXPECT_EQ(*parsed_opt, id);
    EXPECT_EQ(parsed_opt->to_string(), str);
}

TEST(AuditEventModelTest, EnumStringConversionRoundtrip) {
    // Severity
    EXPECT_EQ(to_string(Severity::Info), "INFO");
    EXPECT_EQ(to_string(Severity::Warning), "WARNING");
    EXPECT_EQ(to_string(Severity::Security), "SECURITY");
    EXPECT_EQ(to_string(Severity::Critical), "CRITICAL");

    EXPECT_EQ(severity_from_string("INFO"), Severity::Info);
    EXPECT_EQ(severity_from_string("warning"), Severity::Warning);
    EXPECT_EQ(severity_from_string("3"), Severity::Security);
    EXPECT_EQ(severity_from_string("CRITICAL"), Severity::Critical);
    EXPECT_FALSE(severity_from_string("INVALID").has_value());

    // ProducerService
    EXPECT_EQ(to_string(ProducerService::Gateway), "gateway");
    EXPECT_EQ(to_string(ProducerService::Auth), "auth");
    EXPECT_EQ(to_string(ProducerService::Messaging), "messaging");
    EXPECT_EQ(to_string(ProducerService::Files), "files");
    EXPECT_EQ(to_string(ProducerService::Audit), "audit");

    EXPECT_EQ(producer_from_string("gateway"), ProducerService::Gateway);
    EXPECT_EQ(producer_from_string("AUTH"), ProducerService::Auth);
    EXPECT_FALSE(producer_from_string("unknown_service").has_value());

    // ActorType
    EXPECT_EQ(to_string(ActorType::User), "USER");
    EXPECT_EQ(to_string(ActorType::Device), "DEVICE");
    EXPECT_EQ(actor_type_from_string("user"), ActorType::User);
    EXPECT_FALSE(actor_type_from_string("INVALID").has_value());

    // TargetType
    EXPECT_EQ(to_string(TargetType::Conversation), "CONVERSATION");
    EXPECT_EQ(to_string(TargetType::File), "FILE");
    EXPECT_EQ(target_type_from_string("file"), TargetType::File);
    EXPECT_FALSE(target_type_from_string("INVALID").has_value());
}

} // namespace securecloud::audit::domain::test
