#include "domain/event_payload_fingerprint.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::domain::testing {

class EventPayloadFingerprintTest : public ::testing::Test {
  protected:
    AuditEvent build_base_event() {
        AuditEvent event;
        event.event_id = EventId::from_string("018f6e4a-7b3c-7000-8000-000000000001").value();
        event.occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710000000000LL));
        event.received_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710000001000LL));
        event.event_type = "user.login";
        event.severity = Severity::Info;
        event.producer_service = ProducerService::Auth;
        event.producer_instance = "auth-01";
        event.actor_type = ActorType::User;
        event.actor_id = "user-123";
        event.target_type = TargetType::Service;
        event.target_id = "sys-456";
        event.correlation_id = "corr-789";
        event.causation_id = "cause-001";
        event.metadata = {{"ip", "192.168.1.1"}, {"agent", "Mozilla"}};
        return event;
    }
};

TEST_F(EventPayloadFingerprintTest, DeterministicAcrossIdenticalEvents) {
    auto e1 = build_base_event();
    auto e2 = build_base_event();

    auto fp1 = EventPayloadFingerprint::compute(e1);
    auto fp2 = EventPayloadFingerprint::compute(e2);

    EXPECT_EQ(fp1, fp2);
    EXPECT_EQ(fp1.bytes(), fp2.bytes());
    EXPECT_EQ(fp1.bytes().size(), 32u);
}

TEST_F(EventPayloadFingerprintTest, InsensitiveToReceivedAtDifferences) {
    auto e1 = build_base_event();
    auto e2 = build_base_event();

    // Change service-assigned received_at timestamp
    e2.received_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    auto fp1 = EventPayloadFingerprint::compute(e1);
    auto fp2 = EventPayloadFingerprint::compute(e2);

    EXPECT_EQ(fp1, fp2);
}

TEST_F(EventPayloadFingerprintTest, InsensitiveToMetadataInsertionOrder) {
    auto e1 = build_base_event();
    auto e2 = build_base_event();

    e1.metadata.clear();
    e2.metadata.clear();

    for (int i = 0; i < 20; ++i) {
        std::string key = "key_" + std::to_string(i);
        std::string val = "val_" + std::to_string(i);
        e1.metadata[key] = val;
    }

    for (int i = 19; i >= 0; --i) {
        std::string key = "key_" + std::to_string(i);
        std::string val = "val_" + std::to_string(i);
        e2.metadata[key] = val;
    }

    auto fp1 = EventPayloadFingerprint::compute(e1);
    auto fp2 = EventPayloadFingerprint::compute(e2);

    EXPECT_EQ(fp1, fp2);
}

TEST_F(EventPayloadFingerprintTest, SensitiveToEveryImmutableFieldMutation) {
    auto base = build_base_event();
    auto base_fp = EventPayloadFingerprint::compute(base);

    // 1. occurred_at
    auto e_occurred = base;
    e_occurred.occurred_at += std::chrono::seconds(1);
    EXPECT_NE(EventPayloadFingerprint::compute(e_occurred), base_fp);

    // 2. event_type
    auto e_type = base;
    e_type.event_type = "user.logout";
    EXPECT_NE(EventPayloadFingerprint::compute(e_type), base_fp);

    // 3. severity
    auto e_sev = base;
    e_sev.severity = Severity::Warning;
    EXPECT_NE(EventPayloadFingerprint::compute(e_sev), base_fp);

    // 4. producer_service
    auto e_prod = base;
    e_prod.producer_service = ProducerService::Gateway;
    EXPECT_NE(EventPayloadFingerprint::compute(e_prod), base_fp);

    // 5. producer_instance
    auto e_inst = base;
    e_inst.producer_instance = "auth-02";
    EXPECT_NE(EventPayloadFingerprint::compute(e_inst), base_fp);

    // 6. actor_type
    auto e_act_type = base;
    e_act_type.actor_type = ActorType::System;
    EXPECT_NE(EventPayloadFingerprint::compute(e_act_type), base_fp);

    // 7. actor_id
    auto e_act_id = base;
    e_act_id.actor_id = "user-999";
    EXPECT_NE(EventPayloadFingerprint::compute(e_act_id), base_fp);

    // 8. target_type
    auto e_tgt_type = base;
    e_tgt_type.target_type = TargetType::User;
    EXPECT_NE(EventPayloadFingerprint::compute(e_tgt_type), base_fp);

    // 9. target_id
    auto e_tgt_id = base;
    e_tgt_id.target_id = "sys-999";
    EXPECT_NE(EventPayloadFingerprint::compute(e_tgt_id), base_fp);

    // 10. correlation_id
    auto e_corr = base;
    e_corr.correlation_id = "corr-000";
    EXPECT_NE(EventPayloadFingerprint::compute(e_corr), base_fp);

    // 11. causation_id
    auto e_cause = base;
    e_cause.causation_id = "cause-000";
    EXPECT_NE(EventPayloadFingerprint::compute(e_cause), base_fp);

    // 12. metadata key/value
    auto e_meta = base;
    e_meta.metadata["ip"] = "10.0.0.1";
    EXPECT_NE(EventPayloadFingerprint::compute(e_meta), base_fp);
}

TEST_F(EventPayloadFingerprintTest, LengthPrefixPreventsConcatenationCollision) {
    auto e1 = build_base_event();
    e1.actor_id = "ab";
    e1.target_id = "c";

    auto e2 = build_base_event();
    e2.actor_id = "a";
    e2.target_id = "bc";

    auto fp1 = EventPayloadFingerprint::compute(e1);
    auto fp2 = EventPayloadFingerprint::compute(e2);

    EXPECT_NE(fp1, fp2);
}

} // namespace securecloud::audit::domain::testing