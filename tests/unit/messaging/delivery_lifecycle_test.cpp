#include "domain/delivery_types.hpp"
#include "service/delivery_lifecycle.hpp"

#include <gtest/gtest.h>

namespace securecloud::messaging::service {
namespace {

using domain::DeliveryAttemptResult;
using domain::DeliveryState;
using domain::DeliveryTask;

TEST(DeliveryLifecycleTest, DomainStateCanonicalValidTransitions) {
    // Queued transitions
    EXPECT_TRUE(is_valid_delivery_transition(DeliveryState::Queued, DeliveryState::Delivering));
    EXPECT_TRUE(is_valid_delivery_transition(DeliveryState::Queued, DeliveryState::Expired));

    // Delivering transitions
    EXPECT_TRUE(is_valid_delivery_transition(DeliveryState::Delivering, DeliveryState::Delivered));
    EXPECT_TRUE(is_valid_delivery_transition(DeliveryState::Delivering, DeliveryState::RetryWait));
    EXPECT_TRUE(is_valid_delivery_transition(DeliveryState::Delivering, DeliveryState::Expired));

    // RetryWait transitions
    EXPECT_TRUE(is_valid_delivery_transition(DeliveryState::RetryWait, DeliveryState::Delivering));
    EXPECT_TRUE(is_valid_delivery_transition(DeliveryState::RetryWait, DeliveryState::Expired));

    // Delivered transitions
    EXPECT_TRUE(is_valid_delivery_transition(DeliveryState::Delivered, DeliveryState::Read));
}

TEST(DeliveryLifecycleTest, DomainStateProhibitedTransitions) {
    // Cannot skip Delivering
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Queued, DeliveryState::Delivered));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Queued, DeliveryState::Read));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Queued, DeliveryState::RetryWait));

    // Cannot regress from Delivering to Queued
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Delivering, DeliveryState::Queued));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Delivering, DeliveryState::Read));

    // Cannot jump from RetryWait to terminal Delivered or Read
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::RetryWait, DeliveryState::Queued));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::RetryWait, DeliveryState::Delivered));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::RetryWait, DeliveryState::Read));

    // Delivered cannot regress or expire
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Delivered, DeliveryState::Queued));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Delivered, DeliveryState::Delivering));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Delivered, DeliveryState::RetryWait));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Delivered, DeliveryState::Expired));

    // Terminal Read cannot transition
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Read, DeliveryState::Queued));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Read, DeliveryState::Delivering));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Read, DeliveryState::Delivered));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Read, DeliveryState::RetryWait));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Read, DeliveryState::Expired));

    // Terminal Expired cannot transition
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Expired, DeliveryState::Queued));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Expired, DeliveryState::Delivering));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Expired, DeliveryState::Delivered));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Expired, DeliveryState::Read));
    EXPECT_FALSE(is_valid_delivery_transition(DeliveryState::Expired, DeliveryState::RetryWait));
}

TEST(DeliveryLifecycleTest, DomainIdempotentStateChecks) {
    EXPECT_TRUE(is_idempotent_delivery_state(DeliveryState::Queued, DeliveryState::Queued));
    EXPECT_TRUE(is_idempotent_delivery_state(DeliveryState::Delivering, DeliveryState::Delivering));
    EXPECT_TRUE(is_idempotent_delivery_state(DeliveryState::Delivered, DeliveryState::Delivered));
    EXPECT_TRUE(is_idempotent_delivery_state(DeliveryState::Read, DeliveryState::Read));
    EXPECT_TRUE(is_idempotent_delivery_state(DeliveryState::RetryWait, DeliveryState::RetryWait));
    EXPECT_TRUE(is_idempotent_delivery_state(DeliveryState::Expired, DeliveryState::Expired));

    EXPECT_FALSE(is_idempotent_delivery_state(DeliveryState::Queued, DeliveryState::Delivering));
    EXPECT_FALSE(is_idempotent_delivery_state(DeliveryState::Delivered, DeliveryState::Read));
}

TEST(DeliveryLifecycleTest, DomainProtoConversionParity) {
    EXPECT_EQ(to_proto_delivery_state(DeliveryState::Queued), v1::DELIVERY_STATE_QUEUED);
    EXPECT_EQ(to_proto_delivery_state(DeliveryState::Delivering), v1::DELIVERY_STATE_DELIVERING);
    EXPECT_EQ(to_proto_delivery_state(DeliveryState::Delivered), v1::DELIVERY_STATE_DELIVERED);
    EXPECT_EQ(to_proto_delivery_state(DeliveryState::Read), v1::DELIVERY_STATE_READ);
    EXPECT_EQ(to_proto_delivery_state(DeliveryState::RetryWait), v1::DELIVERY_STATE_RETRY_WAIT);
    EXPECT_EQ(to_proto_delivery_state(DeliveryState::Expired), v1::DELIVERY_STATE_EXPIRED);

    EXPECT_EQ(from_proto_delivery_state(v1::DELIVERY_STATE_QUEUED), DeliveryState::Queued);
    EXPECT_EQ(from_proto_delivery_state(v1::DELIVERY_STATE_DELIVERING), DeliveryState::Delivering);
    EXPECT_EQ(from_proto_delivery_state(v1::DELIVERY_STATE_DELIVERED), DeliveryState::Delivered);
    EXPECT_EQ(from_proto_delivery_state(v1::DELIVERY_STATE_READ), DeliveryState::Read);
    EXPECT_EQ(from_proto_delivery_state(v1::DELIVERY_STATE_RETRY_WAIT), DeliveryState::RetryWait);
    EXPECT_EQ(from_proto_delivery_state(v1::DELIVERY_STATE_EXPIRED), DeliveryState::Expired);
    EXPECT_EQ(from_proto_delivery_state(v1::DELIVERY_STATE_UNSPECIFIED), std::nullopt);
}

TEST(DeliveryTypesTest, DeliveryStateStringParsingAndBackwardsCompatibility) {
    EXPECT_EQ(to_string(DeliveryState::Queued), "QUEUED");
    EXPECT_EQ(to_string(DeliveryState::Delivering), "DELIVERING");
    EXPECT_EQ(to_string(DeliveryState::Delivered), "DELIVERED");
    EXPECT_EQ(to_string(DeliveryState::Read), "READ");
    EXPECT_EQ(to_string(DeliveryState::RetryWait), "RETRY_WAIT");
    EXPECT_EQ(to_string(DeliveryState::Expired), "EXPIRED");

    // Parse canonical strings
    EXPECT_EQ(domain::delivery_state_from_string("QUEUED"), DeliveryState::Queued);
    EXPECT_EQ(domain::delivery_state_from_string("DELIVERING"), DeliveryState::Delivering);
    EXPECT_EQ(domain::delivery_state_from_string("DELIVERED"), DeliveryState::Delivered);
    EXPECT_EQ(domain::delivery_state_from_string("READ"), DeliveryState::Read);
    EXPECT_EQ(domain::delivery_state_from_string("RETRY_WAIT"), DeliveryState::RetryWait);
    EXPECT_EQ(domain::delivery_state_from_string("EXPIRED"), DeliveryState::Expired);

    // Backwards-compatibility for existing DB records containing "PENDING"
    EXPECT_EQ(domain::delivery_state_from_string("PENDING"), DeliveryState::Queued);
    EXPECT_EQ(DeliveryState::Pending, DeliveryState::Queued);

    // Invalid string
    EXPECT_EQ(domain::delivery_state_from_string("UNKNOWN"), std::nullopt);
}

TEST(DeliveryTypesTest, DeliveryAttemptResultStringConversions) {
    EXPECT_EQ(to_string(DeliveryAttemptResult::Success), "SUCCESS");
    EXPECT_EQ(to_string(DeliveryAttemptResult::RecipientOffline), "RECIPIENT_OFFLINE");
    EXPECT_EQ(to_string(DeliveryAttemptResult::TransientFailure), "TRANSIENT_FAILURE");
    EXPECT_EQ(to_string(DeliveryAttemptResult::TerminalFailure), "TERMINAL_FAILURE");

    EXPECT_EQ(domain::delivery_attempt_result_from_string("SUCCESS"), DeliveryAttemptResult::Success);
    EXPECT_EQ(domain::delivery_attempt_result_from_string("RECIPIENT_OFFLINE"),
              DeliveryAttemptResult::RecipientOffline);
    EXPECT_EQ(domain::delivery_attempt_result_from_string("TRANSIENT_FAILURE"),
              DeliveryAttemptResult::TransientFailure);
    EXPECT_EQ(domain::delivery_attempt_result_from_string("TERMINAL_FAILURE"), DeliveryAttemptResult::TerminalFailure);
    EXPECT_EQ(domain::delivery_attempt_result_from_string("UNKNOWN"), std::nullopt);
}

TEST(DeliveryTypesTest, DeliveryTaskEqualityAndValueSemantics) {
    DeliveryTask task1;
    task1.message_id = domain::MessageId::generate_v7();
    task1.conversation_id = domain::ConversationId::generate_v7();
    task1.recipient_device_id = domain::DeviceId("device-123");
    task1.recipient_user_id = domain::UserId("user-456");
    task1.attempt_count = 1;

    DeliveryTask task2 = task1;
    EXPECT_EQ(task1, task2);

    task2.attempt_count = 2;
    EXPECT_NE(task1, task2);
}

} // namespace
} // namespace securecloud::messaging::service
