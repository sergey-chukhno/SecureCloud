#include "domain/delivery_types.hpp"
#include "domain/read_receipt_types.hpp"
#include "service/delivery_state_transition_guard.hpp"

#include <gtest/gtest.h>

namespace securecloud::messaging::service {
namespace {

using domain::DeliveryState;
using domain::DeviceDeliveryStatus;
using domain::DeviceId;
using domain::LogicalRecipientReadStatus;
using domain::MessageDeliverySummary;
using domain::MessageId;
using domain::ReadState;
using domain::UserId;

// ============================================================================
// 1. Forward Valid Transitions
// ============================================================================

TEST(DeliveryStateTransitionGuardTest, ForwardValidTransitions) {
    // Queued
    EXPECT_TRUE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Queued, DeliveryState::Delivering));
    EXPECT_TRUE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Queued, DeliveryState::Expired));

    // Delivering
    EXPECT_TRUE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Delivering, DeliveryState::Delivered));
    EXPECT_TRUE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Delivering, DeliveryState::RetryWait));
    EXPECT_TRUE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Delivering, DeliveryState::Expired));

    // RetryWait
    EXPECT_TRUE(DeliveryStateTransitionGuard::can_transition(DeliveryState::RetryWait, DeliveryState::Delivering));
    EXPECT_TRUE(DeliveryStateTransitionGuard::can_transition(DeliveryState::RetryWait, DeliveryState::Expired));

    // Delivered (wire compatibility with Read)
    EXPECT_TRUE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Delivered, DeliveryState::Read));

    // Protobuf enum overloads
    EXPECT_TRUE(DeliveryStateTransitionGuard::can_transition(v1::DELIVERY_STATE_QUEUED, v1::DELIVERY_STATE_DELIVERING));
    EXPECT_TRUE(DeliveryStateTransitionGuard::can_transition(v1::DELIVERY_STATE_QUEUED, v1::DELIVERY_STATE_EXPIRED));
    EXPECT_TRUE(
        DeliveryStateTransitionGuard::can_transition(v1::DELIVERY_STATE_DELIVERING, v1::DELIVERY_STATE_DELIVERED));
    EXPECT_TRUE(
        DeliveryStateTransitionGuard::can_transition(v1::DELIVERY_STATE_DELIVERING, v1::DELIVERY_STATE_RETRY_WAIT));
    EXPECT_TRUE(
        DeliveryStateTransitionGuard::can_transition(v1::DELIVERY_STATE_RETRY_WAIT, v1::DELIVERY_STATE_DELIVERING));
    EXPECT_TRUE(DeliveryStateTransitionGuard::can_transition(v1::DELIVERY_STATE_DELIVERED, v1::DELIVERY_STATE_READ));
}

// ============================================================================
// 2. Strict Regression Rejection
// ============================================================================

TEST(DeliveryStateTransitionGuardTest, BackwardRegressionsRejected) {
    // Delivered cannot regress to Queued, Delivering, or RetryWait
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_regression(DeliveryState::Delivered, DeliveryState::Queued));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_regression(DeliveryState::Delivered, DeliveryState::Delivering));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_regression(DeliveryState::Delivered, DeliveryState::RetryWait));

    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Delivered, DeliveryState::Queued));
    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Delivered, DeliveryState::Delivering));
    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Delivered, DeliveryState::RetryWait));

    // Delivering cannot regress to Queued
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_regression(DeliveryState::Delivering, DeliveryState::Queued));
    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Delivering, DeliveryState::Queued));

    // RetryWait cannot regress to Queued
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_regression(DeliveryState::RetryWait, DeliveryState::Queued));
    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition(DeliveryState::RetryWait, DeliveryState::Queued));

    // Expired is terminal and cannot regress to any prior state
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_regression(DeliveryState::Expired, DeliveryState::Queued));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_regression(DeliveryState::Expired, DeliveryState::Delivering));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_regression(DeliveryState::Expired, DeliveryState::RetryWait));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_regression(DeliveryState::Expired, DeliveryState::Delivered));

    // Protobuf enum regression checks
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_regression(v1::DELIVERY_STATE_DELIVERED, v1::DELIVERY_STATE_QUEUED));
    EXPECT_TRUE(
        DeliveryStateTransitionGuard::is_regression(v1::DELIVERY_STATE_DELIVERED, v1::DELIVERY_STATE_RETRY_WAIT));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_regression(v1::DELIVERY_STATE_EXPIRED, v1::DELIVERY_STATE_DELIVERED));
}

// ============================================================================
// 3. Prohibited State Jumps
// ============================================================================

TEST(DeliveryStateTransitionGuardTest, ProhibitedStateJumps) {
    // Cannot jump directly from Queued to Delivered (must go through Delivering)
    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Queued, DeliveryState::Delivered));
    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Queued, DeliveryState::RetryWait));

    // Cannot jump directly from RetryWait to Delivered
    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition(DeliveryState::RetryWait, DeliveryState::Delivered));

    // Delivered cannot expire
    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Delivered, DeliveryState::Expired));
}

// ============================================================================
// 4. Idempotency Checks
// ============================================================================

TEST(DeliveryStateTransitionGuardTest, IdempotencyChecks) {
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_idempotent(DeliveryState::Queued, DeliveryState::Queued));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_idempotent(DeliveryState::Delivering, DeliveryState::Delivering));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_idempotent(DeliveryState::Delivered, DeliveryState::Delivered));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_idempotent(DeliveryState::RetryWait, DeliveryState::RetryWait));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_idempotent(DeliveryState::Expired, DeliveryState::Expired));

    EXPECT_FALSE(DeliveryStateTransitionGuard::is_idempotent(DeliveryState::Delivered, DeliveryState::Queued));
    EXPECT_FALSE(DeliveryStateTransitionGuard::is_idempotent(DeliveryState::Queued, DeliveryState::Delivering));

    // Protobuf overload
    EXPECT_TRUE(
        DeliveryStateTransitionGuard::is_idempotent(v1::DELIVERY_STATE_DELIVERED, v1::DELIVERY_STATE_DELIVERED));
    EXPECT_FALSE(
        DeliveryStateTransitionGuard::is_idempotent(v1::DELIVERY_STATE_UNSPECIFIED, v1::DELIVERY_STATE_UNSPECIFIED));
}

// ============================================================================
// 5. Terminal State Checks
// ============================================================================

TEST(DeliveryStateTransitionGuardTest, TerminalStateChecks) {
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_terminal(DeliveryState::Delivered));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_terminal(DeliveryState::Expired));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_terminal(DeliveryState::Read));

    EXPECT_FALSE(DeliveryStateTransitionGuard::is_terminal(DeliveryState::Queued));
    EXPECT_FALSE(DeliveryStateTransitionGuard::is_terminal(DeliveryState::Delivering));
    EXPECT_FALSE(DeliveryStateTransitionGuard::is_terminal(DeliveryState::RetryWait));

    // Protobuf overload
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_terminal(v1::DELIVERY_STATE_DELIVERED));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_terminal(v1::DELIVERY_STATE_EXPIRED));
    EXPECT_FALSE(DeliveryStateTransitionGuard::is_terminal(v1::DELIVERY_STATE_QUEUED));
    EXPECT_FALSE(DeliveryStateTransitionGuard::is_terminal(v1::DELIVERY_STATE_RETRY_WAIT));
}

// ============================================================================
// 6. Comprehensive Transition Validation
// ============================================================================

TEST(DeliveryStateTransitionGuardTest, ValidateTransitionResults) {
    // Valid transition succeeds
    auto res_valid =
        DeliveryStateTransitionGuard::validate_transition(DeliveryState::Queued, DeliveryState::Delivering);
    EXPECT_TRUE(res_valid);

    // Idempotent re-application succeeds
    auto res_idempotent =
        DeliveryStateTransitionGuard::validate_transition(DeliveryState::Delivered, DeliveryState::Delivered);
    EXPECT_TRUE(res_idempotent);

    // Regressive transition returns descriptive failure
    auto res_regress =
        DeliveryStateTransitionGuard::validate_transition(DeliveryState::Delivered, DeliveryState::Queued);
    EXPECT_FALSE(res_regress);
    EXPECT_NE(res_regress.error_message.find("Invalid delivery state regression"), std::string::npos);

    // Transition from Expired returns MESSAGE_EXPIRED
    auto res_expired =
        DeliveryStateTransitionGuard::validate_transition(DeliveryState::Expired, DeliveryState::Delivered);
    EXPECT_FALSE(res_expired);
    EXPECT_EQ(res_expired.error_code, v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED);

    // Prohibited skip returns failure
    auto res_skip = DeliveryStateTransitionGuard::validate_transition(DeliveryState::Queued, DeliveryState::Delivered);
    EXPECT_FALSE(res_skip);
    EXPECT_NE(res_skip.error_message.find("Prohibited delivery state transition"), std::string::npos);
}

// ============================================================================
// 7. ReadState Lifecycle Transitions (Decoupled User-Level Semantics)
// ============================================================================

TEST(DeliveryStateTransitionGuardTest, ReadStateTransitions) {
    // Unread -> Read is valid
    EXPECT_TRUE(DeliveryStateTransitionGuard::can_transition_read(ReadState::Unread, ReadState::Read));

    // Read -> Unread is prohibited regression
    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition_read(ReadState::Read, ReadState::Unread));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_read_regression(ReadState::Read, ReadState::Unread));
    EXPECT_FALSE(DeliveryStateTransitionGuard::is_read_regression(ReadState::Unread, ReadState::Read));

    // Idempotent read check
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_read_idempotent(ReadState::Read, ReadState::Read));
    EXPECT_TRUE(DeliveryStateTransitionGuard::is_read_idempotent(ReadState::Unread, ReadState::Unread));
    EXPECT_FALSE(DeliveryStateTransitionGuard::is_read_idempotent(ReadState::Unread, ReadState::Read));

    // Validate read transition
    auto val_read = DeliveryStateTransitionGuard::validate_read_transition(ReadState::Unread, ReadState::Read);
    EXPECT_TRUE(val_read);

    auto val_idempotent_read = DeliveryStateTransitionGuard::validate_read_transition(ReadState::Read, ReadState::Read);
    EXPECT_TRUE(val_idempotent_read);

    auto val_regress_read = DeliveryStateTransitionGuard::validate_read_transition(ReadState::Read, ReadState::Unread);
    EXPECT_FALSE(val_regress_read);
    EXPECT_NE(val_regress_read.error_message.find("already marked as READ"), std::string::npos);
}

// ============================================================================
// 8. Domain Value Types & Serialization
// ============================================================================

TEST(DeliveryStateTransitionGuardTest, ReadStateStringConversions) {
    EXPECT_EQ(domain::to_string(ReadState::Unread), "UNREAD");
    EXPECT_EQ(domain::to_string(ReadState::Read), "READ");

    EXPECT_EQ(domain::read_state_from_string("UNREAD"), ReadState::Unread);
    EXPECT_EQ(domain::read_state_from_string("READ"), ReadState::Read);
    EXPECT_EQ(domain::read_state_from_string("INVALID"), std::nullopt);
}

TEST(DeliveryStateTransitionGuardTest, DomainAggregates) {
    UserId user_id("user-11111111-1111-1111-1111-111111111111");
    DeviceId device_id("dev-11111111-1111-1111-1111-111111111111");
    auto now = std::chrono::system_clock::now();

    LogicalRecipientReadStatus read_status;
    read_status.user_id = user_id;
    read_status.read_state = ReadState::Read;
    read_status.read_at = now;
    read_status.reader_device_id = device_id;

    EXPECT_EQ(read_status.user_id, user_id);
    EXPECT_EQ(read_status.read_state, ReadState::Read);
    EXPECT_EQ(read_status.reader_device_id, device_id);

    DeviceDeliveryStatus dev_status;
    dev_status.device_id = device_id;
    dev_status.recipient_user_id = user_id;
    dev_status.delivery_state = DeliveryState::Delivered;
    dev_status.delivered_at = now;
    dev_status.attempt_count = 1;

    EXPECT_EQ(dev_status.delivery_state, DeliveryState::Delivered);
    EXPECT_EQ(dev_status.attempt_count, 1);

    MessageDeliverySummary summary;
    summary.message_id = MessageId::generate_v7();
    summary.total_targets = 2;
    summary.delivered_targets = 1;
    summary.pending_targets = 1;
    summary.expired_targets = 0;
    summary.device_statuses.push_back(dev_status);
    summary.recipient_read_statuses.push_back(read_status);

    EXPECT_EQ(summary.total_targets, 2u);
    EXPECT_EQ(summary.delivered_targets, 1u);
    EXPECT_EQ(summary.device_statuses.size(), 1u);
    EXPECT_EQ(summary.recipient_read_statuses.size(), 1u);
}

} // namespace
} // namespace securecloud::messaging::service
