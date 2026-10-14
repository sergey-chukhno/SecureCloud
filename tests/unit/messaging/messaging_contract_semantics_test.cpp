#include "securecloud/messaging/v1/messaging.pb.h"
#include "service/delivery_lifecycle.hpp"

#include <gtest/gtest.h>
#include <string>

namespace securecloud::messaging::service {
namespace {

// ============================================================================
// Delivery State Machine Transition Tests (ADR-007, Design 5.13)
// ============================================================================

TEST(MessagingContractSemanticsTest, ValidDeliveryTransitionsPass) {
    // 1. From QUEUED
    EXPECT_TRUE(is_valid_delivery_transition(v1::DELIVERY_STATE_QUEUED, v1::DELIVERY_STATE_DELIVERING));
    EXPECT_TRUE(is_valid_delivery_transition(v1::DELIVERY_STATE_QUEUED, v1::DELIVERY_STATE_EXPIRED));

    // 2. From DELIVERING
    EXPECT_TRUE(is_valid_delivery_transition(v1::DELIVERY_STATE_DELIVERING, v1::DELIVERY_STATE_DELIVERED));
    EXPECT_TRUE(is_valid_delivery_transition(v1::DELIVERY_STATE_DELIVERING, v1::DELIVERY_STATE_RETRY_WAIT));
    EXPECT_TRUE(is_valid_delivery_transition(v1::DELIVERY_STATE_DELIVERING, v1::DELIVERY_STATE_EXPIRED));

    // 3. From RETRY_WAIT
    EXPECT_TRUE(is_valid_delivery_transition(v1::DELIVERY_STATE_RETRY_WAIT, v1::DELIVERY_STATE_DELIVERING));
    EXPECT_TRUE(is_valid_delivery_transition(v1::DELIVERY_STATE_RETRY_WAIT, v1::DELIVERY_STATE_EXPIRED));

    // 4. From DELIVERED (read receipt event)
    EXPECT_TRUE(is_valid_delivery_transition(v1::DELIVERY_STATE_DELIVERED, v1::DELIVERY_STATE_READ));
}

TEST(MessagingContractSemanticsTest, InvalidDeliveryTransitionsRejected) {
    // Skipping delivering phase directly to delivered or read
    EXPECT_FALSE(is_valid_delivery_transition(v1::DELIVERY_STATE_QUEUED, v1::DELIVERY_STATE_DELIVERED));
    EXPECT_FALSE(is_valid_delivery_transition(v1::DELIVERY_STATE_QUEUED, v1::DELIVERY_STATE_READ));

    // Backward regressions
    EXPECT_FALSE(is_valid_delivery_transition(v1::DELIVERY_STATE_DELIVERED, v1::DELIVERY_STATE_QUEUED));
    EXPECT_FALSE(is_valid_delivery_transition(v1::DELIVERY_STATE_DELIVERED, v1::DELIVERY_STATE_DELIVERING));
    EXPECT_FALSE(is_valid_delivery_transition(v1::DELIVERY_STATE_DELIVERED, v1::DELIVERY_STATE_RETRY_WAIT));

    // Terminal states cannot transition to other states
    EXPECT_FALSE(is_valid_delivery_transition(v1::DELIVERY_STATE_READ, v1::DELIVERY_STATE_DELIVERING));
    EXPECT_FALSE(is_valid_delivery_transition(v1::DELIVERY_STATE_READ, v1::DELIVERY_STATE_QUEUED));
    EXPECT_FALSE(is_valid_delivery_transition(v1::DELIVERY_STATE_EXPIRED, v1::DELIVERY_STATE_QUEUED));
    EXPECT_FALSE(is_valid_delivery_transition(v1::DELIVERY_STATE_EXPIRED, v1::DELIVERY_STATE_DELIVERED));

    // Unspecified initial state
    EXPECT_FALSE(is_valid_delivery_transition(v1::DELIVERY_STATE_UNSPECIFIED, v1::DELIVERY_STATE_QUEUED));
}

TEST(MessagingContractSemanticsTest, IdempotentDeliveryStateReapplication) {
    EXPECT_TRUE(is_idempotent_delivery_state(v1::DELIVERY_STATE_DELIVERED, v1::DELIVERY_STATE_DELIVERED));
    EXPECT_TRUE(is_idempotent_delivery_state(v1::DELIVERY_STATE_READ, v1::DELIVERY_STATE_READ));
    EXPECT_TRUE(is_idempotent_delivery_state(v1::DELIVERY_STATE_EXPIRED, v1::DELIVERY_STATE_EXPIRED));

    EXPECT_FALSE(is_idempotent_delivery_state(v1::DELIVERY_STATE_DELIVERED, v1::DELIVERY_STATE_READ));
    EXPECT_FALSE(is_idempotent_delivery_state(v1::DELIVERY_STATE_QUEUED, v1::DELIVERY_STATE_DELIVERED));
    EXPECT_FALSE(is_idempotent_delivery_state(v1::DELIVERY_STATE_UNSPECIFIED, v1::DELIVERY_STATE_UNSPECIFIED));
}

// ============================================================================
// Sync Cursor Monotonicity & Sequence Semantics (ADR-007, Design 5.17)
// ============================================================================

TEST(MessagingContractSemanticsTest, ValidSequenceNumbers) {
    EXPECT_TRUE(is_valid_sequence(0));
    EXPECT_TRUE(is_valid_sequence(1));
    EXPECT_TRUE(is_valid_sequence(1000));
    EXPECT_TRUE(is_valid_sequence(INT64_MAX));

    EXPECT_FALSE(is_valid_sequence(-1));
    EXPECT_FALSE(is_valid_sequence(-100));
    EXPECT_FALSE(is_valid_sequence(INT64_MIN));
}

TEST(MessagingContractSemanticsTest, CursorMonotonicAdvanceSucceeds) {
    constexpr int64_t k_initial_seq = 0;
    constexpr int64_t k_next_seq = 1;
    EXPECT_TRUE(is_valid_cursor_progression(k_initial_seq, k_next_seq));

    constexpr int64_t k_current_seq = 100;
    constexpr int64_t k_advanced_seq = 101;
    EXPECT_TRUE(is_valid_cursor_progression(k_current_seq, k_advanced_seq));

    constexpr int64_t k_jump_seq = 250;
    EXPECT_TRUE(is_valid_cursor_progression(k_current_seq, k_jump_seq));
}

TEST(MessagingContractSemanticsTest, StaleOrRegressiveCursorUpdatesRejected) {
    // Duplicate / identical sequence
    constexpr int64_t k_current_seq = 100;
    EXPECT_FALSE(is_valid_cursor_progression(k_current_seq, k_current_seq));

    // Backward regression
    constexpr int64_t k_regressive_seq = 99;
    EXPECT_FALSE(is_valid_cursor_progression(k_current_seq, k_regressive_seq));

    constexpr int64_t k_zero_seq = 0;
    EXPECT_FALSE(is_valid_cursor_progression(k_current_seq, k_zero_seq));

    // Negative sequence
    constexpr int64_t k_negative_seq = -5;
    EXPECT_FALSE(is_valid_cursor_progression(k_current_seq, k_negative_seq));
}

// ============================================================================
// Bounded Pagination Semantics Tests (ADR-007, Design 5.17)
// ============================================================================

TEST(MessagingContractSemanticsTest, PageLimitValidation) {
    EXPECT_FALSE(is_valid_page_limit(0));

    EXPECT_TRUE(is_valid_page_limit(1));
    EXPECT_TRUE(is_valid_page_limit(50));
    EXPECT_TRUE(is_valid_page_limit(100));

    EXPECT_FALSE(is_valid_page_limit(101));
    EXPECT_FALSE(is_valid_page_limit(500));
}

TEST(MessagingContractSemanticsTest, PageLimitSanitization) {
    // Default fallback when 0 requested
    EXPECT_EQ(sanitize_page_limit(0), k_default_page_limit);

    // Explicit valid sizes preserved
    constexpr uint32_t k_explicit_size = 25;
    EXPECT_EQ(sanitize_page_limit(k_explicit_size), k_explicit_size);
    EXPECT_EQ(sanitize_page_limit(k_max_page_limit), k_max_page_limit);

    // Clamping to maximum limit
    constexpr uint32_t k_oversized_limit1 = 101;
    constexpr uint32_t k_oversized_limit2 = 1000;
    EXPECT_EQ(sanitize_page_limit(k_oversized_limit1), k_max_page_limit);
    EXPECT_EQ(sanitize_page_limit(k_oversized_limit2), k_max_page_limit);
}

// ============================================================================
// Receipt Type Classification & Protobuf Fidelity Tests
// ============================================================================

TEST(MessagingContractSemanticsTest, ReceiptTypeValidation) {
    EXPECT_TRUE(is_valid_receipt_type(v1::RECEIPT_TYPE_DELIVERY));
    EXPECT_TRUE(is_valid_receipt_type(v1::RECEIPT_TYPE_READ));

    EXPECT_FALSE(is_valid_receipt_type(v1::RECEIPT_TYPE_UNSPECIFIED));
}

TEST(MessagingContractSemanticsTest, DeliveryReceiptProtobufFidelity) {
    v1::DeliveryReceipt receipt;
    receipt.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    receipt.set_conversation_id("550e8400-e29b-41d4-a716-446655440000");
    receipt.set_recipient_user_id("a0b1c2d3-e4f5-6789-abcd-ef0123456789");
    receipt.set_recipient_device_id("b1c2d3e4-f5a6-7890-bcde-f01234567890");
    receipt.set_receipt_type(v1::RECEIPT_TYPE_READ);
    constexpr int64_t k_timestamp = 1729000000000;
    receipt.set_timestamp_unix_ms(k_timestamp);

    std::string serialized;
    ASSERT_TRUE(receipt.SerializeToString(&serialized));

    v1::DeliveryReceipt parsed;
    ASSERT_TRUE(parsed.ParseFromString(serialized));
    EXPECT_EQ(parsed.message_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    EXPECT_EQ(parsed.conversation_id(), "550e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(parsed.recipient_user_id(), "a0b1c2d3-e4f5-6789-abcd-ef0123456789");
    EXPECT_EQ(parsed.recipient_device_id(), "b1c2d3e4-f5a6-7890-bcde-f01234567890");
    EXPECT_EQ(parsed.receipt_type(), v1::RECEIPT_TYPE_READ);
    EXPECT_EQ(parsed.timestamp_unix_ms(), k_timestamp);
}

TEST(MessagingContractSemanticsTest, SyncDeviceMessagesResponseNextSequenceField) {
    v1::SyncDeviceMessagesResponse response;
    response.set_device_id("b1c2d3e4-f5a6-7890-bcde-f01234567890");
    response.set_has_more(true);
    constexpr int64_t k_next_sequence = 1042;
    response.set_next_sequence(k_next_sequence);

    constexpr int64_t k_cursor_sequence = 1041;
    constexpr int64_t k_cursor_timestamp = 1729000000000;

    auto* cursor = response.mutable_cursor();
    cursor->set_device_id("b1c2d3e4-f5a6-7890-bcde-f01234567890");
    cursor->set_last_delivered_sequence(k_cursor_sequence);
    cursor->set_last_sync_timestamp_unix_ms(k_cursor_timestamp);

    std::string serialized;
    ASSERT_TRUE(response.SerializeToString(&serialized));

    v1::SyncDeviceMessagesResponse parsed;
    ASSERT_TRUE(parsed.ParseFromString(serialized));
    EXPECT_EQ(parsed.device_id(), "b1c2d3e4-f5a6-7890-bcde-f01234567890");
    EXPECT_TRUE(parsed.has_more());
    EXPECT_EQ(parsed.next_sequence(), k_next_sequence);
    EXPECT_EQ(parsed.cursor().last_delivered_sequence(), k_cursor_sequence);
}

} // namespace
} // namespace securecloud::messaging::service
