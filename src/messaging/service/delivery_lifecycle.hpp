#pragma once

#include "securecloud/messaging/v1/messaging.pb.h"

#include <cstdint>

namespace securecloud::messaging::service {

/// Standard pagination constants for message synchronization & retrieval (ADR-007, Design 5.17)
inline constexpr uint32_t k_default_page_limit = 50;
inline constexpr uint32_t k_max_page_limit = 100;

/// Validates whether a state transition follows the canonical delivery lifecycle state machine (ADR-007):
///   QUEUED -> DELIVERING -> DELIVERED -> READ
///   DELIVERING -> RETRY_WAIT -> DELIVERING
///   QUEUED | DELIVERING | RETRY_WAIT -> EXPIRED
[[nodiscard]] bool is_valid_delivery_transition(v1::DeliveryState current_state, v1::DeliveryState next_state) noexcept;

/// Checks if an attempted state update is an idempotent re-application of the current state
/// (e.g. duplicate delivery ACK or duplicate read receipt)
[[nodiscard]] bool is_idempotent_delivery_state(v1::DeliveryState current_state,
                                                v1::DeliveryState candidate_state) noexcept;

/// Validates non-negative sequence number requirement for device streams
[[nodiscard]] bool is_valid_sequence(int64_t sequence) noexcept;

/// Validates that a new synchronization cursor strictly advances monotonically
/// past the current sequence without regression or replay:
///   new_sequence > current_sequence && is_valid_sequence(new_sequence)
[[nodiscard]] bool is_valid_cursor_progression(int64_t current_sequence, int64_t new_sequence) noexcept;

/// Validates whether a requested pagination limit falls within bounded limits [1, 100]
[[nodiscard]] bool is_valid_page_limit(uint32_t limit) noexcept;

/// Sanitizes requested page limit: returns k_default_page_limit if 0, caps to k_max_page_limit if > 100
[[nodiscard]] uint32_t sanitize_page_limit(uint32_t requested_limit) noexcept;

/// Validates whether a receipt type is a recognized active type (DELIVERY or READ)
[[nodiscard]] bool is_valid_receipt_type(v1::ReceiptType type) noexcept;

} // namespace securecloud::messaging::service
