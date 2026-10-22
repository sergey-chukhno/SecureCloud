#pragma once

#include "domain/delivery_types.hpp"
#include "domain/read_receipt_types.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "service/conversation_service.hpp" // for ServiceResult

#include <optional>
#include <string>

namespace securecloud::messaging::service {

/**
 * @brief Authoritative Monotonic Delivery State Transition Engine (MSG-008-T01).
 *
 * Enforces valid state machine transitions for:
 * 1. Device-specific DeliveryState (ADR-007):
 *      QUEUED -> DELIVERING -> DELIVERED (Terminal Success)
 *      DELIVERING -> RETRY_WAIT -> DELIVERING
 *      QUEUED / DELIVERING / RETRY_WAIT -> EXPIRED (Terminal Failure)
 * 2. User-specific ReadState (ADR-007, 03-messaging-data-model):
 *      UNREAD -> READ (Terminal)
 *
 * Invariants:
 * - Monotonicity: Prohibits backward regressions (e.g., DELIVERED -> QUEUED or RETRY_WAIT).
 * - Terminality: DELIVERED and EXPIRED are terminal delivery states.
 * - Idempotency: Duplicate transitions (e.g. DELIVERED -> DELIVERED, READ -> READ) are recognized as no-ops.
 * - Decoupling: DeliveryState (per device) is decoupled from ReadState (per user).
 */
class DeliveryStateTransitionGuard {
  public:
    // --- Device Delivery Lifecycle Transitions ---

    /// Checks if a transition between domain::DeliveryState states is authorized.
    [[nodiscard]] static bool can_transition(domain::DeliveryState current_state,
                                             domain::DeliveryState next_state) noexcept;

    /// Overload for protobuf v1::DeliveryState
    [[nodiscard]] static bool can_transition(v1::DeliveryState current_state, v1::DeliveryState next_state) noexcept;

    /// Validates a domain::DeliveryState transition; returns ServiceResult::ok or ServiceResult::fail.
    [[nodiscard]] static ServiceResult<void> validate_transition(domain::DeliveryState current_state,
                                                                 domain::DeliveryState next_state) noexcept;

    /// Overload for protobuf v1::DeliveryState
    [[nodiscard]] static ServiceResult<void> validate_transition(v1::DeliveryState current_state,
                                                                 v1::DeliveryState next_state) noexcept;

    /// Checks whether candidate_state represents an invalid backward regression
    /// (e.g. attempting to regress DELIVERED back to QUEUED, RETRY_WAIT, or DELIVERING).
    [[nodiscard]] static bool is_regression(domain::DeliveryState current_state,
                                            domain::DeliveryState candidate_state) noexcept;

    /// Overload for protobuf v1::DeliveryState
    [[nodiscard]] static bool is_regression(v1::DeliveryState current_state,
                                            v1::DeliveryState candidate_state) noexcept;

    /// Checks whether candidate_state is an idempotent re-application of current_state.
    [[nodiscard]] static bool is_idempotent(domain::DeliveryState current_state,
                                            domain::DeliveryState candidate_state) noexcept;

    /// Overload for protobuf v1::DeliveryState
    [[nodiscard]] static bool is_idempotent(v1::DeliveryState current_state,
                                            v1::DeliveryState candidate_state) noexcept;

    /// Checks whether state is a terminal delivery state (Delivered or Expired).
    [[nodiscard]] static bool is_terminal(domain::DeliveryState state) noexcept;
    [[nodiscard]] static bool is_terminal(v1::DeliveryState state) noexcept;

    // --- User Read Lifecycle Transitions ---

    /// Checks if a user read state transition is valid (Unread -> Read).
    [[nodiscard]] static bool can_transition_read(domain::ReadState current_state,
                                                  domain::ReadState next_state) noexcept;

    /// Checks if a candidate read state is an idempotent re-application (e.g. Read -> Read).
    [[nodiscard]] static bool is_read_idempotent(domain::ReadState current_state,
                                                 domain::ReadState candidate_state) noexcept;

    /// Checks if a candidate read state is an invalid regression (Read -> Unread).
    [[nodiscard]] static bool is_read_regression(domain::ReadState current_state,
                                                 domain::ReadState candidate_state) noexcept;

    /// Validates a domain::ReadState transition; returns ServiceResult::ok or ServiceResult::fail.
    [[nodiscard]] static ServiceResult<void> validate_read_transition(domain::ReadState current_state,
                                                                      domain::ReadState next_state) noexcept;
};

} // namespace securecloud::messaging::service
