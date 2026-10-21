#include "service/delivery_state_transition_guard.hpp"

namespace securecloud::messaging::service {

bool DeliveryStateTransitionGuard::can_transition(domain::DeliveryState current_state,
                                                  domain::DeliveryState next_state) noexcept {
    switch (current_state) {
    case domain::DeliveryState::Queued:
        return next_state == domain::DeliveryState::Delivering || next_state == domain::DeliveryState::Expired;

    case domain::DeliveryState::Delivering:
        return next_state == domain::DeliveryState::Delivered || next_state == domain::DeliveryState::RetryWait ||
               next_state == domain::DeliveryState::Expired;

    case domain::DeliveryState::RetryWait:
        return next_state == domain::DeliveryState::Delivering || next_state == domain::DeliveryState::Expired;

    case domain::DeliveryState::Delivered:
        // Delivered is terminal for the per-device delivery pipeline;
        // Read is accepted for backward-compatibility with proto wire formats.
        return next_state == domain::DeliveryState::Read;

    case domain::DeliveryState::Read:
    case domain::DeliveryState::Expired:
    default:
        return false;
    }
}

bool DeliveryStateTransitionGuard::can_transition(v1::DeliveryState current_state,
                                                  v1::DeliveryState next_state) noexcept {
    switch (current_state) {
    case v1::DELIVERY_STATE_QUEUED:
        return next_state == v1::DELIVERY_STATE_DELIVERING || next_state == v1::DELIVERY_STATE_EXPIRED;

    case v1::DELIVERY_STATE_DELIVERING:
        return next_state == v1::DELIVERY_STATE_DELIVERED || next_state == v1::DELIVERY_STATE_RETRY_WAIT ||
               next_state == v1::DELIVERY_STATE_EXPIRED;

    case v1::DELIVERY_STATE_RETRY_WAIT:
        return next_state == v1::DELIVERY_STATE_DELIVERING || next_state == v1::DELIVERY_STATE_EXPIRED;

    case v1::DELIVERY_STATE_DELIVERED:
        return next_state == v1::DELIVERY_STATE_READ;

    case v1::DELIVERY_STATE_READ:
    case v1::DELIVERY_STATE_EXPIRED:
    case v1::DELIVERY_STATE_UNSPECIFIED:
    default:
        return false;
    }
}

bool DeliveryStateTransitionGuard::is_regression(domain::DeliveryState current_state,
                                                 domain::DeliveryState candidate_state) noexcept {
    // If it's an idempotent re-application, it's not a regression
    if (current_state == candidate_state) {
        return false;
    }

    switch (current_state) {
    case domain::DeliveryState::Delivered:
        // DELIVERED cannot regress to QUEUED, DELIVERING, or RETRY_WAIT
        return candidate_state == domain::DeliveryState::Queued ||
               candidate_state == domain::DeliveryState::Delivering ||
               candidate_state == domain::DeliveryState::RetryWait;

    case domain::DeliveryState::Read:
        // READ cannot regress to DELIVERED, DELIVERING, RETRY_WAIT, or QUEUED
        return candidate_state == domain::DeliveryState::Delivered ||
               candidate_state == domain::DeliveryState::Delivering ||
               candidate_state == domain::DeliveryState::RetryWait || candidate_state == domain::DeliveryState::Queued;

    case domain::DeliveryState::Expired:
        // Terminal EXPIRED cannot regress to any prior active delivery state
        return candidate_state == domain::DeliveryState::Queued ||
               candidate_state == domain::DeliveryState::Delivering ||
               candidate_state == domain::DeliveryState::RetryWait ||
               candidate_state == domain::DeliveryState::Delivered || candidate_state == domain::DeliveryState::Read;

    case domain::DeliveryState::Delivering:
        // DELIVERING cannot regress to QUEUED
        return candidate_state == domain::DeliveryState::Queued;

    case domain::DeliveryState::RetryWait:
        // RETRY_WAIT cannot regress to QUEUED
        return candidate_state == domain::DeliveryState::Queued;

    case domain::DeliveryState::Queued:
    default:
        return false;
    }
}

bool DeliveryStateTransitionGuard::is_regression(v1::DeliveryState current_state,
                                                 v1::DeliveryState candidate_state) noexcept {
    if (current_state == candidate_state) {
        return false;
    }

    switch (current_state) {
    case v1::DELIVERY_STATE_DELIVERED:
        return candidate_state == v1::DELIVERY_STATE_QUEUED || candidate_state == v1::DELIVERY_STATE_DELIVERING ||
               candidate_state == v1::DELIVERY_STATE_RETRY_WAIT;

    case v1::DELIVERY_STATE_READ:
        return candidate_state == v1::DELIVERY_STATE_DELIVERED || candidate_state == v1::DELIVERY_STATE_DELIVERING ||
               candidate_state == v1::DELIVERY_STATE_RETRY_WAIT || candidate_state == v1::DELIVERY_STATE_QUEUED;

    case v1::DELIVERY_STATE_EXPIRED:
        return candidate_state == v1::DELIVERY_STATE_QUEUED || candidate_state == v1::DELIVERY_STATE_DELIVERING ||
               candidate_state == v1::DELIVERY_STATE_RETRY_WAIT || candidate_state == v1::DELIVERY_STATE_DELIVERED ||
               candidate_state == v1::DELIVERY_STATE_READ;

    case v1::DELIVERY_STATE_DELIVERING:
        return candidate_state == v1::DELIVERY_STATE_QUEUED;

    case v1::DELIVERY_STATE_RETRY_WAIT:
        return candidate_state == v1::DELIVERY_STATE_QUEUED;

    case v1::DELIVERY_STATE_QUEUED:
    case v1::DELIVERY_STATE_UNSPECIFIED:
    default:
        return false;
    }
}

bool DeliveryStateTransitionGuard::is_idempotent(domain::DeliveryState current_state,
                                                 domain::DeliveryState candidate_state) noexcept {
    return current_state == candidate_state;
}

bool DeliveryStateTransitionGuard::is_idempotent(v1::DeliveryState current_state,
                                                 v1::DeliveryState candidate_state) noexcept {
    return current_state == candidate_state && current_state != v1::DELIVERY_STATE_UNSPECIFIED;
}

bool DeliveryStateTransitionGuard::is_terminal(domain::DeliveryState state) noexcept {
    return state == domain::DeliveryState::Delivered || state == domain::DeliveryState::Read ||
           state == domain::DeliveryState::Expired;
}

bool DeliveryStateTransitionGuard::is_terminal(v1::DeliveryState state) noexcept {
    return state == v1::DELIVERY_STATE_DELIVERED || state == v1::DELIVERY_STATE_READ ||
           state == v1::DELIVERY_STATE_EXPIRED;
}

ServiceResult<void> DeliveryStateTransitionGuard::validate_transition(domain::DeliveryState current_state,
                                                                      domain::DeliveryState next_state) noexcept {
    if (is_idempotent(current_state, next_state)) {
        return ServiceResult<void>::ok();
    }

    if (current_state == domain::DeliveryState::Expired) {
        return ServiceResult<void>::fail(v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED,
                                         "Message delivery window has expired and cannot transition to " +
                                             domain::to_string(next_state));
    }

    if (is_regression(current_state, next_state)) {
        return ServiceResult<void>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                         "Invalid delivery state regression from " + domain::to_string(current_state) +
                                             " to " + domain::to_string(next_state));
    }

    if (!can_transition(current_state, next_state)) {
        return ServiceResult<void>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                         "Prohibited delivery state transition from " +
                                             domain::to_string(current_state) + " to " + domain::to_string(next_state));
    }

    return ServiceResult<void>::ok();
}

ServiceResult<void> DeliveryStateTransitionGuard::validate_transition(v1::DeliveryState current_state,
                                                                      v1::DeliveryState next_state) noexcept {
    if (is_idempotent(current_state, next_state)) {
        return ServiceResult<void>::ok();
    }

    if (current_state == v1::DELIVERY_STATE_EXPIRED) {
        return ServiceResult<void>::fail(v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED,
                                         "Message delivery window has expired and cannot transition");
    }

    if (is_regression(current_state, next_state)) {
        return ServiceResult<void>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                         "Invalid delivery state regression from " +
                                             std::to_string(static_cast<int>(current_state)) + " to " +
                                             std::to_string(static_cast<int>(next_state)));
    }

    if (!can_transition(current_state, next_state)) {
        return ServiceResult<void>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Prohibited delivery state transition");
    }

    return ServiceResult<void>::ok();
}

// --- User Read Lifecycle Transitions ---

bool DeliveryStateTransitionGuard::can_transition_read(domain::ReadState current_state,
                                                       domain::ReadState next_state) noexcept {
    switch (current_state) {
    case domain::ReadState::Unread:
        return next_state == domain::ReadState::Read;
    case domain::ReadState::Read:
    default:
        return false;
    }
}

bool DeliveryStateTransitionGuard::is_read_idempotent(domain::ReadState current_state,
                                                      domain::ReadState candidate_state) noexcept {
    return current_state == candidate_state;
}

bool DeliveryStateTransitionGuard::is_read_regression(domain::ReadState current_state,
                                                      domain::ReadState candidate_state) noexcept {
    return current_state == domain::ReadState::Read && candidate_state == domain::ReadState::Unread;
}

ServiceResult<void> DeliveryStateTransitionGuard::validate_read_transition(domain::ReadState current_state,
                                                                           domain::ReadState next_state) noexcept {
    if (is_read_idempotent(current_state, next_state)) {
        return ServiceResult<void>::ok();
    }

    if (is_read_regression(current_state, next_state)) {
        return ServiceResult<void>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                         "Invalid read state regression: message already marked as READ");
    }

    if (!can_transition_read(current_state, next_state)) {
        return ServiceResult<void>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Prohibited read state transition");
    }

    return ServiceResult<void>::ok();
}

} // namespace securecloud::messaging::service
