#include "service/delivery_lifecycle.hpp"

#include <algorithm>

namespace securecloud::messaging::service {

bool is_valid_delivery_transition(v1::DeliveryState current_state, v1::DeliveryState next_state) noexcept {
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

bool is_valid_delivery_transition(domain::DeliveryState current_state, domain::DeliveryState next_state) noexcept {
    switch (current_state) {
    case domain::DeliveryState::Queued:
        return next_state == domain::DeliveryState::Delivering || next_state == domain::DeliveryState::Expired;

    case domain::DeliveryState::Delivering:
        return next_state == domain::DeliveryState::Delivered || next_state == domain::DeliveryState::RetryWait ||
               next_state == domain::DeliveryState::Expired;

    case domain::DeliveryState::RetryWait:
        return next_state == domain::DeliveryState::Delivering || next_state == domain::DeliveryState::Expired;

    case domain::DeliveryState::Delivered:
        return next_state == domain::DeliveryState::Read;

    case domain::DeliveryState::Read:
    case domain::DeliveryState::Expired:
    default:
        return false;
    }
}

bool is_idempotent_delivery_state(v1::DeliveryState current_state, v1::DeliveryState candidate_state) noexcept {
    return current_state == candidate_state && current_state != v1::DELIVERY_STATE_UNSPECIFIED;
}

bool is_idempotent_delivery_state(domain::DeliveryState current_state, domain::DeliveryState candidate_state) noexcept {
    return current_state == candidate_state;
}

v1::DeliveryState to_proto_delivery_state(domain::DeliveryState domain_state) noexcept {
    switch (domain_state) {
    case domain::DeliveryState::Queued:
        return v1::DELIVERY_STATE_QUEUED;
    case domain::DeliveryState::Delivering:
        return v1::DELIVERY_STATE_DELIVERING;
    case domain::DeliveryState::Delivered:
        return v1::DELIVERY_STATE_DELIVERED;
    case domain::DeliveryState::Read:
        return v1::DELIVERY_STATE_READ;
    case domain::DeliveryState::RetryWait:
        return v1::DELIVERY_STATE_RETRY_WAIT;
    case domain::DeliveryState::Expired:
        return v1::DELIVERY_STATE_EXPIRED;
    }
    return v1::DELIVERY_STATE_UNSPECIFIED;
}

std::optional<domain::DeliveryState> from_proto_delivery_state(v1::DeliveryState proto_state) noexcept {
    switch (proto_state) {
    case v1::DELIVERY_STATE_QUEUED:
        return domain::DeliveryState::Queued;
    case v1::DELIVERY_STATE_DELIVERING:
        return domain::DeliveryState::Delivering;
    case v1::DELIVERY_STATE_DELIVERED:
        return domain::DeliveryState::Delivered;
    case v1::DELIVERY_STATE_READ:
        return domain::DeliveryState::Read;
    case v1::DELIVERY_STATE_RETRY_WAIT:
        return domain::DeliveryState::RetryWait;
    case v1::DELIVERY_STATE_EXPIRED:
        return domain::DeliveryState::Expired;
    case v1::DELIVERY_STATE_UNSPECIFIED:
    default:
        return std::nullopt;
    }
}

bool is_valid_sequence(int64_t sequence) noexcept {
    return sequence >= 0;
}

bool is_valid_cursor_progression(int64_t current_sequence, int64_t new_sequence) noexcept {
    return is_valid_sequence(new_sequence) && new_sequence > current_sequence;
}

bool is_valid_page_limit(uint32_t limit) noexcept {
    return limit >= 1 && limit <= k_max_page_limit;
}

uint32_t sanitize_page_limit(uint32_t requested_limit) noexcept {
    if (requested_limit == 0) {
        return k_default_page_limit;
    }
    return std::min(requested_limit, k_max_page_limit);
}

bool is_valid_receipt_type(v1::ReceiptType type) noexcept {
    return type == v1::RECEIPT_TYPE_DELIVERY || type == v1::RECEIPT_TYPE_READ;
}

} // namespace securecloud::messaging::service
