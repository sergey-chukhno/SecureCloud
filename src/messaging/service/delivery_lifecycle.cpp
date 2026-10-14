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

bool is_idempotent_delivery_state(v1::DeliveryState current_state, v1::DeliveryState candidate_state) noexcept {
    return current_state == candidate_state && current_state != v1::DELIVERY_STATE_UNSPECIFIED;
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
