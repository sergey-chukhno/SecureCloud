#include "domain/delivery_state.hpp"

namespace securecloud::client::domain {

std::string_view to_string(DeliveryState state) noexcept {
    switch (state) {
    case DeliveryState::LocalPending:
        return "LocalPending";
    case DeliveryState::Submitting:
        return "Submitting";
    case DeliveryState::Accepted:
        return "Accepted";
    case DeliveryState::Delivering:
        return "Delivering";
    case DeliveryState::Delivered:
        return "Delivered";
    case DeliveryState::Read:
        return "Read";
    case DeliveryState::Failed:
        return "Failed";
    }
    return "Unknown";
}

std::optional<DeliveryState> delivery_state_from_string(std::string_view str) noexcept {
    if (str == "LocalPending") {
        return DeliveryState::LocalPending;
    }
    if (str == "Submitting") {
        return DeliveryState::Submitting;
    }
    if (str == "Accepted") {
        return DeliveryState::Accepted;
    }
    if (str == "Delivering") {
        return DeliveryState::Delivering;
    }
    if (str == "Delivered") {
        return DeliveryState::Delivered;
    }
    if (str == "Read") {
        return DeliveryState::Read;
    }
    if (str == "Failed") {
        return DeliveryState::Failed;
    }
    return std::nullopt;
}

int delivery_state_rank(DeliveryState state) noexcept {
    switch (state) {
    case DeliveryState::LocalPending:
        return 0;
    case DeliveryState::Submitting:
        return 1;
    case DeliveryState::Accepted:
        return 2;
    case DeliveryState::Delivering:
        return 3;
    case DeliveryState::Delivered:
        return 4;
    case DeliveryState::Read:
        return 5;
    case DeliveryState::Failed:
        return -1;
    }
    return -1;
}

bool can_transition_delivery_state(DeliveryState current, DeliveryState next) noexcept {
    if (current == next) {
        return true;
    }
    if (current == DeliveryState::Failed) {
        return next == DeliveryState::Submitting || next == DeliveryState::LocalPending;
    }
    if (next == DeliveryState::Failed) {
        return current != DeliveryState::Delivered && current != DeliveryState::Read;
    }
    return delivery_state_rank(next) >= delivery_state_rank(current);
}

} // namespace securecloud::client::domain
