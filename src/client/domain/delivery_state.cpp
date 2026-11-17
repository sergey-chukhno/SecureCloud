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

} // namespace securecloud::client::domain
