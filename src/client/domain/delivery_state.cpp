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

} // namespace securecloud::client::domain
