#pragma once

#include <optional>
#include <string_view>

namespace securecloud::client::domain {

enum class DeliveryState { LocalPending, Submitting, Accepted, Delivering, Delivered, Read, Failed };

[[nodiscard]] std::string_view to_string(DeliveryState state) noexcept;
[[nodiscard]] std::optional<DeliveryState> delivery_state_from_string(std::string_view str) noexcept;
[[nodiscard]] int delivery_state_rank(DeliveryState state) noexcept;
[[nodiscard]] bool can_transition_delivery_state(DeliveryState current, DeliveryState next) noexcept;

} // namespace securecloud::client::domain
